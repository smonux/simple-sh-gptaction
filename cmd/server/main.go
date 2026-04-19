package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gptsh/internal/auth"
	"gptsh/internal/config"
	"gptsh/internal/mcp"
	"gptsh/internal/proto"

	"gopkg.in/yaml.v3"
)

const (
	maxTimeoutMs = 45000
	maxBodyBytes = 1 << 20
)

type execClient struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
}

func newExecClient(path string) (*execClient, error) {
	cmd := exec.Command(path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &execClient{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

func (c *execClient) close() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
}

func (c *execClient) restart(path string) error {
	c.close()
	client, err := newExecClient(path)
	if err != nil {
		return err
	}
	*c = *client
	return nil
}

func (c *execClient) exec(ctx context.Context, req proto.ExecRequest) (proto.ExecResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	payload, err := json.Marshal(req)
	if err != nil {
		return proto.ExecResponse{}, err
	}
	if err := proto.WriteFrame(c.stdin, payload); err != nil {
		return proto.ExecResponse{}, err
	}

	respCh := make(chan proto.ExecResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		frame, err := proto.ReadFrame(c.stdout)
		if err != nil {
			errCh <- err
			return
		}
		var resp proto.ExecResponse
		if err := json.Unmarshal(frame, &resp); err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	select {
	case <-ctx.Done():
		return proto.ExecResponse{}, ctx.Err()
	case err := <-errCh:
		return proto.ExecResponse{}, err
	case resp := <-respCh:
		return resp, nil
	}
}

type execRequest struct {
	Cmd       string `json:"cmd"`
	TimeoutMs int    `json:"timeout_ms"`
}

type openAPICache struct {
	once    sync.Once
	yaml    []byte
	json    []byte
	loadErr error
}

type staticFileCache struct {
	once    sync.Once
	name    string
	data    []byte
	loadErr error
}

func (c *staticFileCache) load() {
	exe, err := os.Executable()
	if err != nil {
		c.loadErr = err
		return
	}
	path := filepath.Join(filepath.Dir(exe), c.name)
	data, err := os.ReadFile(path)
	if err != nil {
		c.loadErr = err
		return
	}
	c.data = data
}

func (c *staticFileCache) get() ([]byte, error) {
	c.once.Do(c.load)
	return c.data, c.loadErr
}

func (c *openAPICache) load() {
	exe, err := os.Executable()
	if err != nil {
		c.loadErr = err
		return
	}
	path := filepath.Join(filepath.Dir(exe), "openapi.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		c.loadErr = err
		return
	}
	c.yaml = data

	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		c.loadErr = err
		return
	}
	converted, err := json.Marshal(doc)
	if err != nil {
		c.loadErr = err
		return
	}
	c.json = converted
}

func (c *openAPICache) getJSON() ([]byte, error) {
	c.once.Do(c.load)
	return c.json, c.loadErr
}

func (c *openAPICache) getYAML() ([]byte, error) {
	c.once.Do(c.load)
	return c.yaml, c.loadErr
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("%s %s %d %dB %s", r.Method, r.URL.Path, status, rec.bytes, time.Since(start))
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func truncateForLog(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	return s[:max] + "...(truncated)", true
}

func main() {
	cfg, err := config.LoadServerConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	openapi := &openAPICache{}
	privacyPolicy := &staticFileCache{name: "privacy-policy.html"}

	authorizer, err := auth.NewAuthorizer(auth.Config{
		Mode:                 cfg.AuthMode,
		APIKey:               cfg.APIKey,
		OAuthClientID:        cfg.OAuthClientID,
		OAuthTokenTTLSeconds: cfg.OAuthTokenTTLSeconds,
		OAuthCodeTTLSeconds:  cfg.OAuthCodeTTLSeconds,
		OAuthAllowedScopes:   cfg.OAuthAllowedScopes,
		OAuthRedirectURIs:    cfg.OAuthRedirectURIs,
		OAuthUsername:        cfg.OAuthUsername,
		OAuthPassword:        cfg.OAuthPassword,
		OAuthSQLitePath:      cfg.OAuthSQLitePath,
		PublicURL:            cfg.PublicURL,
		AuthServerURL:        cfg.AuthServerURL,
		Logf:                 log.Printf,
	})
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	client, err := newExecClient(cfg.ExecutorPath)
	if err != nil {
		log.Fatalf("executor start: %v", err)
	}

	var idCounter int64

	execHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/exec" {
			http.NotFound(w, r)
			return
		}

		if !authorizer.AuthorizeRequest(r) {
			authorizer.WriteUnauthorized(w, r)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var req execRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Cmd) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Printf("exec request: cmd=%q timeout_ms=%d", req.Cmd, req.TimeoutMs)

		timeout := req.TimeoutMs
		if timeout <= 0 || timeout > maxTimeoutMs {
			timeout = maxTimeoutMs
		}

		id := atomic.AddInt64(&idCounter, 1)
		execReq := proto.ExecRequest{
			ID:             id,
			Cmd:            req.Cmd,
			TimeoutMs:      timeout,
			MaxOutputChars: cfg.MaxOutputChar,
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Millisecond)
		defer cancel()
		resp, err := client.exec(ctx, execReq)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				_ = client.restart(cfg.ExecutorPath)
				resp = proto.ExecResponse{
					ID:       id,
					ExitCode: 124,
					Stderr:   "timeout; shell reset",
				}
			} else {
				log.Printf("exec error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		stdout, stdoutTrunc := truncateForLog(resp.Stdout, 4000)
		stderr, stderrTrunc := truncateForLog(resp.Stderr, 4000)
		log.Printf(
			"exec response: id=%d exit=%d duration_ms=%d truncated=%t stdout_len=%d stderr_len=%d stdout_trunc=%t stderr_trunc=%t stdout=%q stderr=%q error=%q",
			resp.ID,
			resp.ExitCode,
			resp.DurationMs,
			resp.Truncated,
			len(resp.Stdout),
			len(resp.Stderr),
			stdoutTrunc,
			stderrTrunc,
			stdout,
			stderr,
			resp.Error,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mcpHandler := &mcp.Handler{
		Exec:           client.exec,
		Auth:           authorizer,
		Logf:           log.Printf,
		MaxBodyBytes:   int64(maxBodyBytes),
		MaxTimeoutMs:   maxTimeoutMs,
		MaxOutputChars: cfg.MaxOutputChar,
		ServerName:     "gptsh-mcp",
		ServerVersion:  "1.0.0",
	}

	mux := http.NewServeMux()
	mux.Handle("/exec", execHandler)
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, err := openapi.getJSON()
		if err != nil || len(data) == 0 {
			log.Printf("openapi.json error: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, err := openapi.getYAML()
		if err != nil || len(data) == 0 {
			log.Printf("openapi.yaml error: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(data)
	})
	privacyPolicyHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, err := privacyPolicy.get()
		if err != nil || len(data) == 0 {
			log.Printf("privacy policy error: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(data)
	}
	mux.HandleFunc("/privacy-policy", privacyPolicyHandler)
	mux.HandleFunc("/privacy-policy.html", privacyPolicyHandler)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/", mcpHandler)

	if authorizer.OAuth() != nil {
		mux.HandleFunc("/oauth/authorize", authorizer.OAuth().HandleAuthorize)
		mux.HandleFunc("/oauth/token", authorizer.OAuth().HandleToken)
		mux.HandleFunc("/.well-known/oauth-protected-resource", authorizer.HandleProtectedResource)
		mux.HandleFunc("/.well-known/oauth-authorization-server", authorizer.HandleAuthorizationServerMetadata)
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: logRequests(withCORS(mux)),
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServe())
}
