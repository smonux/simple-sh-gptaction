package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gptsh/internal/config"
	"gptsh/internal/proto"
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

func main() {
	cfg, err := config.LoadServerConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	client, err := newExecClient(cfg.ExecutorPath)
	if err != nil {
		log.Fatalf("executor start: %v", err)
	}

	var idCounter int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/exec" {
			http.NotFound(w, r)
			return
		}

		if !authorized(r, cfg.APIKey) {
			w.WriteHeader(http.StatusUnauthorized)
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
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServe())
}

func authorized(r *http.Request, apiKey string) bool {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	return subtle.ConstantTimeCompare([]byte(got), []byte(apiKey)) == 1
}
