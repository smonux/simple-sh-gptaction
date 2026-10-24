package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"gptsh/internal/auth"
	"gptsh/internal/config"
	"gptsh/internal/proto"
)

// The test executable doubles as a tiny framed executor, allowing cancellation
// and restart behavior to be verified without relying on the host's Landlock.
func TestMain(m *testing.M) {
	if os.Getenv("GPTSH_TEST_EXECUTOR") == "1" {
		for {
			frame, err := proto.ReadFrame(os.Stdin)
			if err != nil {
				os.Exit(0)
			}
			var req proto.ExecRequest
			if json.Unmarshal(frame, &req) != nil {
				os.Exit(1)
			}
			if req.Cmd == "slow" {
				time.Sleep(10 * time.Second)
			}
			payload, _ := json.Marshal(proto.ExecResponse{ID: req.ID, Stdout: req.Cmd})
			if proto.WriteFrame(os.Stdout, payload) != nil {
				os.Exit(1)
			}
		}
	}
	os.Exit(m.Run())
}

func TestExecutorRecoversAfterCancellation(t *testing.T) {
	t.Setenv("GPTSH_TEST_EXECUTOR", "1")
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := newExecClientWithEnvironment(path, append(config.ExecutorEnvironment(os.Environ()), "GPTSH_TEST_EXECUTOR=1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.close)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.exec(ctx, proto.ExecRequest{ID: 1, Cmd: "slow"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wanted timeout: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.exec(ctx, proto.ExecRequest{ID: 2, Cmd: "after-timeout"})
	if err != nil || resp.ID != 2 || resp.Stdout != "after-timeout" {
		t.Fatalf("stale response after restart: %+v, %v", resp, err)
	}
}

func TestDisableActionRoutes(t *testing.T) {
	a, err := auth.NewAuthorizer(auth.Config{Mode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	for _, disabled := range []bool{false, true} {
		h := newHTTPHandler(config.ServerConfig{DisableAction: disabled}, a, stub, stub)
		for _, path := range []string{"/exec", "/openapi.json", "/openapi.yaml"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
			want := 405
			if path == "/exec" {
				want = 204
			}
			if disabled {
				want = 404
			}
			if w.Code != want {
				t.Fatalf("disabled=%t path=%s: got %d want %d", disabled, path, w.Code, want)
			}
		}
		for _, path := range []string{"/mcp", "/"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
			if w.Code != 204 {
				t.Fatalf("MCP endpoint %s disabled: %d", path, w.Code)
			}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/unknown", nil))
		if w.Code != 404 {
			t.Fatal("unknown path incorrectly routed to MCP")
		}
	}
}
