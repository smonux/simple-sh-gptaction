package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gptsh/internal/auth"
	"gptsh/internal/proto"
)

func testHandler(t *testing.T) (*Handler, *int, *bytes.Buffer) {
	t.Helper()
	authorizer, err := auth.NewAuthorizer(auth.Config{Mode: "api_key", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	calls := new(int)
	logs := new(bytes.Buffer)
	return &Handler{
		Auth: authorizer, PublicURL: "https://mcp.example.com", MaxTimeoutMs: 45000,
		ServerName: "gptsh-mcp", ServerVersion: "test",
		Logf: func(format string, args ...any) { fmt.Fprintf(logs, format, args...) },
		Exec: func(ctx context.Context, req proto.ExecRequest) (proto.ExecResponse, error) {
			*calls++
			return proto.ExecResponse{ID: req.ID, Stdout: "secret-output", Cwd: "/tmp"}, nil
		},
	}, calls, logs
}

func mcpRequest(handler http.Handler, method, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://mcp.example.com/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer test-key")
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestTransportAndNegotiation(t *testing.T) {
	h, _, _ := testHandler(t)
	for _, version := range []string{"2025-03-26", "2025-06-18", "2099-01-01"} {
		w := mcpRequest(h, "POST", fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":%q}}`, version), nil)
		var response struct{ Result initializeResult }
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		want := version
		if version != defaultProtocolVersion {
			want = defaultProtocolVersion
		}
		if w.Code != 200 || response.Result.ProtocolVersion != want {
			t.Fatalf("initialize: %d %s", w.Code, w.Body)
		}
	}
	for _, tc := range []struct {
		name, method, body string
		headers            map[string]string
		status             int
	}{
		{"no SSE stream", "GET", "", nil, 405},
		{"no session deletion", "DELETE", "", nil, 405},
		{"initialized", "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil, 202},
		{"ping", "POST", `{"jsonrpc":"2.0","id":2,"method":"ping"}`, nil, 200},
		{"auth", "POST", `{}`, map[string]string{"Authorization": ""}, 401},
		{"version", "POST", `{}`, map[string]string{"MCP-Protocol-Version": "2099-01-01"}, 400},
		{"origin", "POST", `{}`, map[string]string{"Origin": "https://attacker.example"}, 403},
		{"content type", "POST", `{}`, map[string]string{"Content-Type": "text/plain"}, 415},
		{"accept", "POST", `{}`, map[string]string{"Accept": "application/json"}, 406},
		{"malformed JSON", "POST", `{`, nil, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := mcpRequest(h, tc.method, tc.body, tc.headers)
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.status, w.Body)
			}
		})
	}
}

func TestToolsAndSensitiveLogs(t *testing.T) {
	h, calls, logs := testHandler(t)
	w := mcpRequest(h, "POST", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if !strings.Contains(w.Body.String(), `"destructiveHint":true`) || !strings.Contains(w.Body.String(), `"readOnlyHint":false`) {
		t.Fatalf("missing safety metadata: %s", w.Body)
	}
	w = mcpRequest(h, "POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"secret-command"}}}`, nil)
	if *calls != 1 || !strings.Contains(w.Body.String(), `"stdout":"secret-output"`) {
		t.Fatalf("call failed: %s", w.Body)
	}
	if strings.Contains(logs.String(), "secret-command") || strings.Contains(logs.String(), "secret-output") {
		t.Fatal("sensitive data in logs")
	}
	for _, body := range []string{
		`[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"ignored"}}}]`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec","arguments":{"cmd":"ignored"}}}`,
		`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"ignored"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"ignored","extra":true}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"ignored","timeout_ms":999999}}}`,
	} {
		mcpRequest(h, "POST", body, nil)
	}
	if *calls != 1 {
		t.Fatal("invalid requests or notifications executed commands")
	}
}
