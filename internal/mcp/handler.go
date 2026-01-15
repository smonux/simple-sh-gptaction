package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"gptsh/internal/auth"
	"gptsh/internal/proto"
)

const defaultProtocolVersion = "2024-11-05"

type ExecFunc func(context.Context, proto.ExecRequest) (proto.ExecResponse, error)

type Handler struct {
	Exec           ExecFunc
	Auth           *auth.Authorizer
	Logf           func(string, ...any)
	MaxBodyBytes   int64
	MaxTimeoutMs   int
	MaxOutputChars int
	ServerName     string
	ServerVersion  string

	idCounter int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": h.ServerName,
		})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Auth != nil && !h.Auth.AuthorizeRequest(r) {
		h.Auth.WriteUnauthorized(w, r)
		return
	}

	body, err := readBody(w, r, h.MaxBodyBytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responses, ok := h.handlePayload(r.Context(), body)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(responses) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if len(responses) == 1 {
		_ = enc.Encode(responses[0])
		return
	}
	_ = enc.Encode(responses)
}

func (h *Handler) handlePayload(ctx context.Context, body []byte) ([]jsonRPCResponse, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] == '[' {
		var batch []jsonRPCRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, false
		}
		responses := make([]jsonRPCResponse, 0, len(batch))
		for _, req := range batch {
			if resp := h.handleRequest(ctx, req); resp != nil {
				responses = append(responses, *resp)
			}
		}
		return responses, true
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, false
	}
	if resp := h.handleRequest(ctx, req); resp != nil {
		return []jsonRPCResponse{*resp}, true
	}
	return nil, true
}

func (h *Handler) handleRequest(ctx context.Context, req jsonRPCRequest) *jsonRPCResponse {
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return req.errorResponse(errInvalidRequest, "invalid jsonrpc version")
	}

	switch req.Method {
	case "initialize":
		return h.handleInitialize(req)
	case "notifications/initialized":
		return nil
	case "tools/list":
		return h.handleToolsList(req)
	case "tools/call":
		return h.handleToolsCall(ctx, req)
	default:
		if isNotification(req.ID) {
			return nil
		}
		return req.errorResponse(errMethodNotFound, "method not found")
	}
}

func (h *Handler) handleInitialize(req jsonRPCRequest) *jsonRPCResponse {
	var params initializeParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return req.errorResponse(errInvalidParams, "invalid params")
		}
	}
	version := strings.TrimSpace(params.ProtocolVersion)
	if version == "" {
		version = defaultProtocolVersion
	}
	result := initializeResult{
		ProtocolVersion: version,
		ServerInfo: serverInfo{
			Name:    h.ServerName,
			Version: h.ServerVersion,
		},
		Capabilities: map[string]any{
			"tools": map[string]any{},
		},
	}
	return req.resultResponse(result)
}

func (h *Handler) handleToolsList(req jsonRPCRequest) *jsonRPCResponse {
	tool := toolDef{
		Name:        "exec",
		Description: "Execute a shell command inside the sandboxed persistent bash session",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"cmd": map[string]any{
					"type":        "string",
					"description": "Command to execute",
				},
				"timeout_ms": map[string]any{
					"type":        "integer",
					"description": "Timeout in milliseconds (max 45000)",
					"minimum":     1,
					"maximum":     h.MaxTimeoutMs,
				},
			},
			"required": []string{"cmd"},
		},
	}
	return req.resultResponse(map[string]any{
		"tools": []toolDef{tool},
	})
}

func (h *Handler) handleToolsCall(ctx context.Context, req jsonRPCRequest) *jsonRPCResponse {
	if h.Exec == nil {
		return req.errorResponse(errInternal, "executor not configured")
	}
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return req.errorResponse(errInvalidParams, "invalid params")
	}
	if params.Name != "exec" {
		return req.errorResponse(errInvalidParams, "unknown tool")
	}
	if params.Arguments == nil {
		return req.errorResponse(errInvalidParams, "missing arguments")
	}
	var args execArgs
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		return req.errorResponse(errInvalidParams, "invalid arguments")
	}
	if strings.TrimSpace(args.Cmd) == "" {
		return req.errorResponse(errInvalidParams, "cmd is required")
	}

	if h.Logf != nil {
		h.Logf("mcp tools/call request: cmd=%q timeout_ms=%d", args.Cmd, args.TimeoutMs)
	}

	timeout := args.TimeoutMs
	if timeout <= 0 || timeout > h.MaxTimeoutMs {
		timeout = h.MaxTimeoutMs
	}
	id := atomic.AddInt64(&h.idCounter, 1)
	execReq := proto.ExecRequest{
		ID:             id,
		Cmd:            args.Cmd,
		TimeoutMs:      timeout,
		MaxOutputChars: h.MaxOutputChars,
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()

	resp, err := h.Exec(ctx, execReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			resp = proto.ExecResponse{
				ID:       id,
				ExitCode: 124,
				Stderr:   "timeout; shell reset",
			}
		} else {
			if h.Logf != nil {
				h.Logf("mcp tools/call error: %v", err)
			}
			return req.errorResponse(errInternal, "execution failed")
		}
	}

	if h.Logf != nil {
		stdout, stdoutTrunc := truncateForLog(resp.Stdout, 4000)
		stderr, stderrTrunc := truncateForLog(resp.Stderr, 4000)
		errText, errTrunc := truncateForLog(resp.Error, 4000)
		h.Logf(
			"mcp tools/call response: id=%d exit=%d duration_ms=%d truncated=%t stdout_len=%d stderr_len=%d err_len=%d stdout_trunc=%t stderr_trunc=%t err_trunc=%t stdout=%q stderr=%q error=%q",
			resp.ID,
			resp.ExitCode,
			resp.DurationMs,
			resp.Truncated,
			len(resp.Stdout),
			len(resp.Stderr),
			len(resp.Error),
			stdoutTrunc,
			stderrTrunc,
			errTrunc,
			stdout,
			stderr,
			errText,
		)
	}

	text := resp.Stdout
	if resp.Stderr != "" {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "stderr:\n" + resp.Stderr
	}
	if resp.Error != "" {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "error:\n" + resp.Error
	}
	if text == "" {
		text = "(no output)"
	}

	result := toolCallResult{
		Content: []contentItem{
			{Type: "text", Text: text},
		},
		StructuredContent: map[string]any{
			"id":          resp.ID,
			"exit_code":   resp.ExitCode,
			"cwd":         resp.Cwd,
			"stdout":      resp.Stdout,
			"stderr":      resp.Stderr,
			"truncated":   resp.Truncated,
			"duration_ms": resp.DurationMs,
			"error":       resp.Error,
		},
	}
	if resp.ExitCode != 0 || resp.Error != "" {
		result.IsError = true
	}

	return req.resultResponse(result)
}

func readBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func truncateForLog(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	return s[:max] + "...(truncated)", true
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternal       = -32603
)

func (r jsonRPCRequest) resultResponse(result any) *jsonRPCResponse {
	if isNotification(r.ID) {
		return nil
	}
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      r.ID,
		Result:  result,
	}
}

func (r jsonRPCRequest) errorResponse(code int, message string) *jsonRPCResponse {
	if isNotification(r.ID) {
		return nil
	}
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      r.ID,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
}

func isNotification(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	trim := bytes.TrimSpace(id)
	return bytes.Equal(trim, []byte("null"))
}

type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      map[string]any `json:"clientInfo"`
}

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      serverInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type execArgs struct {
	Cmd       string `json:"cmd"`
	TimeoutMs int    `json:"timeout_ms"`
}

type toolCallResult struct {
	Content           []contentItem  `json:"content"`
	IsError           bool           `json:"isError,omitempty"`
	StructuredContent map[string]any `json:"structuredContent,omitempty"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
