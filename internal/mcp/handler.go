package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"gptsh/internal/auth"
	"gptsh/internal/proto"
)

const defaultProtocolVersion = "2025-06-18"

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
	PublicURL      string

	idCounter int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Stateless Streamable HTTP: POST returns JSON. No SSE stream or transport
	// session is advertised; the personal shell persists independently.
	if !h.allowedOrigin(r) {
		http.Error(w, "origin is not allowed", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Auth != nil && !h.Auth.AuthorizeRequest(r) {
		h.Auth.WriteUnauthorized(w, r)
		return
	}
	if version := r.Header.Get("MCP-Protocol-Version"); version != "" && !supportedVersion(version) {
		http.Error(w, "unsupported MCP protocol version", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if !accepts(r.Header.Get("Accept"), "application/json") || !accepts(r.Header.Get("Accept"), "text/event-stream") {
		w.WriteHeader(http.StatusNotAcceptable)
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
	var request jsonRPCRequest
	if json.Unmarshal(body, &request) == nil && request.Method == "tools/call" &&
		h.Auth != nil && !h.Auth.AuthorizeRequest(r, "tools.execute") {
		h.Auth.WriteUnauthorized(w, r, "tools.execute")
		return
	}

	responses, ok := h.handlePayload(r.Context(), body)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(rpcError(nil, errParse, "parse error"))
		return
	}
	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
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
	if trimmed[0] != '{' {
		return []jsonRPCResponse{*rpcError(nil, errInvalidRequest, "expected one JSON-RPC object")}, true
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
	if req.JSONRPC != "2.0" || req.Method == "" || !validID(req.ID) {
		return rpcError(nil, errInvalidRequest, "invalid JSON-RPC request")
	}
	if isNotification(req.ID) {
		// Notifications never execute tools or produce responses.
		return nil
	}

	switch req.Method {
	case "initialize":
		return h.handleInitialize(req)
	case "notifications/initialized":
		return nil
	case "ping":
		return req.resultResponse(map[string]any{})
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
		return req.errorResponse(errInvalidParams, "protocolVersion is required")
	}
	if !supportedVersion(version) {
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
		Name:         "exec",
		Description:  "Execute a shell command inside the sandboxed persistent bash session",
		Annotations:  map[string]bool{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true, "idempotentHint": false},
		OutputSchema: execOutputSchema(),
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
			"required":             []string{"cmd"},
			"additionalProperties": false,
		},
	}
	if h.Auth != nil {
		tool.SecuritySchemes = h.Auth.SecuritySchemes()
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
	decoder := json.NewDecoder(bytes.NewReader(params.Arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return req.errorResponse(errInvalidParams, "invalid arguments")
	}
	if strings.TrimSpace(args.Cmd) == "" {
		return req.errorResponse(errInvalidParams, "cmd is required")
	}

	timeout := args.TimeoutMs
	var rawArgs map[string]json.RawMessage
	_ = json.Unmarshal(params.Arguments, &rawArgs)
	if _, present := rawArgs["timeout_ms"]; present && timeout == 0 {
		return req.errorResponse(errInvalidParams, "timeout_ms must be a positive integer when provided")
	}
	if timeout < 0 || timeout > h.MaxTimeoutMs {
		return req.errorResponse(errInvalidParams, "timeout_ms is out of range")
	}
	if timeout == 0 {
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
		h.Logf(
			"mcp tools/call response: id=%d exit=%d duration_ms=%d truncated=%t stdout_len=%d stderr_len=%d",
			resp.ID,
			resp.ExitCode,
			resp.DurationMs,
			resp.Truncated,
			len(resp.Stdout),
			len(resp.Stderr),
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

func supportedVersion(version string) bool {
	return version == defaultProtocolVersion
}

func execOutputSchema() map[string]any {
	properties := map[string]any{}
	for _, key := range []string{"cwd", "stdout", "stderr", "error"} {
		properties[key] = map[string]any{"type": "string"}
	}
	for _, key := range []string{"id", "exit_code", "duration_ms"} {
		properties[key] = map[string]any{"type": "integer"}
	}
	properties["truncated"] = map[string]any{"type": "boolean"}
	return map[string]any{
		"type": "object", "properties": properties,
		"required": []string{"id", "exit_code", "cwd", "stdout", "stderr", "truncated", "duration_ms", "error"},
	}
}

func accepts(header, want string) bool {
	for _, entry := range strings.Split(header, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err == nil && params["q"] != "0" && (mediaType == want || mediaType == "*/*") {
			return true
		}
	}
	return false
}

func (h *Handler) allowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Native MCP clients do not send Origin.
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	if h.PublicURL != "" {
		public, err := url.Parse(h.PublicURL)
		return err == nil && u.Scheme == public.Scheme && u.Host == public.Host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && u.Host == r.Host
}

func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	var value any
	if json.Unmarshal(id, &value) != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func rpcError(id json.RawMessage, code int, message string) *jsonRPCResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &jsonRPCError{Code: code, Message: message}}
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
	errParse          = -32700
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
	OutputSchema    map[string]any   `json:"outputSchema"`
	Name            string           `json:"name"`
	Description     string           `json:"description,omitempty"`
	InputSchema     map[string]any   `json:"inputSchema"`
	Annotations     map[string]bool  `json:"annotations"`
	SecuritySchemes []map[string]any `json:"securitySchemes,omitempty"`
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
