# gptsh MCP Server

Minimal MCP server that exposes a persistent bash session via a sandboxed executor. Includes OAuth 2.1 (auth code + PKCE) and SQLite-backed persistence for codes/tokens.

## Quick start

1) Copy the example config and edit values:

```bash
cp config.env.example config.env
```

2) Build:

```bash
make build
```

3) Run:

```bash
./run.sh
```

The MCP endpoint is available at:

- `http(s)://<host>/mcp`

The legacy exec endpoint remains at:

- `http(s)://<host>/exec`

## Configuration

All configuration lives in `config.env` (loaded by `run.sh`).

Core settings:

- `LISTEN_ADDR` – address/port to bind (e.g. `0.0.0.0:8002`)
- `MAX_OUTPUT_CHARS`
- `EXECUTOR_PATH`

Sandbox settings (executor):

- `WRITE_ALLOW` – colon-separated allowed write paths
- `BIND_TCP_ALLOW` – colon-separated allowed bind ports
- `ALLOW_OUTGOING_TCP` – `true`/`false`
- `BASH_PATH`

### MCP auth modes

Set `AUTH_MODE` to one of:

- `api_key` – default, uses `API_KEY` as Bearer token
- `oauth` – OAuth 2.1 authorization code + PKCE
- `any` – accept either API key or OAuth
- `none` – no auth

### OAuth (self-contained)

This project includes a minimal OAuth provider with a login form. It **requires SQLite** for persistence.

Required (when OAuth is enabled):

- `OAUTH_CLIENT_ID`
- `OAUTH_REDIRECT_URIS` – space-separated list of allowed redirect URIs
- `OAUTH_SQLITE_PATH` – path to SQLite file (e.g. `./oauth.sqlite`)
- `OAUTH_USERNAME` / `OAUTH_PASSWORD` – credentials for the login form

Optional:

- `OAUTH_ALLOWED_SCOPES` – space-separated scopes
- `OAUTH_TOKEN_TTL_SECONDS`
- `OAUTH_CODE_TTL_SECONDS`
- `PUBLIC_URL` – external URL if behind a proxy
- `AUTH_SERVER_URL` – override OAuth issuer URL (defaults to `PUBLIC_URL`)

OAuth endpoints:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `/oauth/authorize`
- `/oauth/token`

## ChatGPT MCP setup notes

- ChatGPT requires OAuth 2.1 auth code + PKCE (client credentials are not supported).
- Configure **static client credentials** in ChatGPT and set `OAUTH_CLIENT_ID` to match. This server accepts public clients only (no client secret).
- Ensure `PUBLIC_URL` is set if running behind a proxy, and that `OAUTH_REDIRECT_URIS` includes ChatGPT’s redirect URI.

## Tests

```bash
make test
```

The test suite builds server/executor and runs sandbox behavior checks.

## Files

- `cmd/server` – HTTP/MCP server
- `cmd/executor` – sandboxed executor
- `internal/mcp` – MCP JSON-RPC handler
- `internal/auth` – OAuth + auth middleware
