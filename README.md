# gptsh MCP Server

Personal MCP server exposing one persistent bash session through a Landlock-sandboxed executor. Includes a local OAuth login, PKCE S256 and SQLite-backed codes/tokens. Every connection shares the same shell, working directory and environment; this is intentionally a single-owner service.

## Quick start

1) Copy the example config and edit values:

```bash
cp config.env.example config.env
```

2) Build with Go 1.26.10 or newer (the module's minimum includes security fixes):

```bash
make build
```

3) Run:

```bash
./run.sh
```

The MCP endpoint is available at:

- `http(s)://<host>/mcp`

The legacy exec endpoint remains available when `DISABLE_ACTION=false` (the default):

- `http(s)://<host>/exec`

The privacy policy page is available at:

- `http(s)://<host>/privacy-policy`

## Configuration

All configuration lives in `config.env` (loaded by `run.sh`).

Core settings:

- `LISTEN_ADDR` – address/port to bind (e.g. `0.0.0.0:8002`)
- `MAX_OUTPUT_CHARS` – output capture limit, between 1 and 1048576 bytes
- `EXECUTOR_PATH`
- `DISABLE_ACTION` – `true` returns 404 for `/exec`, `/openapi.json` and `/openapi.yaml`; `false` retains the existing Action during migration. It does not disable MCP, OAuth or the privacy page.

Sandbox settings (executor):

- `WRITE_ALLOW` – colon-separated allowed write paths
- `BIND_TCP_ALLOW` – colon-separated allowed bind ports
- `ALLOW_OUTGOING_TCP` – `true`/`false`
- `BASH_PATH`

Landlock policy is applied to all Go runtime threads before Bash starts. The
executor receives only the sandbox settings and basic shell variables (`PATH`,
`HOME`, `USER`, `LOGNAME`, locale, terminal, timezone and temporary-directory
settings). Bash receives only those shell variables. Server API keys, OAuth
credentials, cloud credentials and startup/loader hooks are not inherited.

Filesystem reads remain allowed wherever the service user can read. This is a
write/network sandbox, not a confidential filesystem container: commands can
still read credentials from files. File permissions remain an operator choice.

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
- `PUBLIC_URL` – canonical public HTTPS base URL, without `/mcp` (e.g. `https://mcp.example.com`). HTTP is allowed only on loopback for development. This exact URL is the OAuth `resource`/token audience.

Optional:

- `OAUTH_ALLOWED_SCOPES` – space-separated scopes (defaults to `tools.read tools.execute`). Calling `exec` requires `tools.execute`; a `tools.read` token can initialize and list tools but cannot execute commands.
- `OAUTH_TOKEN_TTL_SECONDS`
- `OAUTH_CODE_TTL_SECONDS`
- `AUTH_SERVER_URL` – issuer base URL, defaulting to `PUBLIC_URL`. If overridden, it must route to this server's OAuth handlers; this is not an external identity-provider setting.

OAuth endpoints:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp` – discovery alias for the `/mcp` endpoint
- `/.well-known/oauth-authorization-server`
- `/oauth/authorize`
- `/oauth/token`

## ChatGPT MCP setup notes

- Create a custom MCP connection using `https://<host>/mcp` and choose OAuth.
- Configure a **static public client** with the exact `OAUTH_CLIENT_ID` and no client secret. CIMD and dynamic client registration are not implemented; static registration is intentional for this personal server.
- Copy the exact callback URL displayed by ChatGPT into `OAUTH_REDIRECT_URIS`. Do not use the old Actions callback `/aip/oauth/callback`. The example uses `https://chatgpt.com/connector_platform_oauth_redirect`; the displayed callback is authoritative.
- Use `AUTH_MODE=oauth` for OAuth only, or `any` to keep API-key access for other clients. `any` is not anonymous/OAuth mixed authentication: every MCP request requires a Bearer credential.
- You authenticate on this server's form using `OAUTH_USERNAME` and `OAUTH_PASSWORD`. No external provider is contacted. The form uses a CSRF cookie and requires cookies in your browser.
- Clients send the exact advertised `resource` on both authorization and token requests. Tokens are checked for expiry, issuer, resource and execution scope.
- Only PKCE S256 is accepted. Authorization responses include `iss`, and redirect URLs must be explicitly allowlisted.
- Login is limited to five POST attempts per minute for the single account, across all IP addresses. Excess attempts return 429 and `Retry-After`. The limit also counts successful attempts and resets when the process restarts.
- Access tokens expire after `OAUTH_TOKEN_TTL_SECONDS` (default one hour). There is no refresh-token grant; reconnect/re-authorize when required.

See [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth) and [custom MCP connections](https://developers.openai.com/api/docs/guides/custom-mcp-server).

### Transport and diagnostics

`/mcp` implements stateless Streamable HTTP with JSON responses. It negotiates
`2025-06-18`; an unsupported initialization version receives the
server's supported version instead of being echoed. Subsequent requests may send
`MCP-Protocol-Version`; unsupported values return 400.

POST requires `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. Notifications receive 202. GET
and DELETE receive 405 because no standalone SSE stream or HTTP session is
offered. JSON-RPC batches are not supported. A transport session ID is not needed
to preserve the personal Bash session. Requests with an Origin must match the
public server origin.

The exact root `/` also serves MCP for older connections configured with just
the server origin. Other unknown paths still return 404, including disabled
Action endpoints. Prefer `/mcp` when configuring a new connection.

`exec` is explicitly marked as destructive, non-idempotent and capable of
accessing external systems. Its results include text and structured fields.
Timeout or cancellation restarts the executor and clears shell state. Logs
record IDs, exit codes, durations and output sizes, not command text or results.

The HTTP server handles at most 16 concurrent requests, returning 503 with
`Retry-After` during overload. Headers/body reads time out after 10 seconds;
writes after 65 seconds, and idle connections after 30 seconds. Headers are
limited to 32 KiB. Commands have a 1 MiB request limit and a 45-second execution
limit; internal frames are capped at 8 MiB before allocating memory.

The checked-in OpenAPI server URL is an example. When serving the legacy
schema, the application inserts `PUBLIC_URL` so the Action keeps working on
the configured host without committing that host to source control.

### Updating an existing deployment

Keep your existing `config.env` and SQLite file. Review `PUBLIC_URL`, the callback
allowlist and scopes, then rebuild and restart:

```bash
make build
systemctl --user restart gptsh
journalctl --user -u gptsh -n 30
```

Re-authorize the ChatGPT connection after upgrading: old tokens/codes without
resource binding are not accepted. New credentials use separate `*_v2` SQLite
tables with hashed codes/tokens; old tables are preserved. Refresh the connection's
tool metadata to pick up the annotations.

Set `DISABLE_ACTION=true` in `config.env` and restart when ready to disable the
old Action. Leaving it unset preserves those endpoints.

## Tests

```bash
make test
```

Run the security checks before publication:

```bash
make audit
```

The test suite builds server/executor, runs Go protocol/OAuth/routing tests and
checks sandbox behavior. Network and Landlock checks require a Linux host that
permits sockets and supports Landlock networking.

For an independent end-to-end check using the official Python MCP SDK:

```bash
make build
uv run scripts/test-mcp.py
```

This starts an isolated server on a temporary loopback port, uses test-only local
credentials and a temporary SQLite database, and verifies OAuth, initialization,
tools, persistent state, errors and timeout recovery. It does not use `config.env`
or restart the installed service. Dependencies are declared in the script.

The end-to-end check also verifies that test API/OAuth credentials and an
arbitrary private environment variable do not appear in Bash's initial environment.

You can also use MCP Inspector (`npx @modelcontextprotocol/inspector`) with
Streamable HTTP and the `/mcp` URL to inspect your deployed connection and OAuth
flow. Configure the same static public client, resource and allowed callback.

## Start automatically on boot (systemd)

On a Linux system that uses systemd, the recommended option installs a user
service and does not require `sudo`. First create and review `config.env`, then
build and install it:

```bash
cp config.env.example config.env
# Edit config.env and replace the example credentials and paths.
make install-user-service
```

The installer enables systemd linger when the system permits it, so the service
can start during boot without waiting for an interactive login. If linger cannot
be enabled, the service will still start when that user logs in.

Useful user-service commands:

```bash
systemctl --user status gptsh
journalctl --user -u gptsh -f
systemctl --user restart gptsh
make uninstall-user-service
```

Alternatively, install a system-wide service with administrative privileges:

```bash
make install-service
```

The installer enables and starts `gptsh.service` immediately. It runs as the
user that invoked `sudo`, so that user must have access to every path configured
in `WRITE_ALLOW` and `OAUTH_SQLITE_PATH`.

Useful service commands:

```bash
sudo systemctl status gptsh
sudo journalctl -u gptsh -f
sudo systemctl restart gptsh
make uninstall-service
```

To run the service as a different account, build first and invoke the installer
directly:

```bash
make build
sudo ./scripts/install-systemd.sh --user gptsh
```

## Preparing a public repository

Deployment files, database sidecars, backups, logs and local agent state are
ignored. Only publish `config.env.example`, with placeholder credentials and
paths. Builds use `-trimpath` to avoid embedding local source directories.

Ignoring a file does not remove an earlier committed copy. To prepare an
independent repository containing the current sources and cleaned history:

```bash
make prepare-publication
```

The script uses an independent clone, removes historical server/executor
binaries and deployment artifacts, replaces deployment domains and personal
example paths, then copies the working sources (including new tests). It checks
historical blobs for ELF binaries, common credential patterns and the current
API/OAuth password values without printing them. It never copies `config.env`
or SQLite data, changes the original refs, or pushes to a remote. The generated
repository has no remote configured. Review its output before publishing;
updating an existing remote to rewritten history requires separate coordination.

## Files

- `cmd/server` – HTTP/MCP server
- `cmd/executor` – sandboxed executor
- `internal/mcp` – MCP JSON-RPC handler
- `internal/auth` – OAuth + auth middleware
