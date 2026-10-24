# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.12,<2", "httpx>=0.28,<1"]
# ///
"""Exercise local OAuth and MCP with the official Python client SDK.

Run after `make build`: uv run scripts/test-mcp.py
An isolated test server uses temporary credentials and a temporary database.
"""

import asyncio
import argparse
import base64
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from urllib.parse import parse_qs, urlparse

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


ROOT = Path(__file__).resolve().parent.parent
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


async def verify_mcp(base_url: str, token: str) -> None:
    async with streamablehttp_client(
        f"{base_url}/mcp", headers={"Authorization": f"Bearer {token}"}
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            initialization = await session.initialize()
            assert initialization.protocolVersion == "2025-06-18"
            await session.send_ping()
            tools = (await session.list_tools()).tools
            assert len(tools) == 1 and tools[0].name == "exec"
            assert tools[0].annotations.destructiveHint
            result = await session.call_tool(
                "exec", {"cmd": "cd /tmp && export MCP_CHECK=ready && echo $MCP_CHECK"}
            )
            assert not result.isError, result
            assert result.structuredContent["stdout"] == "ready\n"
            result = await session.call_tool("exec", {"cmd": "echo $MCP_CHECK"})
            assert result.structuredContent["stdout"] == "ready\n"
            result = await session.call_tool("exec", {
                "cmd": "printf '%s:%s:%s' \"${API_KEY-unset}\" \"${OAUTH_PASSWORD-unset}\" \"${GPTSH_TEST_PRIVATE_TOKEN-unset}\""
            })
            assert result.structuredContent["stdout"] == "unset:unset:unset"
            result = await session.call_tool("exec", {"cmd": "false"})
            assert result.isError and result.structuredContent["exit_code"] == 1
            result = await session.call_tool("exec", {"cmd": "sleep 5", "timeout_ms": 100})
            assert result.isError and result.structuredContent["exit_code"] == 124
            result = await session.call_tool("exec", {"cmd": "echo recovered"})
            assert not result.isError and result.structuredContent["stdout"] == "recovered\n"


async def run_checks(base_url: str, inspector_cli: str | None, directory: str) -> None:
    async with httpx.AsyncClient(base_url=base_url, follow_redirects=False) as client:
        for _ in range(100):
            try:
                if (await client.get("/mcp")).status_code == 405:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("test server failed to start")

        for path in ("/exec", "/openapi.json", "/openapi.yaml"):
            assert (await client.post(path)).status_code == 404
        metadata = (await client.get("/.well-known/oauth-authorization-server")).json()
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        resource = (await client.get("/.well-known/oauth-protected-resource")).json()
        assert resource["resource"] == base_url

        verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        form = {
            "client_id": "sdk-test", "response_type": "code", "redirect_uri": REDIRECT,
            "resource": base_url, "scope": "tools.execute", "state": "test-state",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        response = await client.get("/oauth/authorize", params=form)
        response.raise_for_status()
        form.update({
            "csrf_token": client.cookies["gptsh_login_csrf"],
            "username": "test-owner", "password": "test-password",
        })
        response = await client.post("/oauth/authorize", data=form)
        assert response.status_code == 302, response.text
        callback = parse_qs(urlparse(response.headers["location"]).query)
        assert callback["state"] == ["test-state"] and callback["iss"] == [base_url]
        response = await client.post("/oauth/token", data={
            "client_id": "sdk-test", "grant_type": "authorization_code",
            "code": callback["code"][0], "redirect_uri": REDIRECT,
            "resource": base_url, "code_verifier": verifier,
        })
        response.raise_for_status()
        token = response.json()["access_token"]
        await verify_mcp(base_url, token)
        if inspector_cli:
            common = [
                "node", inspector_cli, "--transport", "http", "--server-url", f"{base_url}/mcp",
                "--client-config", str(Path(directory) / "inspector-client.json"),
                "--header", f"Authorization: Bearer {token}",
            ]
            for method_args in (
                ["--method", "tools/list", "--strict"],
                ["--method", "tools/call", "--tool-name", "exec", "--tool-arg", "cmd=echo inspector-ok"],
            ):
                process = await asyncio.create_subprocess_exec(
                    *common, *method_args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env=os.environ | {"MCP_CATALOG_PATH": str(Path(directory) / "inspector-catalog.json")},
                )
                stdout, stderr = await process.communicate()
                if process.returncode:
                    raise RuntimeError(f"MCP Inspector failed: {stdout.decode()} {stderr.decode()}")
            print("MCP Inspector: strict tools/list and tools/call passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspector-cli", help="Optional path to MCP Inspector's clients/cli/build/index.js")
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="gptsh-mcp-test-") as directory:
        env = os.environ | {
            "LISTEN_ADDR": f"127.0.0.1:{port}", "PUBLIC_URL": base_url,
            "AUTH_SERVER_URL": base_url, "AUTH_MODE": "oauth", "DISABLE_ACTION": "true",
            "OAUTH_CLIENT_ID": "sdk-test", "OAUTH_REDIRECT_URIS": REDIRECT,
            "OAUTH_ALLOWED_SCOPES": "tools.read tools.execute",
            "OAUTH_USERNAME": "test-owner", "OAUTH_PASSWORD": "test-password",
            "OAUTH_SQLITE_PATH": str(Path(directory) / "oauth.sqlite"),
            "API_KEY": "test-api-key-canary", "GPTSH_TEST_PRIVATE_TOKEN": "test-private-canary",
            "EXECUTOR_PATH": str(ROOT / "executor"), "WRITE_ALLOW": directory,
            "BIND_TCP_ALLOW": "", "ALLOW_OUTGOING_TCP": "false", "BASH_PATH": "/bin/bash",
        }
        with tempfile.TemporaryFile(mode="w+") as server_log:
            server = subprocess.Popen([str(ROOT / "server")], cwd=ROOT, env=env, stdout=server_log, stderr=server_log)
            try:
                asyncio.run(run_checks(base_url, args.inspector_cli, directory))
            except BaseException:
                server_log.seek(0)
                print(server_log.read())
                raise
            finally:
                server.terminate()
                server.wait(timeout=10)
    print("Local OAuth + official MCP SDK: all checks passed")


if __name__ == "__main__":
    main()
