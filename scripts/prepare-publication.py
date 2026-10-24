# /// script
# requires-python = ">=3.11"
# dependencies = ["git-filter-repo==2.47.0"]
# ///
"""Create a separate publication repository with sanitized history and sources.

Run with uv. The original worktree, refs and remotes are never changed. No push
is performed. Review the generated repository before using its rewritten history.
"""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TOP_LEVEL = {
    ".gitignore", "Makefile", "README.md", "SECURITY.md", "LICENSE", "LICENSE.md",
    "go.mod", "go.sum", "config.env.example", "openapi.yaml", "privacy-policy.html", "run.sh",
}
SOURCE_DIRS = {"cmd", "internal", "scripts", "systemd", "docs", ".github"}
SOURCE_SUFFIXES = {".go", ".md", ".sh", ".py", ".yaml", ".yml", ".in", ".html"}
SECRET_PATTERNS = (
    rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{25,}",
    rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
    rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
)


def git(directory: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(directory), *args], stderr=subprocess.PIPE)


def quoted_settings(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return dict(re.findall(r'^([A-Z_]+)="([^"\n]*)"', path.read_text(), re.MULTILINE))


def public_replacements(settings: dict[str, str]) -> dict[str, str]:
    replacements = {}
    for name in ("PUBLIC_URL", "AUTH_SERVER_URL"):
        value = settings.get(name, "")
        if value.startswith(("https://", "http://")) and "example.com" not in value:
            replacements[value] = "https://mcp.example.com"
    # Recover old deployment examples without baking private domains or user
    # paths into this reusable publication script.
    for revision in git(ROOT, "rev-list", "HEAD").decode().splitlines():
        for name in ("openapi.yaml", "config.env.example"):
            try:
                source = git(ROOT, "show", f"{revision}:{name}").decode()
            except subprocess.CalledProcessError:
                continue
            if name == "openapi.yaml":
                for value in re.findall(r'^\s*- url:\s*(https?://\S+)', source, re.MULTILINE):
                    if "example.com" not in value:
                        replacements[value] = "https://mcp.example.com"
            else:
                for value in re.findall(r'^WRITE_ALLOW="([^"\n]+)"', source, re.MULTILINE):
                    if value not in {"/path/to/workspace", "/tmp"}:
                        replacements[value] = "/path/to/workspace"
    return replacements


def publication_sources() -> list[Path]:
    paths = git(ROOT, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
    result = []
    for raw in paths:
        if not raw:
            continue
        relative = Path(raw.decode())
        allowed = str(relative) in TOP_LEVEL or (
            relative.parts[0] in SOURCE_DIRS and relative.suffix in SOURCE_SUFFIXES
        )
        source = ROOT / relative
        if allowed and source.is_file() and not source.is_symlink():
            result.append(relative)
    return sorted(set(result))


def verify_history(repository: Path, settings: dict[str, str]) -> int:
    secrets = [settings.get(key, "").encode() for key in ("API_KEY", "OAUTH_PASSWORD")]
    secrets = [value for value in secrets if len(value) >= 8 and value != b"replace_me"]
    checked = 0
    for entry in git(repository, "rev-list", "--objects", "--all").decode().splitlines():
        oid, _, path = entry.partition(" ")
        if not path or git(repository, "cat-file", "-t", oid).strip() != b"blob":
            continue
        content = git(repository, "cat-file", "blob", oid)
        if content.startswith(b"\x7fELF"):
            raise RuntimeError(f"Publication stopped: historical binary in {path}")
        if any(value in content for value in secrets) or any(re.search(pattern, content) for pattern in SECRET_PATTERNS):
            raise RuntimeError(f"Publication stopped: possible credential in {path}; value withheld")
        checked += 1
    return checked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New, nonexistent output directory; defaults to a temporary directory")
    args = parser.parse_args()
    if args.output:
        destination = args.output.resolve()
        if destination.exists():
            parser.error("output directory already exists; it will not be overwritten")
    else:
        destination = Path(tempfile.mkdtemp(prefix="gptsh-publication-")) / "repo"
    settings = quoted_settings(ROOT / "config.env")
    replacements = public_replacements(settings)
    # Independent objects prevent history filtering from affecting the source.
    subprocess.run(["git", "clone", "--no-local", "--no-hardlinks", "--single-branch", str(ROOT), str(destination)], check=True)
    with tempfile.TemporaryDirectory(prefix="gptsh-filter-") as temporary:
        replacement_file = Path(temporary) / "replacements.txt"
        replacement_file.write_text("".join(f"literal:{old}==>{new}\n" for old, new in replacements.items()))
        command = [sys.executable, "-m", "git_filter_repo", "--force", "--replace-text", str(replacement_file), "--invert-paths"]
        for path in ("server", "executor", "config.env", "oauth.sqlite", ".env", ".codex", ".agents/", ".gocache/", ".gomodcache/", ".gopath/"):
            command += ["--path", path]
        for pattern in ("*.sqlite*", "*.log", "*.bak", "*.pem", "*.key"):
            command += ["--path-glob", pattern]
        subprocess.run(command, cwd=destination, check=True)
    # Replace the copy's tracked snapshot with the reviewed working sources,
    # including new tests/scripts, never ignored deployment files.
    for raw in git(destination, "ls-files", "-z").split(b"\0"):
        if raw:
            target = destination / raw.decode()
            if target.is_file() or target.is_symlink():
                target.unlink()
    sources = publication_sources()
    for relative in sources:
        source, target = ROOT / relative, destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_bytes()
        for old, new in replacements.items():
            content = content.replace(old.encode(), new.encode())
        target.write_bytes(content)
        shutil.copymode(source, target)
    git(destination, "add", "--all")
    if git(destination, "diff", "--cached", "--name-only").strip():
        git(destination, "-c", "user.name=gptsh publication", "-c", "user.email=publication@localhost", "commit", "-m", "Harden personal MCP server for publication")
    for remote in git(destination, "remote").decode().splitlines():
        git(destination, "remote", "remove", remote)
    checked = verify_history(destination, settings)
    print(f"Publication repository: {destination}")
    print(f"Copied {len(sources)} source files; checked {checked} historical blobs.")
    print("No remote is configured. Original refs/worktree unchanged. No push performed.")


if __name__ == "__main__":
    main()
