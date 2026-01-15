#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

export GOCACHE="${ROOT_DIR}/.gocache"
export GOMODCACHE="${ROOT_DIR}/.gomodcache"
export GOPATH="${ROOT_DIR}/.gopath"
: "${GOTOOLCHAIN:=auto}"
export GOTOOLCHAIN

API_KEY="testkey"
LISTEN_ADDR="127.0.0.1:9000"
EXECUTOR_PATH="${ROOT_DIR}/executor"
MAX_OUTPUT_CHARS=200000
BASH_PATH="/bin/bash"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd python3

run_server() {
  local outgoing="$1"
  export LISTEN_ADDR
  export API_KEY
  export MAX_OUTPUT_CHARS
  export EXECUTOR_PATH
  export WRITE_ALLOW="/tmp"
  export BIND_TCP_ALLOW="5173"
  export ALLOW_OUTGOING_TCP="$outgoing"
  export BASH_PATH

  "${ROOT_DIR}/server" >/tmp/gptsh-server.log 2>&1 &
  SERVER_PID=$!
  for _ in {1..50}; do
    if curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${API_KEY}" -X POST \
      -d '{"cmd":"true"}' "http://${LISTEN_ADDR}/exec" | grep -q "200"; then
      return 0
    fi
    sleep 0.1
  done
  echo "server failed to start" >&2
  stop_server
  return 1
}

stop_server() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}

exec_cmd() {
  local cmd="$1"
  python3 - "$cmd" <<'PY' | curl -s -H "Authorization: Bearer ${API_KEY}" -X POST --data-binary @- "http://${LISTEN_ADDR}/exec"
import json,sys
print(json.dumps({"cmd": sys.argv[1]}))
PY
}

get_field() {
  local field="$1"
  python3 -c 'import json,sys; resp=json.load(sys.stdin); print(resp.get(sys.argv[1],""))' "$field"
}

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $msg (got=$got want=$want)" >&2
    exit 1
  fi
}

assert_ne() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" == "$want" ]]; then
    echo "FAIL: $msg (got=$got)" >&2
    exit 1
  fi
}

run_state_tests() {
  local resp
  resp=$(exec_cmd "pwd")
  local cwd
  cwd=$(printf "%s" "$resp" | get_field cwd)
  [[ -n "$cwd" ]] || { echo "FAIL: empty cwd" >&2; exit 1; }

  resp=$(exec_cmd "cd /tmp")
  cwd=$(printf "%s" "$resp" | get_field cwd)
  assert_eq "$cwd" "/tmp" "cwd after cd"

  resp=$(exec_cmd "pwd")
  cwd=$(printf "%s" "$resp" | get_field cwd)
  assert_eq "$cwd" "/tmp" "cwd persists"

  resp=$(exec_cmd "export X=1")
  resp=$(exec_cmd 'echo "$X"')
  local out
  out=$(printf "%s" "$resp" | get_field stdout)
  out=${out%$'\n'}
  assert_eq "$out" "1" "env persists"
}

run_write_tests() {
  local resp
  resp=$(exec_cmd "touch /tmp/gptsh_ok")
  local code
  code=$(printf "%s" "$resp" | get_field exit_code)
  assert_eq "$code" "0" "write allow /tmp"

  resp=$(exec_cmd "touch /etc/gptsh_nope")
  code=$(printf "%s" "$resp" | get_field exit_code)
  assert_ne "$code" "0" "write denied /etc"
}

run_bind_tests() {
  local resp
  resp=$(exec_cmd "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",5173)); s.close()'")
  local code
  code=$(printf "%s" "$resp" | get_field exit_code)
  assert_eq "$code" "0" "bind allowed 5173"

  resp=$(exec_cmd "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",9999)); s.close()'")
  code=$(printf "%s" "$resp" | get_field exit_code)
  assert_ne "$code" "0" "bind denied 9999"
}

run_outgoing_denied_test() {
  local resp
  resp=$(exec_cmd "python3 -c 'code=\"import socket\\ntry:\\n    s=socket.socket(); s.connect((\\\"127.0.0.1\\\",1)); s.close(); print(\\\"ok\\\")\\nexcept OSError as e:\\n    print(e.errno)\\n\"; exec(code)'")
  local out
  out=$(printf "%s" "$resp" | get_field stdout)
  out=${out%$'\n'}
  if [[ "$out" != "1" && "$out" != "13" ]]; then
    echo "FAIL: outgoing connect denied (got=$out want=1 or 13)" >&2
    exit 1
  fi
}

run_outgoing_allowed_test() {
  local resp
  resp=$(exec_cmd "python3 -c 'code=\"import socket\\ntry:\\n    s=socket.socket(); s.connect((\\\"127.0.0.1\\\",1)); s.close(); print(\\\"ok\\\")\\nexcept OSError as e:\\n    print(e.errno)\\n\"; exec(code)'")
  local out
  out=$(printf "%s" "$resp" | get_field stdout)
  out=${out%$'\n'}
  assert_eq "$out" "111" "outgoing connect allowed (ECONNREFUSED)"
}

main() {
  local port
  port=$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(('127.0.0.1',0))
print(s.getsockname()[1])
s.close()
PY
)
  LISTEN_ADDR="127.0.0.1:${port}"

  make -C "${ROOT_DIR}" build

  echo "== Running tests with outgoing TCP denied =="
  trap stop_server EXIT
  run_server "false"
  run_state_tests
  run_write_tests
  run_bind_tests
  run_outgoing_denied_test
  stop_server
  trap - EXIT

  echo "== Running tests with outgoing TCP allowed =="
  trap stop_server EXIT
  run_server "true"
  run_outgoing_allowed_test
  stop_server
  trap - EXIT

  echo "ALL TESTS PASSED"
}

main "$@"
