#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

export LISTEN_ADDR="0.0.0.0:8002"
export API_KEY="TBy30YF0beiYN2Kf"
export MAX_OUTPUT_CHARS="50000"
export EXECUTOR_PATH="${ROOT_DIR}/executor"

export WRITE_ALLOW="/path/to/workspace"
export BIND_TCP_ALLOW="9000:9001:9002:9003:9004:9005"
export ALLOW_OUTGOING_TCP="true"
export BASH_PATH="/bin/bash"

exec "${ROOT_DIR}/server"
