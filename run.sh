#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

CONFIG_FILE="${ROOT_DIR}/config.env"
if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "missing ${CONFIG_FILE}; copy config.env.example and fill in values" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${CONFIG_FILE}"
set +a

exec "${ROOT_DIR}/server"
