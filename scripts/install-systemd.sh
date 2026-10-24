#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIT_NAME="gptsh.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
TEMPLATE_PATH="${ROOT_DIR}/systemd/gptsh.service.in"

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/install-systemd.sh [--user USER]
  sudo ./scripts/install-systemd.sh --uninstall

Installs and enables gptsh as a systemd system service. By default the service
runs as the user who invoked sudo (or the current user when already root).
EOF
}

ACTION="install"
SERVICE_USER="${SUDO_USER:-$(id -un)}"

while (($# > 0)); do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || { echo "--user requires a value" >&2; exit 2; }
      SERVICE_USER="$2"
      shift 2
      ;;
    --uninstall)
      ACTION="uninstall"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "this installer must run as root; use sudo $0" >&2
  exit 1
fi

command -v systemctl >/dev/null 2>&1 || {
  echo "systemctl is required" >&2
  exit 1
}

if [[ "${ACTION}" == "uninstall" ]]; then
  systemctl disable --now "${UNIT_NAME}" 2>/dev/null || true
  if [[ -f "${UNIT_PATH}" ]]; then
    rm -f -- "${UNIT_PATH}"
    systemctl daemon-reload
  fi
  echo "removed ${UNIT_NAME}"
  exit 0
fi

for required_file in config.env server executor run.sh "${TEMPLATE_PATH#${ROOT_DIR}/}"; do
  if [[ ! -f "${ROOT_DIR}/${required_file}" ]]; then
    echo "missing ${ROOT_DIR}/${required_file}" >&2
    if [[ "${required_file}" == "server" || "${required_file}" == "executor" ]]; then
      echo "run 'make build' before installing the service" >&2
    fi
    exit 1
  fi
done

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  echo "user does not exist: ${SERVICE_USER}" >&2
  exit 1
fi
SERVICE_GROUP=$(id -gn "${SERVICE_USER}")

escape_unit_value() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//\%/\%\%}
  value=${value//&/\\&}
  value=${value//|/\\|}
  printf '%s' "$value"
}

escaped_user=$(escape_unit_value "${SERVICE_USER}")
escaped_group=$(escape_unit_value "${SERVICE_GROUP}")
escaped_root=$(escape_unit_value "${ROOT_DIR}")
escaped_start=$(escape_unit_value "${ROOT_DIR}/run.sh")

case "${ROOT_DIR}" in
  /*) ;;
  *)
    echo "resolved project directory is not absolute: ${ROOT_DIR}" >&2
    exit 1
    ;;
esac
if [[ "${ROOT_DIR}" =~ [[:space:]] ]]; then
  echo "the project path cannot contain whitespace for this systemd unit: ${ROOT_DIR}" >&2
  exit 1
fi

rendered_unit=$(mktemp --suffix=.service "/tmp/gptsh.XXXXXX")
trap 'rm -f -- "${rendered_unit}"' EXIT

sed \
  -e "s|@SERVICE_USER@|${escaped_user}|g" \
  -e "s|@SERVICE_GROUP@|${escaped_group}|g" \
  -e "s|@WORKING_DIRECTORY@|${escaped_root}|g" \
  -e "s|@EXEC_START@|\"${escaped_start}\"|g" \
  "${TEMPLATE_PATH}" >"${rendered_unit}"

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "${rendered_unit}"
fi

install -m 0644 "${rendered_unit}" "${UNIT_PATH}"
systemctl daemon-reload
systemctl enable --now "${UNIT_NAME}"
systemctl --no-pager --full status "${UNIT_NAME}"
