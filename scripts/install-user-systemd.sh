#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIT_NAME="gptsh.service"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
UNIT_PATH="${USER_UNIT_DIR}/${UNIT_NAME}"
TEMPLATE_PATH="${ROOT_DIR}/systemd/gptsh.service.in"
ACTION="install"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/install-user-systemd.sh
  ./scripts/install-user-systemd.sh --uninstall

Installs gptsh as a systemd user service. No sudo is required.
EOF
}

while (($# > 0)); do
  case "$1" in
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

command -v systemctl >/dev/null 2>&1 || {
  echo "systemctl is required" >&2
  exit 1
}

if [[ "${ACTION}" == "uninstall" ]]; then
  systemctl --user disable --now "${UNIT_NAME}" 2>/dev/null || true
  if [[ -f "${UNIT_PATH}" ]]; then
    rm -f -- "${UNIT_PATH}"
    systemctl --user daemon-reload
  fi
  echo "removed user service ${UNIT_NAME}"
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

escape_sed_replacement() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//\%/\%\%}
  value=${value//&/\\&}
  value=${value//|/\\|}
  printf '%s' "${value}"
}

escaped_root=$(escape_sed_replacement "${ROOT_DIR}")
escaped_start=$(escape_sed_replacement "${ROOT_DIR}/run.sh")
if [[ "${ROOT_DIR}" =~ [[:space:]] ]]; then
  echo "the project path cannot contain whitespace for this systemd unit: ${ROOT_DIR}" >&2
  exit 1
fi
rendered_unit=$(mktemp --suffix=.service "/tmp/gptsh-user.XXXXXX")
trap 'rm -f -- "${rendered_unit}"' EXIT

# User and Group are inherited from the per-user systemd manager.
sed \
  -e '/^After=network-online.target$/d' \
  -e '/^Wants=network-online.target$/d' \
  -e '/^User=@SERVICE_USER@$/d' \
  -e '/^Group=@SERVICE_GROUP@$/d' \
  -e "s|@WORKING_DIRECTORY@|${escaped_root}|g" \
  -e "s|@EXEC_START@|\"${escaped_start}\"|g" \
  -e 's/^WantedBy=multi-user.target$/WantedBy=default.target/' \
  "${TEMPLATE_PATH}" >"${rendered_unit}"

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "${rendered_unit}"
fi

mkdir -p "${USER_UNIT_DIR}"
install -m 0644 "${rendered_unit}" "${UNIT_PATH}"
systemctl --user daemon-reload
# Remove links created by previous versions (which used multi-user.target).
systemctl --user disable "${UNIT_NAME}" >/dev/null 2>&1 || true
systemctl --user enable --now "${UNIT_NAME}"

if command -v loginctl >/dev/null 2>&1; then
  if loginctl enable-linger "$(id -un)" &&
    [[ "$(loginctl show-user "$(id -un)" --property=Linger --value 2>/dev/null)" == "yes" ]]; then
    echo "linger enabled: ${UNIT_NAME} can start at boot without a login session"
  else
    echo "warning: could not enable linger; the service will start when you log in" >&2
    echo "an administrator can enable it with: loginctl enable-linger $(id -un)" >&2
  fi
else
  echo "warning: loginctl is unavailable; the service will start when you log in" >&2
fi

systemctl --user --no-pager --full status "${UNIT_NAME}"
