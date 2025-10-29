#!/usr/bin/env bash
# Wrapper de compatibilidad: delega al desinstalador Linux en ModeloARCH
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$ROOT_DIR/ModeloARCH/uninstall_arch.sh"
if [[ -f "$TARGET" ]]; then
  exec bash "$TARGET" "$@"
else
  echo "[ERROR] No se encuentra $TARGET" >&2
  exit 1
fi
