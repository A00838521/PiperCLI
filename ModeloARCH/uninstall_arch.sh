#!/usr/bin/env bash
# Desinstalador de Piper CLI para Linux (ModeloARCH)
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] Este desinstalador es solo para Linux" >&2
  exit 2
fi

DRY_RUN=${DRY_RUN:-0}
KEEP_STATE=0
STOP_SERVICE=0

say(){ echo -e "$*"; }
run(){ if [[ "$DRY_RUN" = 1 ]]; then echo "+ $*"; else eval "$*"; fi }
exists(){ command -v "$1" >/dev/null 2>&1; }

# Rutas
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_HOME="$HOME/.local/bin"
WRAPPER="$BIN_HOME/piper"
PIPER_HOME="$DATA_HOME/piper-cli"
PIPER_STATE_DIR="$DATA_HOME/piper"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --keep-state) KEEP_STATE=1; shift;;
    --stop-service) STOP_SERVICE=1; shift;;
    *) say "[WARN] Opción desconocida: $1"; shift;;
  esac
done

say "\n== Piper Uninstaller (Linux/ModeloARCH) ==\n"

if [[ "$STOP_SERVICE" = 1 ]]; then
  if exists systemctl; then
    run "systemctl --user stop ollama.service || true"
  fi
  run "pkill -f 'ollama serve' 2>/dev/null || true"
fi

# Quitar wrapper
if [[ -f "$WRAPPER" ]]; then
  run "rm -f '$WRAPPER'"
  say "- Eliminado wrapper: $WRAPPER"
else
  say "- Wrapper no encontrado (ok)"
fi

# Quitar instalación del CLI
if [[ -d "$PIPER_HOME" ]]; then
  run "rm -rf '$PIPER_HOME'"
  say "- Eliminado: $PIPER_HOME"
else
  say "- Directorio de instalación no encontrado (ok)"
fi

# Quitar unidad systemd de usuario si existe
if [[ -f "$SYSTEMD_USER_DIR/ollama.service" ]]; then
  run "rm -f '$SYSTEMD_USER_DIR/ollama.service'"
  say "- Eliminada unidad systemd de usuario: ollama.service"
fi

# Estado
if [[ "$KEEP_STATE" = 1 ]]; then
  say "- Conservando estado en $PIPER_STATE_DIR"
else
  if [[ -d "$PIPER_STATE_DIR" ]]; then
    run "rm -rf '$PIPER_STATE_DIR'"
    say "- Eliminado estado: $PIPER_STATE_DIR"
  else
    say "- Estado no encontrado (ok)"
  fi
fi

say "\nDesinstalación completada."
