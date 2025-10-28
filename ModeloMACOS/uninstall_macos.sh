#!/usr/bin/env bash
# Desinstalador de Piper CLI para macOS (ModeloMACOS)
set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_HOME="$HOME/.local/bin"
PIPER_HOME="$DATA_HOME/piper-cli"
PIPER_WRAPPER="$BIN_HOME/piper"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"

say() { echo -e "$*"; }
exists() { command -v "$1" >/dev/null 2>&1; }

say "\n== Desinstalación Piper (macOS) ==\n"

# Detener ollama si está bajo brew services
if exists brew; then
  if brew services list | grep -q '^ollama\b'; then
    say "[INFO] Deteniendo Ollama (brew services)"
    brew services stop ollama || true
  fi
fi

# Fallback: launchd plist
PLIST="$LAUNCH_AGENTS/com.piper.ollama.plist"
if [[ -f "$PLIST" ]]; then
  say "[INFO] Unloading LaunchAgent com.piper.ollama"
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
fi

# Eliminar Piper CLI
rm -rf "$PIPER_HOME"
rm -f "$PIPER_WRAPPER"

say "\n[OK] Piper desinstalado.\n"
say "Puedes borrar la configuración persistente con: rm -rf ~/.local/share/piper (opcional)"
