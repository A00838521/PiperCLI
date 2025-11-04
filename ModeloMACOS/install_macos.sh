#!/usr/bin/env bash
# Instalador de Piper CLI para macOS (ModeloMACOS)
# - Copia Piper a ~/.local/share/piper-cli/src y crea wrapper en ~/.local/bin/piper
# - Instala Homebrew si falta (sin sudo), Python3 si falta, y Ollama vía brew
# - Inicia Ollama con brew services (launchd). Fallback: plist de usuario
# - Asegura modelos por defecto y aplica configuración inicial
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[ERROR] Este instalador es solo para macOS" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
ENSURE_MODELS=${ENSURE_MODELS:-"mistral:7b-instruct,phi3:mini"}
DRY_RUN=${DRY_RUN:-0}

say() { echo -e "$*"; }
exists() { command -v "$1" >/dev/null 2>&1; }
run() { if [[ "$DRY_RUN" = 1 ]]; then echo "+ $*"; else eval "$*"; fi }

# Destinos (consistentes con Linux)
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_HOME="$HOME/.local/bin"
PIPER_HOME="$DATA_HOME/piper-cli"
PIPER_SRC_DIR="$PIPER_HOME/src"
PIPER_WRAPPER="$BIN_HOME/piper"
PIPER_STATE_DIR="$DATA_HOME/piper"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"

say "\n== Piper Installer (macOS) ==\n"
say "Destino: $PIPER_HOME"
say "Wrapper: $PIPER_WRAPPER"

# Homebrew
if ! exists brew; then
  say "[INFO] Instalando Homebrew..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || {
    say "[ERROR] Falló la instalación de Homebrew. Instálalo manualmente desde https://brew.sh/"
    exit 1
  }
  # Ajustar PATH para brew reciente (Apple Silicon/intel)
  if [[ -d "/opt/homebrew/bin" ]]; then
    echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "$HOME/.zprofile"
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -d "/usr/local/bin" ]]; then
    echo 'eval "$(/usr/local/bin/brew shellenv)"' >> "$HOME/.zprofile"
    eval "$(/usr/local/bin/brew shellenv)"
  fi
fi

# Python3 y curl
if ! exists python3; then
  say "[INFO] Instalando python3 via brew..."
  run "brew install python"
fi
if ! exists curl; then
  say "[INFO] Instalando curl via brew..."
  run "brew install curl"
fi

# Crear carpetas destino
run "mkdir -p '$PIPER_HOME/src' '$BIN_HOME' '$PIPER_HOME/logs' '$PIPER_STATE_DIR'"

# Copiar fuentes del CLI
run "cp -r '$REPO_ROOT/src/'* '$PIPER_HOME/src/'"

# Instalar wrapper (script ejecutable que llama a piper_cli.py) evitando expansiones prematuras
run "printf '%s\n' \
'#!/usr/bin/env bash' \
'set -euo pipefail' \
'PY=\${PYTHON:-python3}' \
'SRC_DIR=\"$PIPER_HOME/src\"' \
'export PYTHONPATH=\"$SRC_DIR\${PYTHONPATH:+:$PYTHONPATH}\"' \
'exec \"\$PY\" \"$PIPER_HOME/src/piper_cli.py\" \"\$@\"' \
> '$PIPER_WRAPPER'"
run "chmod +x '$PIPER_WRAPPER'"

# Asegurar que ~/.local/bin está en PATH (zsh por defecto)
if ! echo ":$PATH:" | grep -q ":$BIN_HOME:"; then
  say "[INFO] Agregando $BIN_HOME a PATH en ~/.zshrc"
  if ! grep -q "\$HOME/.local/bin" "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
  fi
fi

# Instalar Ollama via brew si falta
if ! exists ollama; then
  say "[INFO] Instalando Ollama via Homebrew..."
  run "brew install ollama"
fi

# Iniciar Ollama (preferir brew services)
if brew services info ollama >/dev/null 2>&1; then
  say "[INFO] Iniciando Ollama con brew services..."
  run "brew services start ollama || true"
else
  # Fallback: launchd plist de usuario
  say "[WARN] brew services no disponible; instalando LaunchAgent desde plantilla del repo"
  run "mkdir -p '$LAUNCH_AGENTS'"
  PLIST="$LAUNCH_AGENTS/com.piper.ollama.plist"
  if [[ -f "$REPO_ROOT/ModeloMACOS/launchd/ollama.plist" ]]; then
    # Sustituir ${HOME} por la ruta absoluta del usuario para rutas de log seguras
    run "sed 's#\\${HOME}#'$HOME'#g' \"$REPO_ROOT/ModeloMACOS/launchd/ollama.plist\" > \"$PLIST\""
  else
    # Respaldo: generar un plist mínimo
    run "bash -c 'cat >\''$PLIST'\'' <<\"PL\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>com.piper.ollama</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>ollama</string>\n    <string>serve</string>\n  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n    <key>OLLAMA_HOST</key><string>127.0.0.1:11434</string>\n  </dict>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>StandardOutPath</key><string>$PIPER_HOME/logs/ollama.out.log</string>\n  <key>StandardErrorPath</key><string>$PIPER_HOME/logs/ollama.err.log</string>\n</dict>\n</plist>\nPL\n'"
  fi
  run "launchctl unload '$PLIST' 2>/dev/null || true"
  run "launchctl load -w '$PLIST' || true"
fi

# Espera breve a que Ollama responda
for i in {1..30}; do
  if curl -fsS "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

# Copiar config por defecto si existe en el repo
if [[ -f "$REPO_ROOT/state/config.json" ]]; then
  run "install -m 0644 '$REPO_ROOT/state/config.json' '$PIPER_STATE_DIR/config.json'"
fi

# Aplicar defaults (idempotente)
run "ENV= PIPER_STATE_DIR='$PIPER_STATE_DIR' '$PIPER_WRAPPER' config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python >/dev/null 2>&1 || true"

# Asegurar modelos (si Ollama está disponible)
IFS=',' read -r -a MODELS <<< "$ENSURE_MODELS"
if command -v ollama >/dev/null 2>&1; then
  for m in "${MODELS[@]}"; do
    m_trim="${m// /}"
    [[ -z "$m_trim" ]] && continue
    say "[INFO] Asegurando modelo: $m_trim"
    run "ollama pull '$m_trim' || true"
  done
fi

# Comprobaciones
say "\n== Comprobación =="
if [[ -x "$PIPER_WRAPPER" ]]; then
  say "- Piper instalado en: $PIPER_WRAPPER"
else
  say "[ERROR] Piper no se instaló correctamente en $PIPER_WRAPPER"
fi
if curl -fsS "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then
  say "- Ollama responde en 127.0.0.1:11434"
else
  say "[WARN] No se pudo verificar Ollama vía HTTP (puede ser temporal)"
fi

# Mostrar configuración
run "'$PIPER_WRAPPER' config --show || true"

say "\nInstalación finalizada. Abre una nueva terminal o ejecuta: source ~/.zshrc para refrescar PATH."
