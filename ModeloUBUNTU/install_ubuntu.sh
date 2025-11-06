#!/usr/bin/env bash
# Instalador de Piper CLI para Ubuntu/Debian (ModeloUBUNTU)
# - Copia Piper a ~/.local/share/piper-cli/src y crea wrapper en ~/.local/bin/piper
# - Prepara dependencias con apt (opcional) y configura Ollama; systemd de usuario si está disponible
# - Usa archivos del repo desde REPO_ROOT (carpeta padre) como fuente
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] Este instalador es para Linux (Ubuntu/Debian)" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

DRY_RUN=0
USE_SYSTEMD=1
ENSURE_MODELS="${ENSURE_MODELS:-mistral:7b-instruct,phi3:mini}"
MODEL_OVERRIDE=""
DEFAULT_MODEL=""
RESTORE_TAR=""
WITH_CONFIG=""
UBUNTU_DIAG=0      # Ejecutar diagnósticos/preparación con sudo (apt)
USE_APT=0          # Prefiere apt para instalar ollama (el script oficial ya usa apt en Ubuntu)

say(){ echo -e "$*"; }
run(){ if [[ "$DRY_RUN" = 1 ]]; then echo "+ $*"; else eval "$*"; fi }
exists(){ command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --no-systemd) USE_SYSTEMD=0; shift ;;
  --ensure-models) ENSURE_MODELS="${2:-}"; shift 2 ;;
  --model) MODEL_OVERRIDE="${2:-}"; shift 2 ;;
    --restore) RESTORE_TAR="${2:-}"; shift 2 ;;
    --with-config) WITH_CONFIG="${2:-}"; shift 2 ;;
    --ubuntu-diag) UBUNTU_DIAG=1; shift ;;
    --use-apt) USE_APT=1; shift ;;
    *) echo "[WARN] Opción desconocida: $1"; shift ;;
  esac
done

# Destinos
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_HOME="$HOME/.local/bin"
PIPER_HOME="$DATA_HOME/piper-cli"
PIPER_SRC_DIR="$PIPER_HOME/src"
PIPER_WRAPPER="$BIN_HOME/piper"
PIPER_STATE_DIR="$DATA_HOME/piper"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

say "\n== Piper Installer (Ubuntu/Debian) ==\n"
say "Destino de instalación: $PIPER_HOME"
say "Wrapper: $PIPER_WRAPPER"

# Detectar Ubuntu/Debian
IS_DEBIAN=0
if [[ -f /etc/os-release ]]; then
  if grep -qiE '^(ID|ID_LIKE)=(debian|ubuntu)' /etc/os-release; then IS_DEBIAN=1; fi
fi
if command -v apt-get >/dev/null 2>&1; then IS_DEBIAN=1; fi
if [[ "$IS_DEBIAN" = 1 ]]; then
  say "[INFO] Detectado entorno Ubuntu/Debian (apt disponible)"
fi

# Diagnósticos/preparación opcional (sudo + apt)
if [[ "$UBUNTU_DIAG" = 1 && "$IS_DEBIAN" = 1 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    say "[DIAG] Actualizando índices y preparando dependencias básicas (curl git python3 systemd)"
    run "sudo apt-get update -y || true"
    run "sudo apt-get install -y curl git python3 python3-venv systemd || true"
    say "[DIAG] Información del sistema"
    run "lsb_release -a 2>/dev/null || cat /etc/os-release || true"
    run "uname -a || true"
    say "[DIAG] Habilitar linger para systemd --user"
    run "sudo loginctl enable-linger '$USER' || true"
  else
    say "[WARN] sudo no disponible; omitiendo diagnósticos con privilegios"
  fi
fi

# Si se especifica --model, forzar sólo ese modelo y usarlo por defecto en Piper
if [[ -n "$MODEL_OVERRIDE" ]]; then
  ENSURE_MODELS="$MODEL_OVERRIDE"
  DEFAULT_MODEL="$MODEL_OVERRIDE"
fi

# Crear carpetas destino
run "mkdir -p '$PIPER_HOME/src' '$BIN_HOME' '$PIPER_HOME/logs' '$PIPER_STATE_DIR'"

# Copiar fuentes del CLI
run "cp -r '$REPO_ROOT/src/'* '$PIPER_HOME/src/'"

# Instalar wrapper simple
if [[ -f "$REPO_ROOT/bin/piper" ]]; then
  run "install -m 0755 '$REPO_ROOT/bin/piper' '$PIPER_WRAPPER'"
else
  if [[ "$DRY_RUN" = 1 ]]; then
    say "+ Crear wrapper en $PIPER_WRAPPER"
  else
  cat >"$PIPER_WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PY=\${PYTHON:-python3}
PIPER_HOME="\${PIPER_HOME:-\${XDG_DATA_HOME:-\$HOME/.local/share}/piper-cli}"
APP_PATH="\$PIPER_HOME/src/piper_cli.py"
SRC_DIR="\$PIPER_HOME/src"
export PYTHONPATH="\$SRC_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
${DEFAULT_MODEL:+export PIPER_OLLAMA_MODEL="$DEFAULT_MODEL"}
exec "\$PY" "\$APP_PATH" "\$@"
EOF
    chmod +x "$PIPER_WRAPPER"
  fi
fi

# Asegurar ~/.local/bin en PATH
if ! echo ":$PATH:" | grep -q ":$BIN_HOME:"; then
  SHELL_RC=""
  if [[ -n "${BASH_VERSION:-}" ]]; then SHELL_RC="$HOME/.bashrc"; fi
  if [[ -n "${ZSH_VERSION:-}" ]]; then SHELL_RC="$HOME/.zshrc"; fi
  if [[ -z "$SHELL_RC" ]]; then SHELL_RC="$HOME/.profile"; fi
  say "[INFO] Agregando $BIN_HOME a PATH en $SHELL_RC"
  run "grep -q '\\$HOME/.local/bin' '$SHELL_RC' || echo 'export PATH="$HOME/.local/bin:\$PATH"' >> '$SHELL_RC'"
fi

# Instalar Ollama si no existe
if ! exists ollama; then
  if [[ "$IS_DEBIAN" = 1 ]]; then
    say "[INFO] Instalando Ollama (instalador oficial basado en apt)"
    if exists curl; then
      run "curl -fsSL https://ollama.com/install.sh | sh"
    else
      say "[ERROR] curl no está instalado. Ejecuta con --ubuntu-diag o instala curl manualmente."
    fi
  else
    say "[WARN] Entorno no reconocido como Debian/Ubuntu; intentando instalador oficial"
    if exists curl; then
      run "curl -fsSL https://ollama.com/install.sh | sh"
    else
      say "[ERROR] curl no está instalado."
    fi
  fi
fi

# Configurar servicio de usuario para Ollama (systemd)
if [[ "$USE_SYSTEMD" = 1 ]]; then
  if exists systemctl; then
    run "mkdir -p '$SYSTEMD_USER_DIR'"
    if [[ -f "$REPO_ROOT/systemd/ollama.service" ]]; then
      run "install -m 0644 '$REPO_ROOT/systemd/ollama.service' '$SYSTEMD_USER_DIR/ollama.service'"
    else
      run "bash -c 'cat >\''$SYSTEMD_USER_DIR/ollama.service'\'' <<"UNIT"\n[Unit]\nDescription=Ollama (user)\nAfter=network.target\n\n[Service]\nExecStart=ollama serve\nRestart=on-failure\nEnvironment=OLLAMA_HOST=127.0.0.1:11434\n\n[Install]\nWantedBy=default.target\nUNIT\n'"
    fi
    run "systemctl --user daemon-reload"
    run "systemctl --user enable --now ollama.service || true"
  else
    say "[WARN] systemctl no disponible; usando fallback sin systemd"
    USE_SYSTEMD=0
  fi
fi

# Fallback para iniciar ollama sin systemd
if [[ "$USE_SYSTEMD" = 0 ]]; then
  if pgrep -f "ollama serve" >/dev/null 2>&1; then
    say "[INFO] ollama serve ya está en ejecución"
  else
    say "[INFO] iniciando ollama serve en background (nohup)"
    run "nohup sh -c 'OLLAMA_HOST=127.0.0.1:11434 ollama serve >>"$PIPER_HOME/logs/ollama.log" 2>&1' &"
  fi
fi

# Esperar a que Ollama responda
if exists curl; then
  for i in {1..30}; do
    if curl -fsS "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
fi

# Restaurar backup configuraciones si se da
if [[ -n "$RESTORE_TAR" ]]; then
  if [[ -f "$RESTORE_TAR" ]]; then
    say "[INFO] Restaurando backup: $RESTORE_TAR"
    run "tar -xzf '$RESTORE_TAR' -C '$HOME'"
  else
    say "[WARN] No existe el archivo de backup: $RESTORE_TAR"
  fi
fi

# Copiar config por defecto si existe en el repo o se proporcionó
if [[ -n "$WITH_CONFIG" ]]; then
  run "install -m 0644 '$WITH_CONFIG' '$PIPER_STATE_DIR/config.json'"
elif [[ -f "$REPO_ROOT/state/config.json" ]]; then
  run "install -m 0644 '$REPO_ROOT/state/config.json' '$PIPER_STATE_DIR/config.json'"
fi

# Aplicar defaults (idempotente)
run "ENV= PIPER_STATE_DIR='$PIPER_STATE_DIR' '$PIPER_WRAPPER' config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python >/dev/null 2>&1 || true"

# Asegurar modelos
IFS=',' read -r -a MODELS <<< "$ENSURE_MODELS"
if [[ ${#MODELS[@]} -gt 0 ]]; then
  if exists ollama; then
    for m in "${MODELS[@]}"; do
      m_trim="${m// /}"
      [[ -z "$m_trim" ]] && continue
      say "[INFO] Asegurando modelo: $m_trim"
      run "ollama pull '$m_trim' || true"
    done
  else
    say "[WARN] Ollama no está instalado; omitiendo pull de modelos"
  fi
fi

# Comprobaciones
say "\n== Comprobación =="
if [[ -x "$PIPER_WRAPPER" ]]; then
  say "- Piper instalado en: $PIPER_WRAPPER"
else
  say "[ERROR] Piper no se instaló correctamente en $PIPER_WRAPPER"
fi
if exists curl && curl -fsS "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then
  say "- Ollama responde en 127.0.0.1:11434"
else
  say "[WARN] No se pudo verificar Ollama vía HTTP (puede ser temporal)"
fi

run "'$PIPER_WRAPPER' config --show || true"

say "\nInstalación finalizada. Abre una nueva terminal o ejecuta: source ~/.bashrc (o ~/.zshrc) para refrescar PATH."
