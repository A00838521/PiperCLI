#!/usr/bin/env bash
# Instalador de Piper CLI para Linux (ModeloARCH)
# - Copia Piper a ~/.local/share/piper-cli/src y crea wrapper en ~/.local/bin/piper
# - Configura Ollama (curl installer) y servicio de usuario con systemd si está disponible
# - Usa archivos del repo desde REPO_ROOT (carpeta padre) como fuente
# - Asegura modelos por defecto y aplica configuración inicial
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] Este instalador es solo para Linux" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

DRY_RUN=0
USE_SYSTEMD=1
GIT_URL=""
GIT_BRANCH=""
ENSURE_MODELS="${ENSURE_MODELS:-mistral:7b-instruct,phi3:mini}"
RESTORE_TAR=""
WITH_CONFIG=""
# Opciones Arch
ARCH_DIAG=0           # Ejecutar diagnósticos y preparación del sistema usando sudo (si disponible)
USE_PACMAN=0          # Preferir instalar Ollama con pacman si está disponible

say() { echo -e "$*"; }
run() { if [[ "$DRY_RUN" = 1 ]]; then echo "+ $*"; else eval "$*"; fi }
exists() { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --no-systemd) USE_SYSTEMD=0; shift ;;
    --from-git) GIT_URL="${2:-}"; shift 2 ;;
    --branch) GIT_BRANCH="${2:-}"; shift 2 ;;
    --ensure-models) ENSURE_MODELS="${2:-}"; shift 2 ;;
    --restore) RESTORE_TAR="${2:-}"; shift 2 ;;
    --with-config) WITH_CONFIG="${2:-}"; shift 2 ;;
    --arch-diag) ARCH_DIAG=1; shift ;;
    --use-pacman) USE_PACMAN=1; shift ;;
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

say "\n== Piper Installer (Linux/ModeloARCH) ==\n"
say "Destino de instalación: $PIPER_HOME"
say "Wrapper: $PIPER_WRAPPER"

# Detectar Arch/pacman
IS_ARCH=0
if [[ -f /etc/os-release ]] && grep -qi '^ID=arch' /etc/os-release; then IS_ARCH=1; fi
if command -v pacman >/dev/null 2>&1; then IS_ARCH=1; fi
if [[ "$IS_ARCH" = 1 ]]; then
  say "[INFO] Detectado entorno Arch (pacman disponible)"
fi

# Diagnósticos y preparación opcional (sudo)
if [[ "$ARCH_DIAG" = 1 && "$IS_ARCH" = 1 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    say "[DIAG] Preparando dependencias con pacman (requiere sudo)"
    run "sudo pacman -Sy --needed --noconfirm curl git python systemd || true"
    say "[DIAG] Información del kernel y usuario"
    run "uname -a || true"
    run "id || true"
    say "[DIAG] Habilitar linger para systemd --user (permite servicios de usuario tras logout)"
    run "sudo loginctl enable-linger '$USER' || true"
  else
    say "[WARN] sudo no disponible; omitiendo diagnósticos con privilegios"
  fi
fi

# Preparar fuentes (locales o Git)
SRC_DIR="$REPO_ROOT"
if [[ -n "$GIT_URL" ]]; then
  if ! exists git; then say "[ERROR] git no está instalado"; exit 1; fi
  TMP_CLONE="$(mktemp -d)"
  run "git clone --depth=1 ${GIT_BRANCH:+-b $GIT_BRANCH} '$GIT_URL' '$TMP_CLONE'"
  # Detectar raíz que tenga carpeta src/
  if [[ -d "$TMP_CLONE/src" ]]; then
    SRC_DIR="$TMP_CLONE"
  elif [[ -d "$TMP_CLONE/piper-cli/src" ]]; then
    SRC_DIR="$TMP_CLONE/piper-cli"
  else
    say "[ERROR] No se encontró carpeta src/ en el repo clonado"
    exit 1
  fi
fi

# Crear carpetas destino
run "mkdir -p '$PIPER_HOME/src' '$BIN_HOME' '$PIPER_HOME/logs' '$PIPER_STATE_DIR'"

# Copiar fuentes del CLI
run "cp -r '$SRC_DIR/src/'* '$PIPER_HOME/src/'"

# Instalar wrapper (simple)
if [[ -f "$SRC_DIR/bin/piper" ]]; then
  run "install -m 0755 '$SRC_DIR/bin/piper' '$PIPER_WRAPPER'"
else
  if [[ "$DRY_RUN" = 1 ]]; then
    say "+ Crear wrapper en $PIPER_WRAPPER"
  else
    cat >"$PIPER_WRAPPER" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
PY=${PYTHON:-python3}
PIPER_HOME="${PIPER_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/piper-cli}"
SRC_DIR="$PIPER_HOME/src"
APP_PATH="$PIPER_HOME/src/piper_cli.py"
export PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}"

exec "$PY" "$APP_PATH" "$@"
WRAP
    chmod +x "$PIPER_WRAPPER"
  fi
fi

# Asegurar que ~/.local/bin esté en PATH
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
  if [[ "$IS_ARCH" = 1 && ( "$USE_PACMAN" = 1 || "$ARCH_DIAG" = 1 ) ]] && command -v sudo >/dev/null 2>&1; then
    say "[INFO] Intentando instalar Ollama con pacman (sudo)"
    if run "sudo pacman -S --noconfirm ollama"; then
      say "[OK] Ollama instalado vía pacman"
    else
      say "[WARN] No se pudo instalar ollama con pacman; intentando instalador oficial"
      if exists curl; then
        run "curl -fsSL https://ollama.com/install.sh | sh"
      else
        say "[ERROR] curl no está instalado. Instala curl u ollama manualmente."
      fi
    fi
  else
    say "[INFO] Instalando Ollama... (instalador oficial)"
    if exists curl; then
      run "curl -fsSL https://ollama.com/install.sh | sh"
    else
      say "[ERROR] curl no está instalado. Instala curl u ollama manualmente."
    fi
  fi
fi

# Configurar servicio de usuario para Ollama
if [[ "$USE_SYSTEMD" = 1 ]]; then
  if exists systemctl; then
    run "mkdir -p '$SYSTEMD_USER_DIR'"
    if [[ -f "$SRC_DIR/systemd/ollama.service" ]]; then
      run "install -m 0644 '$SRC_DIR/systemd/ollama.service' '$SYSTEMD_USER_DIR/ollama.service'"
    elif [[ -f "$REPO_ROOT/systemd/ollama.service" ]]; then
      run "install -m 0644 '$REPO_ROOT/systemd/ollama.service' '$SYSTEMD_USER_DIR/ollama.service'"
    else
      # servicio mínimo
      run "bash -c 'cat >\''$SYSTEMD_USER_DIR/ollama.service'\'' <<"UNIT"\n[Unit]\nDescription=Ollama (user)\nAfter=network.target\n\n[Service]\nExecStart=ollama serve\nRestart=on-failure\nEnvironment=OLLAMA_HOST=127.0.0.1:11434\n\n[Install]\nWantedBy=default.target\nUNIT\n'"
    fi
    # Si se ejecutó diagnóstico, intenta habilitar linger del usuario (ya hecho arriba) y mostrar info de systemd
    if [[ "$ARCH_DIAG" = 1 ]]; then
      run "systemctl --user --version || true"
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

# Espera breve a que Ollama responda
if exists curl; then
  for i in {1..20}; do
    if curl -fsS "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
fi

# Restaurar backup si se indicó
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
elif [[ -f "$SRC_DIR/state/config.json" ]]; then
  run "install -m 0644 '$SRC_DIR/state/config.json' '$PIPER_STATE_DIR/config.json'"
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

# Comprobaciones finales
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

# Mostrar configuración
run "'$PIPER_WRAPPER' config --show || true"

say "\nInstalación finalizada. Abre una nueva terminal o ejecuta: source ~/.bashrc (o ~/.zshrc) para refrescar PATH."
