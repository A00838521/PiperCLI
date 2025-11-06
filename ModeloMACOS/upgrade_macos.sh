#!/usr/bin/env bash
# Upgrade de Piper CLI para macOS (ModeloMACOS)
# - Actualiza fuentes y wrapper sin reinstalar modelos
# - Lista modelos instalados
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[ERROR] Este upgrade es solo para macOS" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    *) shift ;;
  esac
done

say(){ echo -e "$*"; }
run(){ if [[ "$DRY_RUN" = 1 ]]; then echo "+ $*"; else eval "$*"; fi }

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_HOME="$HOME/.local/bin"
PIPER_HOME="$DATA_HOME/piper-cli"
PIPER_SRC_DIR="$PIPER_HOME/src"
PIPER_WRAPPER="$BIN_HOME/piper"

say "\n== Piper Upgrade (macOS) ==\n"
run "mkdir -p '$PIPER_SRC_DIR' '$BIN_HOME' '$PIPER_HOME/logs'"
run "cp -r '$REPO_ROOT/src/'* '$PIPER_SRC_DIR/'"

if [[ ! -x "$PIPER_WRAPPER" ]]; then
  cat > "$PIPER_WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PY=\${PYTHON:-python3}
SRC_DIR="$PIPER_HOME/src"
export PYTHONPATH="\$SRC_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\$PY" "$PIPER_HOME/src/piper_cli.py" "\$@"
EOF
  run "chmod +x '$PIPER_WRAPPER'"
fi

if command -v ollama >/dev/null 2>&1; then
  say "\nModelos instalados (ollama list):"
  if ollama list 2>/dev/null; then :; else
    say "(Fallback API tags)"
    curl -fsS http://127.0.0.1:11434/api/tags || true
  fi
else
  say "[INFO] Ollama no está en PATH"
fi

say "\nUpgrade finalizado."
