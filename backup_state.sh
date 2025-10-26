#!/usr/bin/env bash
# Crea un backup del estado de Piper (config y metadatos de modelos) para restaurar fácilmente.
set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
PIPER_STATE_DIR="$DATA_HOME/piper"
TS=$(date +%Y%m%d-%H%M%S)
OUT="${1:-$HOME/piper-backup-$TS}.tar.gz"
TMPDIR="$(mktemp -d)"
mkdir -p "$TMPDIR/.local/share/piper"

# Copiar config.json si existe
if [[ -f "$PIPER_STATE_DIR/config.json" ]]; then
  cp -f "$PIPER_STATE_DIR/config.json" "$TMPDIR/.local/share/piper/config.json"
fi

# Guardar lista de modelos disponibles (si ollama existe)
if command -v ollama >/dev/null 2>&1; then
  ollama list > "$TMPDIR/ollama-models.txt" || true
fi

# Generar tarball
( cd "$TMPDIR" && tar -czf "$OUT" . )
echo "[OK] Backup creado: $OUT"
echo "Para restaurar en otra máquina, ejecuta:"
echo "  bash install.sh --restore '$OUT'"
