#!/usr/bin/env bash
# Bootstrap para reinstalar Piper en una máquina nueva con un solo archivo.
# Edita REPO_URL con tu repositorio (o expórtalo antes de ejecutar).
set -euo pipefail

REPO_URL="${REPO_URL:-}"   # ej: https://github.com/<usuario>/<repo>.git
BRANCH="${BRANCH:-main}"
BACKUP_TAR="${BACKUP_TAR:-}" # opcional: ruta a piper-backup-*.tar.gz

if [[ -z "$REPO_URL" ]]; then
  echo "[ERROR] Debes exportar REPO_URL con la URL del repo que contiene piper-cli/"
  echo "Ejemplo:"
  echo "  export REPO_URL=https://github.com/<usuario>/<repo>.git"
  echo "  curl -fsSLO https://raw.githubusercontent.com/<usuario>/<repo>/main/piper-cli/bootstrap.sh && bash bootstrap.sh"
  exit 2
fi

need() { command -v "$1" >/dev/null 2>&1; }

if ! need git; then echo "[ERROR] git no está instalado"; exit 1; fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[INFO] Clonando $REPO_URL (branch $BRANCH) ..."
 git clone --depth=1 -b "$BRANCH" "$REPO_URL" "$TMP/repo"
cd "$TMP/repo/piper-cli"

if [[ -n "$BACKUP_TAR" ]]; then
  bash install.sh --from-git "$REPO_URL" --branch "$BRANCH" --restore "$BACKUP_TAR"
else
  bash install.sh --from-git "$REPO_URL" --branch "$BRANCH"
fi

echo "[OK] Bootstrap completado. Abre una nueva terminal y prueba 'piper config --show'"
