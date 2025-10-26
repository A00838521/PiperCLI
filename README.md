# Piper CLI (instalador en Linux, usuario)

Asistente local tipo Copilot que convierte prompts en proyectos, con integración a Ollama, TTS opcional y verificación rápida.

## Instalación rápida (local)

```bash
bash install.sh
```

Desde Git (parametrizable):

```bash
bash install.sh --from-git https://github.com/<usuario>/<repo>.git --branch main
```

El instalador:

- Copia Piper a `~/.local/share/piper-cli/src` y crea `~/.local/bin/piper`.
- Instala y arranca Ollama como servicio de usuario (o fallback sin systemd).
- Restaura configuración si existe `state/config.json` o si pasas `--with-config` / `--restore`.
- Aplica defaults generosos: 80MB total, 8MB por archivo; smoke-run Python activado.
- (Opcional) Pre-descarga modelos: `--ensure-models mistral:7b-instruct,phi3:mini` (por defecto ya lo usa).

Asegúrate de tener `~/.local/bin` en el PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"  # añade a ~/.bashrc o ~/.zshrc
```

## Uso básico

- Asistente rápido:

```bash
piper "Explica brevemente qué hace Piper" --no-tts
```

- Crear proyecto con IA y smoke run:

```bash
piper project "API FastAPI con endpoint /salud" --ai --ai-files --auto-apply-notes --smoke-run
```

- Ver y ajustar configuración persistente:

```bash
piper config --show
piper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python
```

- Investigación web (no copia código; ideas/títulos):

```bash
piper research --url https://fastapi.tiangolo.com/ --url https://flask.palletsprojects.com/
```

## Backup y restauración

Crear backup del estado local (config y lista de modelos):

```bash
bash backup_state.sh
```

Restaurar en otra máquina:

```bash
bash install.sh --restore /ruta/piper-backup-*.tar.gz
```

O pasar una configuración exacta:

```bash
bash install.sh --with-config ./state/config.json
```

## Bootstrap en máquina nueva

Usa el script para clonar y reinstalar con un comando (exporta REPO_URL y opcionalmente BACKUP_TAR):

```bash
export REPO_URL=https://github.com/<usuario>/<repo>.git
export BACKUP_TAR=/ruta/piper-backup-YYYYMMDD-HHMMSS.tar.gz  # opcional
bash bootstrap.sh
```

## Notas de modelos

- Por defecto se asegura `mistral:7b-instruct` y `phi3:mini`.
- Forzar modelo rápido por ejecución: `--fast`.
- Variables:
   - `PIPER_OLLAMA_MODEL`: modelo por defecto.
   - `OLLAMA_HOST`: host de Ollama (por defecto `http://127.0.0.1:11434`).

## Seguridad y límites

- Guardas al escribir archivos de IA: límites de tamaño por lote y por archivo; heurística para evitar binarios.
- Sanitización de contenido generado (sin fences/backticks) y diffs por archivo al aplicar.

## Desinstalación

```bash
systemctl --user disable --now ollama.service 2>/dev/null || true
rm -rf ~/.local/share/piper-cli
rm -f ~/.local/bin/piper
# Config (opcional):
rm -rf ~/.local/share/piper
```


