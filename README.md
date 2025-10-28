# Piper CLI

Asistente local de terminal que convierte prompts en proyectos y respuestas útiles, con integración a Ollama, opciones de investigación web y TTS opcional. Todo corre en tu equipo.

## Qué incluye

- Asistente (`piper assist`) con tres modos:
   - Respuesta guiada (pregunta/resultado JSON interno) para aclarar intenciones.
   - Modo libre (`--freeform`) para respuestas de texto directo.
   - Con investigación web (`--web`): busca y resume sitios, usa sus ideas como contexto sin copiar código.

- Generación de proyectos (`piper project`) con notas de IA, archivos sugeridos y verificación rápida (sintaxis/pruebas básicas).
- Investigación web independiente (`piper research --url ...`).
- Control del servicio Ollama (`piper on`/`piper off`).
- Guardas de seguridad al escribir archivos: validación estricta de rutas, límites de tamaño por lote y por archivo, y sanitización de contenido generado.
- UX con banner de inicio, mayordomo ASCII y fases con tiempos estimados.

## Instalación rápida

```bash
bash install.sh
```

El instalador coloca un wrapper en `~/.local/bin/piper` para invocarlo desde cualquier carpeta y prepara los archivos en `~/.local/share/piper-cli`.

Asegura el PATH (zsh):

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Inicia/detén Ollama:

```bash
piper on
piper off
```

## Uso básico

- Asistente natural (silencioso):

```bash
piper "Explica brevemente qué hace Piper" --no-tts
```

- Modo libre tipo chat:

```bash
piper assist "Genera un plan de pruebas para una API REST" --freeform --no-tts
```

- Investigación web como contexto (sin copiar código):

```bash
piper assist "Compara librerías de scraping en Python" --web --no-tts
```

Parámetros web y tiempos:

- `--web-max N`: máximo de sitios a considerar (por defecto 5).
- `--web-timeout S`: timeout por solicitud web en segundos (por defecto 15s).
- `--gen-estimate S`: tiempo estimado mostrado para la fase de generación.
- Guardar salida en un archivo (y anexar):

```bash
piper assist "Resume https://fastapi.tiangolo.com/" --web --save notas.md
piper assist "Añade comparativa con Flask" --freeform --save notas.md --append
```

- Crear proyecto con IA y verificación rápida:

```bash
piper project "API FastAPI con endpoint /salud" --ai --ai-files --auto-apply-notes --smoke-run
```

## Pruebas rápidas

- Verificación básica de un proyecto (sintaxis/pruebas):

```bash
piper fix --dir .
```

- Smoke run tras crear un proyecto (intento de ejecución breve):

```bash
piper project "API FastAPI con /salud" --ai --ai-files --smoke-run
```

Si tu proyecto ya existe, también puedes forzar un smoke run manual ejecutando el entrypoint principal (por ejemplo, `python main.py`, `node index.js`, `go run main.go`).

## Configuración

Ver/ajustar límites persistentes:

```bash
piper config --show
piper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python
```

Variables útiles:

- `PIPER_OLLAMA_MODEL`: modelo por defecto para IA.
- `OLLAMA_HOST`: host de Ollama (por defecto `http://127.0.0.1:11434`).

## Flags clave (cómo funciona cada una)

### Assist

- `--no-tts`: desactiva el texto a voz al responder.
   - Ej: `piper "Qué es Piper" --no-tts`

- `--freeform`: modo estilo chat (texto directo, sin JSON interno).
   - Ej: `piper assist "Plan de pruebas" --freeform`

- `--fast`: fuerza un modelo ligero para esta ejecución (`phi3:mini`).
   - Ej: `piper assist "Resume un artículo" --freeform --fast`

- `--web`: usa investigación web como contexto (no copia código, sólo ideas/temas).
   - Ej: `piper assist "Compara frameworks de scraping" --web`

- `--web-max N`: límite de sitios a considerar en la investigación (por defecto 5).
   - Ej: `piper assist "frameworks en Python" --web --web-max 3`

- `--web-timeout S`: timeout por solicitud web en segundos (por defecto 15s).
   - Ej: `piper assist "tendencias web" --web --web-timeout 10`

- `--gen-estimate S`: tiempo estimado mostrado en la fase de generación (sólo UX de progreso).
   - Ej: `piper assist "explica Redis" --freeform --gen-estimate 12`

- `--save PATH`: guarda la salida en un archivo relativo (validación estricta de ruta).
   - Ej: `piper assist "Resumen de X" --freeform --save notas.md`

- `--append`: anexa al archivo indicado en `--save` en lugar de sobrescribir.
   - Ej: `piper assist "Agrega pros y contras" --freeform --save notas.md --append`

### Project

- `--ai` / `--no-ai`: activa/desactiva generación de notas de IA (`AI_NOTES.md`).
- `--ai-files` / `--no-ai-files`: activa/desactiva creación de archivos propuestos por IA.
- `--auto-apply-notes` / `--no-auto-apply-notes`: aplicar automáticamente los archivos sugeridos desde las notas.
- `--max-files N`: limita el número de archivos IA por fase.
- `--research-url URL` (repetible): agrega URL(s) para investigación y genera `RESEARCH_NOTES.md`.
- `--research-merge`: anexa la investigación a `AI_NOTES.md` si existe.
- `--smoke-run` / `--no-smoke-run`: habilita/deshabilita intento de ejecución breve tras crear.
- `--smoke-timeout S`: timeout del smoke run en segundos (por defecto 5).
- `-y`/`--yes` y `--ask`: controlan si se pregunta antes de escribir archivos IA.
- `--max-ai-bytes BYTES` y `--max-ai-file-bytes BYTES`: límites de tamaño de escritura por IA.
- `--show-diff`: muestra diffs antes de escribir archivos IA.

Ejemplo completo:

```bash
piper project "API FastAPI con /salud" \
  --ai --ai-files --auto-apply-notes \
  --research-url https://fastapi.tiangolo.com/ --research-merge \
  --max-files 8 --show-diff --smoke-run --smoke-timeout 8
```

### Research

- `--url URL` (repetible): páginas a investigar.
- `--merge`: anexa a `AI_NOTES.md` si existe.
- `--dir DIR`: dónde guardar `RESEARCH_NOTES.md` (por defecto `cwd`).

## Seguridad y límites

- Validación estricta de rutas para todo archivo escrito por IA (sólo rutas relativas seguras dentro del proyecto).
- Límites de tamaño totales y por archivo para evitar volúmenes inesperados.
- Sanitización de texto generado (remueve fences/backticks; evita binarios aparentes).
- Investigación web sin incluir bloques de código de terceros; se enfocan ideas y temas.

## Desinstalación

```bash
bash uninstall.sh
```

Esto elimina el wrapper y los archivos de Piper CLI bajo `~/.local/share/piper-cli`.

## Notas de modelos

- Piper funciona con Ollama. Por defecto intenta usar `mistral:7b-instruct`; `--fast` fuerza `phi3:mini` por ejecución.

## Estructura del repo

- `src/`: código fuente del CLI
- `install.sh` / `uninstall.sh`: instalación y desinstalación de usuario
- `state/`: configuración persistente
- `systemd/`: unidad de ejemplo para servicios (Linux), en macOS se usa brew/launchctl

Para instrucciones específicas de macOS, consulta `README-macos.txt`.
