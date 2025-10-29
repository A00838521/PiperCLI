# Piper CLI

Asistente local de terminal que convierte prompts en proyectos y respuestas útiles, con integración a Ollama, investigación web opcional y TTS. Todo corre en tu equipo.

## Qué incluye
- Asistente (`piper assist`):
  - Respuesta guiada (formato JSON interno) para aclarar intenciones.
  - Modo libre (`--freeform`) para respuesta de texto directa.
  - Con investigación web (`--web`): busca y resume sitios, usa ideas como contexto (sin copiar código).
- Generación de proyectos (`piper project`): notas de IA, archivos sugeridos y verificación rápida (sintaxis/pruebas básicas).
- Investigación web independiente (`piper research --url ...`).
- Control de servicio Ollama (`piper on` / `piper off`).
- Guardas de seguridad al escribir archivos (validación de rutas, límites de tamaño, sanitización de contenido IA).

## Instalación

### Linux (ModeloARCH)
- Instalador principal (delegado):

```bash
bash install.sh
# equivalente a:
bash ModeloARCH/install_arch.sh
```

- El instalador crea `~/.local/bin/piper` y prepara `~/.local/share/piper-cli`.
- Asegura PATH (bash/zsh): añade `~/.local/bin` a tu rc (`~/.bashrc` o `~/.zshrc`).

Opciones útiles en Linux:
- `--no-systemd`: no configura servicio de usuario, usa fallback con `nohup`.
- `--ensure-models lista`: predescarga modelos (p. ej. `mistral:7b-instruct,phi3:mini`).
- `--restore TAR`: restaura backup generado por `backup_state.sh` (si lo conservaste).
- `--with-config PATH`: usa un `config.json` específico.
- `--arch-diag`: (Arch) ejecuta diagnósticos/preparación con sudo (pacman, linger, etc.).
- `--use-pacman`: (Arch) intenta instalar `ollama` vía pacman antes de usar el instalador oficial.

### macOS (ModeloMACOS)

```bash
bash ModeloMACOS/install_macos.sh
```

- Usa Homebrew para instalar dependencias y `ollama`.
- Inicia Ollama con `brew services` o crea un LaunchAgent de usuario.

## Desinstalación

- Linux:
```bash
bash uninstall.sh           # o bash ModeloARCH/uninstall_arch.sh
bash ModeloARCH/uninstall_arch.sh --stop-service   # detiene servicio y limpia más a fondo
```

- macOS:
```bash
bash ModeloMACOS/uninstall_macos.sh
```

## Uso básico

- Asistente (silencioso):
```bash
piper "Explica brevemente qué hace Piper" --no-tts
```

- Modo libre tipo chat:
```bash
piper assist "Genera un plan de pruebas para una API REST" --freeform --no-tts
```

- Investigación web (sin copiar código):
```bash
piper assist "Compara librerías de scraping en Python" --web --no-tts
```

- Crear proyecto con IA y verificación rápida:
```bash
piper project "API FastAPI con endpoint /salud" --ai --ai-files --auto-apply-notes --smoke-run
```

## Parámetros y configuración
- Web: `--web-max`, `--web-timeout`, `--gen-estimate`.
- Persistentes:
```bash
piper config --show
piper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python
```
- Variables:
  - `PIPER_OLLAMA_MODEL`: modelo por defecto (por ejemplo `mistral:7b-instruct`).
  - `OLLAMA_HOST`: host de Ollama (por defecto `http://127.0.0.1:11434`).

## Seguridad y límites
- Validación estricta de rutas (solo relativas seguras dentro del proyecto).
- Límites de tamaño totales y por archivo para contenido IA.
- Sanitización de texto generado (remueve fences/backticks; evita binarios aparentes).
- Investigación web: se usan ideas/temas; no se copian bloques de código de terceros.

## Estructura del repo
- `src/`: código fuente del CLI (Python).
- `install.sh` / `uninstall.sh`: wrappers de compatibilidad que delegan a ModeloARCH.
- `ModeloARCH/`: scripts Linux (`install_arch.sh`, `uninstall_arch.sh`, README-arch.txt).
- `ModeloMACOS/`: scripts macOS (`install_macos.sh`, `uninstall_macos.sh`).
- `systemd/`: unidad de ejemplo `ollama.service` (usuario) para Linux.
- `state/`: configuración por defecto (`config.json`).

## Notas de modelos
- Piper usa Ollama; por defecto intenta `mistral:7b-instruct`.
- `--fast` fuerza `phi3:mini` para respuestas rápidas.

## Roadmap
- Soporte Windows (futuro): planeado un modelo `ModeloWIN` con instaladores `.ps1` y servicio en segundo plano equivalente.
