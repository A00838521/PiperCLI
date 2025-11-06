# Piper CLI

Asistente local de terminal que convierte prompts en proyectos y respuestas útiles, con integración a Ollama, investigación web opcional y TTS. Todo corre en tu equipo.

## Qué incluye

- Asistente (`piper assist`):

   - Respuestas concisas tipo Copilot (sin bucles de preguntas).
   - Investigación web opcional (`--web`) o automática según el prompt (sin copiar código).
   - Intents locales: fecha/hora, IP (local/pública), OS info, búsqueda de archivos y clima.

- Agente (`piper agent`): planifica y ejecuta comandos con streaming e inteligencia web ante fallos.
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

- Agente (streaming + alternativas filtradas):

```bash
piper agent "Inicializa un proyecto con Vite y React" --yes
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

## Roadmap y nuevas capacidades

- Soporte Windows (futuro): planeado un modelo `ModeloWIN` con instaladores `.ps1` y servicio en segundo plano equivalente.
- Extensión del inspector: análisis semántico más profundo y detección de 'hotspots' de complejidad.
- Caché local de resúmenes web para reducir peticiones repetidas.

## Agent (ejecutor de comandos y generador de código)

Permite describir una tarea en lenguaje natural y que Piper planifique y ejecute comandos shell (con confirmaciones sensibles). Usa tu sistema operativo como contexto y puede investigar en la web.

```bash
piper agent "Crea una carpeta demo y git init" --cwd ~/proyectos --no-tts
```

```sh
piper agent "Inicializa un proyecto React (Vite) y corrélo" --web --background -y --no-tts
```

```md
- Flags de agent:
  - `--cwd DIR`: directorio de trabajo.
  - `--background`: ejecuta con nohup y guarda logs.
  - `-y/--yes`: omite confirmaciones del plan.
  - `--dry-run`: muestra el plan y sale.
  - `--web`, `--web-max`, `--web-timeout`: investigación web contextual.
  - `--model` / `--fast`: elige modelo Ollama.
  - `--no-auto-web-assist`: desactiva asistencia automática en fallos.
  - `--plan-report FILE`: guarda el plan y resultados en Markdown.
  - `--no-auto-code`: desactiva generación de código y tests automáticos (por defecto activada).

```

```yaml
## TTS (texto a voz)
Por defecto, TTS está desactivado. Actívalo sólo si quieres que hable:
- Exporta `PIPER_ENABLE_TTS=1` para habilitar por defecto.
- Usa `--no-tts` para silenciar puntualmente.
```

## Contexto inteligente y generación de código (nuevo)

Piper mantiene un contexto persistente para evitar preguntas repetitivas y optimizar decisiones, y ahora incluye generación de código autónoma (auto-code) con validación sintáctica y tests mínimos.

- Herramientas rastreadas: `git`, `gh` (GitHub CLI), `node`, `npm`, `python3`, `go`.
- Decisiones recordadas: por ejemplo, si aceptaste o rechazaste instalar `git` (`install.git`), o aplicar `AI_NOTES`.
- Historial de ejecuciones: últimos 100 comandos con salida (exit code) y hora.

Comandos útiles:

```bash
piper context --show                 # Ver estado actual (herramientas, decisiones, últimos runs)
piper context --forget install.git   # Olvida una decisión puntual
piper context --clear                # Limpia sólo el contexto (no la configuración)
```

Integración:

- `piper agent` consulta este contexto antes de preguntar por instalaciones; con `-y` instala sin preguntar.
- `piper project` recuerda si aceptar o no aplicar `AI_NOTES.md` cuando no usas `--auto-apply-notes`.

### Asistencia automática ante fallos o comandos desconocidos (nuevo)

`piper agent` ahora te ayuda por defecto cuando:

- El paso incluye un comando que no está en tu PATH: busca rápidamente en la web cómo usarlo e intenta sugerir alternativas (con el modelo) antes de ejecutar.
- Un comando falla: hace una búsqueda con el error, resume 2–3 páginas y pide al modelo alternativas concretas; puedes elegir una y reintentar al momento.

Control:

- Desactiva este comportamiento con `--no-auto-web-assist`.
- Sigue disponible `--web` para añadir contexto web al plan inicial (además de la asistencia automática en fallos).

### Ayuda completa de Piper

Para ver todas las flags y subcomandos con sus opciones detalladas en un solo listado:

```bash
piper -h
# o
piper --help
```

## Modo CTF (nuevo)

Piper incluye un modo CTF protegido por clave con utilidades para recon, OSINT, cripto y reversing. Además añade SSTI probing y ataques de credenciales controlados (hydra) con flag legal.

- Guía completa: docs/CTF.txt
- Ejemplos rápidos:
   - `piper ctf set-key`
   - `piper ctf install --all`
   - `piper ctf web --target https://victima --report recon_web.md`
   - `piper ctf osint --domain example.com --report osint.md`
   - `piper ctf reverse --file binario --report reverse.md`
   - `piper ctf crypto --data "SGVsbG8="`
   - `piper ctf probe --url https://victima/ssti?x=`
   - `piper ctf creds --service ssh --host 10.10.10.10 --legal`
   - `piper ctf code --file script.py --report code_review.md`

## Inspector de proyecto (nuevo)
Analiza una carpeta (por defecto, el directorio actual) y genera `Inspector-Report.md` con:
- Resumen IA del propósito y capacidades del proyecto (modelo Ollama).
- Conteo por extensión de archivos.
- Funciones e imports en archivos Python.
- Interconexiones entre módulos locales.

Opciones:
- `--cwd DIR`: inspeccionar otra carpeta.
- `--max-files N`: límite de archivos (default 500).
- `--max-lines N`: líneas por archivo (default 2000).
- Ejemplo:
```bash
piper inspect
piper inspect --cwd src --max-files 80 --max-lines 1200
```
