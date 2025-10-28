# Piper CLI para macOS

Asistente local de terminal que convierte prompts en proyectos y respuestas útiles, con integración a Ollama y TTS opcional. Todo corre en tu máquina.

## Requisitos

- macOS 12+ (Intel o Apple Silicon)
- Python 3.10+ disponible como `python3`
- [Ollama](https://ollama.com) instalado y accesible en `http://127.0.0.1:11434` (el instalador puede iniciarlo por ti)
- Homebrew (opcional, recomendado para gestionar el servicio de Ollama)

## Instalación rápida

```bash
bash install.sh
```

El instalador:

- Copia Piper a `~/.local/share/piper-cli/src` y crea el wrapper `~/.local/bin/piper`.
- Asegura modelos por defecto en Ollama (por ejemplo, `mistral:7b-instruct`, `phi3:mini`).
- Intenta iniciar Ollama como servicio (brew services) y aplica un fallback con `launchctl`/`nohup` si es necesario.

Asegura que `~/.local/bin` esté en tu PATH (zsh):

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verifica que arranca y responde:

```bash
piper on     # inicia el servicio de Ollama (brew/launchctl)
piper off    # lo detiene
```

## Uso rápido

- Asistente natural con TTS desactivado:

```bash
piper "Explica qué es Piper CLI" --no-tts
```

- Modo libre (estilo chat):

```bash
piper assist "Redacta un README corto para un microservicio" --freeform --no-tts
```

- Con investigación web (sin pegar código; usa ideas de las páginas):

```bash
piper assist "Dime 3 sitios para texturas 3D y compáralos" --web --no-tts
```

Parámetros web y tiempos (nuevos):

- `--web-max N` controla cuántos sitios usa (por defecto 5).
- `--web-timeout S` fija el timeout por solicitud (por defecto 15s).
- `--gen-estimate S` ajusta el tiempo estimado mostrado para la fase de generación.

Ejemplo:

```bash
piper assist "frameworks para APIs en Python" --web --web-max 4 --web-timeout 12 --gen-estimate 18 --no-tts
```

- Guardar en archivo (con anexado opcional):

```bash
piper assist "Resume https://fastapi.tiangolo.com/" --web --save notas.md
piper assist "Agrega pros y contras" --freeform --save notas.md --append
```

- Crear un proyecto inicial con IA y verificación rápida:

```bash
piper project "API FastAPI con /salud" --ai --ai-files --auto-apply-notes --smoke-run
```

## Configuración

Ver y ajustar límites persistentes:

```bash
piper config --show
piper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python
```

Variables útiles:

- `PIPER_OLLAMA_MODEL`: modelo por defecto.
- `OLLAMA_HOST`: host de Ollama (por defecto `http://127.0.0.1:11434`).

## Desinstalación

```bash
bash uninstall.sh
```

Esto elimina el wrapper y los archivos bajo `~/.local/share/piper-cli`. Puedes mantener tu estado (config) si lo deseas; el script te lo indicará.

## Solución de problemas

- Brew no instalado: Piper usará `launchctl` o `nohup` para arrancar Ollama.
- Servicio no responde: prueba `piper off` y luego `piper on`. Revisa logs en `~/.local/share/piper-cli/logs/`.
- PATH no aplicado: abre una nueva terminal o ejecuta `source ~/.zshrc`.

## Nota sobre TTS

Piper CLI puede hablar si tienes un TTS local (por ejemplo, Piper TTS u otras voces). Usa `--no-tts` para silenciar. En macOS también puedes usar `piper say "Texto..."` si configuraste TTS compatible.
