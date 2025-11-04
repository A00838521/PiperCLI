# Piper CLI para Windows

Asistente local de terminal que convierte prompts en proyectos y respuestas útiles con Ollama. Todo corre en tu máquina.

## Requisitos

- Windows 10/11
- Python 3.10+ accesible como `python`
- [Ollama](https://ollama.com) instalado y accesible en `http://127.0.0.1:11434` (el instalador puede intentar instalarlo con winget)

## Instalación rápida

```powershell
# Ejecuta en PowerShell desde la carpeta del repositorio
powershell -ExecutionPolicy Bypass -File .\ModeloWINDOWS\install_windows.ps1
```

El instalador:
- Copia Piper a `%USERPROFILE%\.local\share\piper-cli\src`.
- Crea el wrapper `piper.cmd` en `%USERPROFILE%\.local\bin`.
- Intenta instalar Ollama con `winget` (o `choco`) si no está presente y arranca `ollama serve` en background.
- Aplica configuración por defecto y (opcional) predescarga modelos (`mistral:7b-instruct`, `phi3:mini`).

Asegúrate de que `%USERPROFILE%\.local\bin` esté en tu PATH. El script intenta añadirlo; abre una nueva consola para que surta efecto.

## Uso básico

```powershell
piper "Explica qué es Piper CLI" --no-tts
piper assist "Compara librerías de scraping" --web --no-tts
piper on     # intenta iniciar Ollama
piper off    # intenta detener Ollama
```

## Configuración

```powershell
piper config --show
piper config --set-max-ai-bytes 83886080 --set-max-ai-file-bytes 8388608 --enable-smoke-python
```

Variables útiles:
- `PIPER_OLLAMA_MODEL`: modelo por defecto (ej. `mistral:7b-instruct`).
- `OLLAMA_HOST`: host de Ollama (por defecto `http://127.0.0.1:11434`).

## Desinstalación

```powershell
powershell -ExecutionPolicy Bypass -File .\ModeloWINDOWS\uninstall_windows.ps1
# Conserva el estado (config.json) si quieres
powershell -ExecutionPolicy Bypass -File .\ModeloWINDOWS\uninstall_windows.ps1 -KeepState
```

Esto elimina el wrapper y los archivos bajo `%USERPROFILE%\.local\share\piper-cli`. Con `-KeepState` mantienes `%USERPROFILE%\.local\share\piper`.

## Solución de problemas

- PATH no actualizado: abre una nueva consola o agrega manualmente `%USERPROFILE%\.local\bin` a tu PATH de usuario.
- Ollama no instalado: si no tienes `winget`/`choco`, instala Ollama desde https://ollama.com/download y luego ejecuta `piper on`.
- Servicio no responde: prueba `piper off` y luego `piper on`. Verifica `http://127.0.0.1:11434/api/tags`.
- TTS: en Windows no se instala TTS automáticamente; `--no-tts` silencia la respuesta si no quieres audio.

## Notas

- Las rutas de logs/estado se alinean con Linux/macOS (`%USERPROFILE%\.local\share\piper-cli\logs`, `%USERPROFILE%\.local\share\piper`).
- `piper on/off` usa métodos nativos de Windows si no hay servicio registrado (arranque/parada por proceso).
