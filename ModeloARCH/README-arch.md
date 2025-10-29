# PiperCLI — ModeloARCH (Linux)

Este modelo contiene los scripts de instalación y desinstalación para Linux, organizados de forma análoga a `ModeloMACOS`.

## Archivos
- `install_arch.sh`: instala Piper CLI bajo `~/.local/share/piper-cli`, crea el wrapper `~/.local/bin/piper`, instala y levanta Ollama (systemd de usuario si está disponible) y copia `state/config.json` por defecto.
- `uninstall_arch.sh`: desinstala Piper CLI y, opcionalmente, detiene el servicio de Ollama y borra el estado.

El instalador detecta el archivo `systemd/ollama.service` en la raíz del repositorio y lo instala bajo `~/.config/systemd/user/`.

## Uso rápido

```bash
# Instalar
bash ModeloARCH/install_arch.sh

# Desinstalar (deteniendo servicio y borrando estado)
bash ModeloARCH/uninstall_arch.sh --stop-service
```

### Opciones de install_arch.sh
- `--no-systemd`: no configura systemd de usuario, usa un fallback con `nohup`.
- `--ensure-models LISTA`: modelos a predescargar con Ollama, separados por comas.
- `--restore TAR`: restaura un backup generado por `backup_state.sh`.
- `--with-config PATH`: usa un `config.json` específico.
- `--dry-run`: muestra las acciones sin ejecutarlas.
- `--arch-diag`: ejecuta diagnósticos y preparación en Arch usando sudo (pacman, linger, etc.).
- `--use-pacman`: intenta instalar `ollama` vía pacman antes de usar el instalador oficial.

### Notas
- Abre una nueva terminal tras la instalación (o `source ~/.bashrc`/`~/.zshrc`) para que `~/.local/bin` entre en `PATH`.
- Si `systemctl --user` no está disponible, el instalador lanza `ollama serve` en background (fallback).
