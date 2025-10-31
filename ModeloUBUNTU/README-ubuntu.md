# PiperCLI — ModeloUBUNTU (Ubuntu/Debian)

Scripts de instalación y desinstalación para Ubuntu/Debian, análogos a `ModeloMACOS` y `ModeloARCH`.

## Archivos
- `install_ubuntu.sh`: instala Piper CLI bajo `~/.local/share/piper-cli`, crea `~/.local/bin/piper`, configura Ollama con el instalador oficial (usa apt en Ubuntu/Debian) y prepara systemd de usuario.
- `uninstall_ubuntu.sh`: desinstala Piper CLI y, opcionalmente, detiene el servicio de Ollama y borra estado.

## Uso rápido
```bash
# Instalar
bash ModeloUBUNTU/install_ubuntu.sh

# Desinstalar (deteniendo servicio y borrando estado)
bash ModeloUBUNTU/uninstall_ubuntu.sh --stop-service
```

## Opciones de install_ubuntu.sh
- `--no-systemd`: no configura systemd de usuario, usa fallback con `nohup`.
- `--ensure-models LISTA`: predescarga modelos con Ollama, separados por comas.
- `--restore TAR`: restaura un backup generado por `backup_state.sh`.
- `--with-config PATH`: usa un `config.json` específico.
- `--dry-run`: muestra las acciones sin ejecutarlas.
- `--ubuntu-diag`: ejecuta diagnósticos y preparación con sudo usando apt (curl, git, python3, systemd; linger; info del sistema).
- `--use-apt`: preferencia por apt para instalar Ollama (el script oficial ya usa apt en Ubuntu/Debian).

## Notas
- Abre una nueva terminal tras la instalación (o `source ~/.bashrc`/`~/.zshrc`) para que `~/.local/bin` entre en `PATH`.
- Si `systemctl --user` no está disponible, el instalador lanza `ollama serve` en background como fallback.
