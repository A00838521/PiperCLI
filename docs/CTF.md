# Piper CLI — Modo CTF (profesional)

Advertencia y ética:
- Este modo está pensado para CTFs, laboratorios y entornos controlados con autorización explícita.
- No lo uses contra sistemas de terceros sin permiso. Piper añade salvaguardas (clave CTF, confirmaciones), pero la responsabilidad es tuya.

Contenido:
- Seguridad y acceso
- Flujo de trabajo de equipo (clave por equipo)
- Subcomandos CTF y ejemplos
- Reportes Markdown (--report)
- Herramientas soportadas y recomendaciones
- Buenas prácticas y límites

---

## 1. Seguridad y acceso

Clave CTF (requerida para usar cualquier subcomando CTF):
- Define/actualiza la clave en tu máquina:
  piper ctf set-key
- Borra la clave (revoca acceso local):
  piper ctf unset-key
- Estado y detección de herramientas:
  piper ctf status

Uso de la clave:
- Si no pasas --key, Piper te pedirá la clave mediante un prompt seguro o tomará PIPER_CTF_KEY del entorno.
- Internamente se almacena un derivado seguro (PBKDF2-SHA256 con salt e iteraciones); no se guarda la clave en texto plano.

API key del servidor local (opcional, para integraciones):
- Protege el endpoint HTTP /ask con una API key propia:
  piper config --set-server-api-key "mi_api_key"
- Para quitarla:
  piper config --unset-server-api-key
- El servidor exige X-API-Key o ?key= cuando está configurada.

## 2. Flujo de trabajo de equipo (misma clave)

- Acordad una clave por equipo y cada integrante ejecuta piper ctf set-key e introduce la misma clave.
- Para rotarla: cada integrante ejecuta piper ctf unset-key seguido de piper ctf set-key con la nueva clave.
- Puedes exportar PIPER_CTF_KEY para evitar prompts interactivos:
  export PIPER_CTF_KEY="clave_equipo"

## 3. Subcomandos CTF y ejemplos

Nota general:
- Muchos subcomandos llaman a utilidades del sistema si están instaladas (sqlmap, gobuster, nmap, etc.). Piper no instala estas herramientas por ti.
- Usa piper ctf status para ver qué está disponible en tu PATH.

3.1 Recon web rápido
- Objetivo: fingerprinting, puertos/servicios, directorios, checks básicos y prueba ligera de inyección SQL.
- Ejemplo:
  piper ctf web --target https://victima.ctf --report recon_web.md
- Flags:
  --wordlist: ruta a wordlist para gobuster
  --limit: tiempo aproximado por herramienta (segundos)
  --report: guarda un reporte Markdown en la carpeta actual (ruta relativa segura)

3.2 OSINT de dominio
- Objetivo: subdominios y probing HTTP pasivo/rápido.
- Ejemplo:
  piper ctf osint --domain example.com --report osint.md
- Flags:
  --max: límite de líneas por herramienta en el reporte

3.3 Análisis estático de carpeta (code)
- Busca patrones de flags, base64 sospechoso, y resume strings/binwalk de binarios.
- Ejemplo:
  piper ctf code --path ./artefactos --report analisis_code.md

3.4 Reverse básico (binarios/archivos)
- Inspección con file, exiftool, strings, binwalk, y rabin2 si está disponible.
- Ejemplo:
  piper ctf reverse --file ./binario --report reverse.md

3.5 Cripto/encodings
- Intenta hex, base64/32/85, rot13 y César; si está ciphey, ofrece análisis adicional.
- Ejemplos:
  piper ctf crypto --text "SGVsbG8gZmxhZw=="
  piper ctf crypto --file ./misterio.txt

3.6 Probe SSTI (GET no destructivo)
- Prueba cargas seguras para motores comunes (Jinja2/Django/Twig/ERB) buscando evaluación 7*7=49.
- Ejemplo:
  piper ctf probe --url "https://victima/path?name=VAL" --param name

3.7 Credenciales controladas (hydra)
- Requiere confirmación legal explícita; pensado para laboratorios y sólo servicios soportados (ssh/ftp).
- Ejemplo:
  piper ctf creds --host 10.10.10.10 --service ssh \
    --users users.txt --passwords passwords.txt --threads 4 --legal

## 4. Reportes Markdown (--report)

- Los subcomandos web, osint, code y reverse permiten --report para generar un archivo Markdown con un resumen de salidas.
- Piper recorta salidas largas y añade cabeceras por herramienta para que el reporte sea legible.
- La ruta debe ser relativa y se valida para evitar escribir fuera de la carpeta actual.
- Ejemplo: recon_web.md, osint.md, analisis_code.md, reverse.md

## 5. Herramientas soportadas (detección automática)

- Recon/web: whatweb, curl, nmap, gobuster, nikto, sqlmap
- OSINT: subfinder, amass, assetfinder, httpx
- Reverse/análisis: file, exiftool, strings, binwalk, rabin2 (radare2)
- Cripto/encodings: ciphey (opcional)
- Credenciales: hydra (con --legal)

Recomendaciones de instalación (Linux/macOS):
- Homebrew (macOS): brew install nmap gobuster nikto sqlmap whatweb ffuf binwalk radare2 exiftool hydra ciphey httpx amass
- Linux (deb/apt, pacman, etc.): consulta paquetes equivalentes o proyectos oficiales.

## 6. Buenas prácticas y límites

- No destructivo por defecto: Piper usa opciones conservadoras (por ejemplo, sqlmap con level/risk bajos y crawl mínimo).
- Respeta reglas del evento/CTF y objetivos permitidos.
- Versiona tus reportes y comparte con el equipo; evita pegar salidas completas en chat.
- Considera usar un proxy (Burp Suite CE) cuando el contexto lo permita; Piper no lo integra para respetar límites.

## 7. Referencia rápida

- Definir clave CTF (equipo):
  piper ctf set-key
- Estado:
  piper ctf status
- Recon web:
  piper ctf web --target https://host --report recon_web.md
- OSINT:
  piper ctf osint --domain example.com --report osint.md
- Carpeta:
  piper ctf code --path ./folder --report analisis_code.md
- Reverse:
  piper ctf reverse --file ./bin --report reverse.md
- Crypto:
  piper ctf crypto --text "SGV..."  |  --file ./misterio.txt
- Probe SSTI:
  piper ctf probe --url "https://h/?p=VAL" --param p
- Credenciales:
  piper ctf creds --host 10.10.10.10 --service ssh --users u.txt --passwords p.txt --legal

---

Hecho con Piper CLI. Mantén esto privado para tu equipo si el CTF lo requiere.
