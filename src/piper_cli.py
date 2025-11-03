#!/usr/bin/env python3
"""
Piper CLI — primer MVP estilo Copilot: de prompt a proyecto.

Comandos:
    project       Crea un proyecto mínimo a partir de un prompt (por defecto)
    assist        Asistente interactivo
    apply-notes   Aplica archivos sugeridos desde AI_NOTES.md
    fix           Revisa sintaxis y prueba proyectos (inicialmente Python)
    say           Reproduce TTS con Piper (si está disponible)

Ejemplos:
    python3 tools/piper_cli.py "Flask hello world con Docker"
    python3 tools/piper_cli.py project --name hola-fastapi "API FastAPI con /salud"
    python3 tools/piper_cli.py say "Listo, proyecto creado"
"""
from __future__ import annotations
import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Tuple
import time
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any
import difflib
import subprocess
import py_compile
import traceback
import shutil
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, quote_plus, unquote
import platform
import socket

try:
    from piper_tts import speak  # noqa: F401
except Exception:
    def speak(_text: str) -> bool:  # type: ignore
        return False
try:
    from piper_memory import get_config, save_config  # noqa: F401
except Exception:
    def get_config():  # type: ignore
        return {}
    def save_config(_cfg):  # type: ignore
        return None

ROOT = Path(__file__).resolve().parent
AI_TOTAL_BYTES_DEFAULT = int(os.environ.get("PIPER_AI_TOTAL_BYTES_DEFAULT", str(20 * 1024 * 1024)))  # 20MB
AI_FILE_BYTES_DEFAULT = int(os.environ.get("PIPER_AI_FILE_BYTES_DEFAULT", str(2 * 1024 * 1024)))    # 2MB


# -------------------- Utilidades --------------------

def slugify(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "piper-proj"


def mkdirp(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_file(path: Path, content: str) -> None:
    mkdirp(path.parent)
    path.write_text(content, encoding="utf-8")


def _maybe_save_output(base: Path, save_path: str | None, content: str, *, append: bool = False) -> None:
    """Si se proporcionó una ruta de guardado, valida y escribe el contenido.
    Usa validación estricta para asegurar que la ruta quede dentro de 'base'.
    """
    if not save_path:
        return
    ok, rel, target = _validate_ai_relpath(base, save_path)
    if not ok or target is None:
        motivo = rel or "inválida"
        print(f"[SKIP] No se guardó salida en '{save_path}' (razón: {motivo})")
        return
    try:
        if append and target.exists():
            with target.open("a", encoding="utf-8") as fh:
                fh.write(("\n" if content and not content.endswith("\n") else "") + content)
        else:
            write_file(target, content)
        print(f"[OK] Salida guardada en {rel}")
    except Exception as e:
        print(f"[ERROR] No se pudo guardar '{rel}': {e}")


# -------------------- UX Mejorada (progreso, ASCII mayordomo) --------------------

def _ascii_butler(lines: list[str]) -> str:
    # Caja ASCII simple sin figura, orientada a resúmenes legibles
    bubble = [f"  | {ln}" for ln in lines]
    width = max([len(s) for s in bubble], default=0)
    top = "  +" + "-" * (width + 2) + "+" if width else ""
    bottom = top
    body = [f"  | {ln.ljust(width)} |" for ln in [b[4:] for b in bubble]] if width else []
    frame = ([top] + body + [bottom]) if width else bubble
    header = ["  PIPER — asistente de proyecto local"]
    return "\n".join(header + frame)


def _ascii_banner() -> str:
    # Banner de arranque global (evitar secuencias ANSI)
    return "\n".join([
        r"",
        r"         ____    ______   ____    ____    ____        ",
        r"        /\  _`\ /\__  _\ /\  _`\ /\  _`\ /\  _`\      ",
        r"        \ \ \L\ \/_/\ \/ \ \ \L\ \ \ \L\_\ \ \L\ \    ",
        r"         \ \ ,__/  \ \ \  \ \ ,__/\ \  _\L\ \ ,  /    ",
        r"          \ \ \/    \_\ \__\ \ \/  \ \ \L\ \ \ \\ \   ",
        r"           \ \_\    /\_____\\ \_\   \ \____/\ \_\ \_\ ",
        r"            \/_/    \/_____/ \/_/    \/___/  \/_/\/ / ",
        r"",
        r" ------------  PIPER — asistente de proyecto local  ------------"
    ])


_PHASE_STACK: list[tuple[str, float, int]] = []  # (name, start_ts, est)

def progress_start(name: str, estimated_seconds: int | None = None) -> None:
    est = int(estimated_seconds or 0)
    _PHASE_STACK.append((name, time.time(), est))
    est_txt = f" ~{est}s" if est else ""
    print(f"⏳ {name}{est_txt}...")


def progress_end() -> None:
    if not _PHASE_STACK:
        return
    name, start, est = _PHASE_STACK.pop()
    dur = time.time() - start
    print(f"✓ {name} — {dur:.1f}s")


def with_progress(name: str, est_seconds: int, func, *args, **kwargs):
    """Ejecuta func(*args, **kwargs) mostrando una fase con tiempo estimado y duración real."""
    try:
        progress_start(name, est_seconds)
        return func(*args, **kwargs)
    finally:
        progress_end()


def _dir_tree(root: Path, *, max_depth: int = 2, max_entries: int = 100) -> list[str]:
    root = root.resolve()
    lines: list[str] = []
    count = 0

    def walk(d: Path, prefix: str, depth: int) -> None:
        nonlocal count
        if depth > max_depth or count >= max_entries:
            return
        try:
            entries = sorted(d.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except Exception:
            return
        for i, p in enumerate(entries):
            if count >= max_entries:
                return
            branch = "└── " if i == len(entries) - 1 else "├── "
            lines.append(prefix + branch + p.name)
            count += 1
            if p.is_dir():
                next_prefix = prefix + ("    " if i == len(entries) - 1 else "│   ")
                walk(p, next_prefix, depth + 1)

    walk(root, "", 0)
    return lines


# -------------------- Entrada interactiva con cancelación q() --------------------

class _UserCanceled(Exception):
    pass


def _ask_input(prompt: str) -> str:
    try:
        s = input(prompt)
    except EOFError:
        raise _UserCanceled()
    if s is None:
        raise _UserCanceled()
    s2 = s.strip()
    if s2.lower() == "q()":
        raise _UserCanceled()
    return s2


# -------------------- Intents locales (fecha de hoy) --------------------

def _normalize_text(s: str) -> str:
    t = (s or "").lower()
    # normalización simple de acentos comunes en español
    t = (t
         .replace("á", "a").replace("é", "e").replace("í", "i")
         .replace("ó", "o").replace("ú", "u").replace("ü", "u")
         .replace("ñ", "n"))
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _is_date_query(s: str) -> bool:
    t = _normalize_text(s)
    patt = [
        "que dia es hoy",
        "que dia es",
        "que fecha es hoy",
        "fecha de hoy",
        "fecha hoy",
        "what day is it",
        "what day is today",
        "today s date",
        "todays date",
        "date today",
    ]
    return any(p in t for p in patt)


def _date_today_text() -> str:
    now = datetime.now()
    dias = ["lunes", "martes", "miercoles", "jueves", "viernes", "sabado", "domingo"]
    meses = [
        "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"
    ]
    dia = dias[now.weekday()]
    mes = meses[now.month - 1]
    return f"Hoy es {dia} {now.day} de {mes} de {now.year}."


def _is_time_query(s: str) -> bool:
    t = _normalize_text(s)
    patt = [
        "que hora es",
        "hora actual",
        "hora local",
        "hora ahora",
        "what time is it",
        "current time",
        "time now",
    ]
    return any(p in t for p in patt)


def _time_now_text() -> str:
    now = datetime.now()
    return now.strftime("La hora local es %H:%M:%S")


def _is_cwd_query(s: str) -> bool:
    t = _normalize_text(s)
    patt = [
        "directorio actual",
        "carpeta actual",
        "donde estoy",
        "ruta actual",
        "current directory",
        "working directory",
        "pwd",
    ]
    return any(p in t for p in patt)


def _cwd_text() -> str:
    try:
        return f"Directorio actual: {Path.cwd()}"
    except Exception:
        return "No pude determinar el directorio actual."


# -------------------- Intents locales (sistema: IP, OS, búsqueda de archivos) --------------------

def _is_ip_query(s: str) -> tuple[bool, str]:
    """Detecta si el usuario pregunta por IP. Devuelve (True, tipo) donde tipo ∈ {"local", "publica", ""}.
    Si no está claro, asume local.
    """
    t = _normalize_text(s)
    if not t:
        return False, ""
    if "ip" not in t:
        return False, ""
    if any(k in t for k in ["publica", "pública", "externa"]):
        return True, "publica"
    return True, "local"


def _get_local_ip() -> str:
    try:
        # Técnica robusta: abrir un socket UDP a una IP pública para conocer la interfaz de salida
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return f"IP local: {ip}"
    except Exception:
        try:
            host = socket.gethostname()
            ip = socket.gethostbyname(host)
            return f"IP local: {ip}"
        except Exception:
            return "No pude determinar la IP local."


def _get_public_ip(timeout: float = 5.0) -> str:
    try:
        # Probar api.ipify.org
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "PiperCLI/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ip = (resp.read().decode("utf-8").strip())
            if ip:
                return f"IP pública: {ip}"
    except Exception:
        pass
    try:
        # Fallback ifconfig.me
        req = urllib.request.Request("https://ifconfig.me/ip", headers={"User-Agent": "PiperCLI/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ip = (resp.read().decode("utf-8").strip())
            if ip:
                return f"IP pública: {ip}"
    except Exception:
        pass
    return "No pude determinar la IP pública (requiere conexión a internet)."


def _is_os_info_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = [
        "sistema operativo", "version de macos", "version macos", "informacion del sistema",
        "os version", "system info", "version del sistema",
    ]
    return any(k in t for k in keys)


def _os_info_text() -> str:
    try:
        sysname = platform.system()
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        py = platform.python_version()
        return f"Sistema: {sysname} {release} ({machine})\nVersión: {version}\nPython: {py}"
    except Exception:
        return "No pude obtener la información del sistema."


def _is_find_file_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = ["donde esta", "dónde está", "ubica archivo", "buscar archivo", "encuentra archivo", "find file", "locate file"]
    return any(k in t for k in keys)


def _extract_filename_term(s: str) -> str | None:
    """Heurística simple para extraer un término de archivo del texto.
    Busca tras 'archivo', 'file', o entre comillas.
    """
    # Entre comillas
    m = re.search(r"['\"]([^'\"]+)['\"]", s)
    if m:
        return m.group(1).strip()
    # Después de la palabra 'archivo' o 'file'
    m = re.search(r"(?:archivo|file)\s+([\w._\-]+)", _normalize_text(s))
    if m:
        return m.group(1).strip()
    # Último recurso: tomar la última palabra con punto (parece nombre de archivo)
    cand = re.findall(r"[\w._\-]+\.[A-Za-z0-9]{1,6}", s)
    if cand:
        return cand[-1]
    return None


def _search_files(term: str, base: Path, *, max_results: int = 20) -> list[Path]:
    base = base.resolve()
    results: list[Path] = []
    try:
        # Si el término incluye separadores, úsalo tal cual; si no, usa rglob sobre nombre
        if "/" in term or "\\" in term:
            p = (base / term).resolve()
            if p.exists():
                results.append(p)
        else:
            # Buscar por nombre exacto o patrón simple
            patts = [term]
            if not any(term.endswith(ext) for ext in (".txt", ".md", ".py", ".json", ".yml", ".yaml")):
                patts.append(f"**/{term}")
            seen: set[Path] = set()
            for patt in patts:
                for p in base.rglob(patt):
                    if p in seen:
                        continue
                    seen.add(p)
                    results.append(p)
                    if len(results) >= max_results:
                        return results
    except Exception:
        pass
    return results


_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def _extract_urls(s: str) -> list[str]:
    return _URL_RE.findall(s or "")


def _wants_web_summary(s: str) -> bool:
    t = _normalize_text(s)
    keys = ["resume", "resumen", "que dice", "que hay", "investiga", "busca", "summary"]
    return any(k in t for k in keys)


def _wants_web_search(s: str) -> bool:
    t = _normalize_text(s)
    keys = [
        "sitios web", "paginas web", "websites", "links", "fuentes",
        "dime", "recomienda", "donde puedo", "donde encontrar", "where can i find",
    ]
    # debe pedir sitios/links y no incluir URLs ya
    return any(k in t for k in keys) and not bool(_extract_urls(s))


# -------------------- Control de servicio Ollama (ON/OFF) --------------------

def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _ollama_logs_dir() -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    piper_home = data_home / "piper-cli"
    mkdirp(piper_home / "logs")
    return piper_home / "logs"


def start_ollama_service() -> tuple[bool, str]:
    try:
        if _is_macos():
            if _exists("brew"):
                proc = subprocess.run(["brew", "services", "start", "ollama"], capture_output=True, text=True)
                ok = proc.returncode == 0
                return ok, (proc.stdout or proc.stderr or "").strip()
            # Fallback launchctl
            plist = Path.home() / "Library" / "LaunchAgents" / "com.piper.ollama.plist"
            if plist.exists():
                proc = subprocess.run(["launchctl", "load", "-w", str(plist)], capture_output=True, text=True)
                return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
            # Último recurso: proceso en background
            log = _ollama_logs_dir() / "ollama.out.log"
            cmd = f"nohup sh -c 'OLLAMA_HOST=127.0.0.1:11434 ollama serve >>\"{log}\" 2>&1' &"
            os.system(cmd)
            return True, "ollama serve lanzado en background (nohup)"
        else:
            # Linux
            if _exists("systemctl"):
                proc = subprocess.run(["systemctl", "--user", "start", "ollama.service"], capture_output=True, text=True)
                if proc.returncode == 0:
                    return True, "systemd user: ollama iniciado"
            # Fallback: lanzar background
            log = _ollama_logs_dir() / "ollama.log"
            cmd = f"nohup sh -c 'OLLAMA_HOST=127.0.0.1:11434 ollama serve >>\"{log}\" 2>&1' &"
            os.system(cmd)
            return True, "ollama serve lanzado en background (nohup)"
    except Exception as e:
        return False, f"Error al iniciar Ollama: {e}"


def stop_ollama_service() -> tuple[bool, str]:
    try:
        if _is_macos():
            if _exists("brew"):
                proc = subprocess.run(["brew", "services", "stop", "ollama"], capture_output=True, text=True)
                # También matar remanentes
                subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
                return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
            plist = Path.home() / "Library" / "LaunchAgents" / "com.piper.ollama.plist"
            if plist.exists():
                subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
            subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
            return True, "ollama detenido"
        else:
            if _exists("systemctl"):
                proc = subprocess.run(["systemctl", "--user", "stop", "ollama.service"], capture_output=True, text=True)
                subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
                return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
            subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
            return True, "ollama detenido"
    except Exception as e:
        return False, f"Error al detener Ollama: {e}"


# -------------------- Ollama integración opcional --------------------

def _ensure_http_scheme(host: str) -> str:
    h = host.strip()
    if not h:
        return "http://127.0.0.1:11434"
    if not (h.startswith("http://") or h.startswith("https://")):
        h = "http://" + h
    return h

def _ollama_host() -> str:
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    host = _ensure_http_scheme(host)
    # Asegurarnos de no duplicar "/api"
    if host.endswith("/api"):
        host = host[: -len("/api")]
    return host

def _get_json(url: str, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return json.loads(body.decode("utf-8"))

def _list_ollama_models(host: str) -> list[str]:
    try:
        obj = _get_json(f"{host}/api/tags")
        models = obj.get("models") or []
        names = []
        for m in models:
            name = m.get("name") or m.get("model")
            if isinstance(name, str):
                names.append(name)
        return names
    except Exception:
        return []

def _pull_ollama_model(host: str, name: str, timeout: float = 900.0) -> bool:
    """Intenta descargar un modelo en el servidor Ollama.
    Retorna True si parece haber terminado sin error. Usa stream=false para respuesta corta.
    """
    try:
        _post_json(f"{host}/api/pull", {"name": name, "stream": False}, timeout=timeout)
        return True
    except Exception:
        return False

def _ensure_model_available(model: str) -> str:
    """Garantiza que el modelo exista en Ollama. Si no está, intenta hacer pull.
    Devuelve el nombre (posiblemente inalterado) para seguir usándolo.
    """
    host = _ollama_host()
    installed = set(_list_ollama_models(host))
    if model in installed:
        return model
    # Intentar pull del solicitado
    ok = _pull_ollama_model(host, model)
    if ok:
        # refrescar lista
        installed = set(_list_ollama_models(host))
        if model in installed:
            return model
    # Heurística de respaldo si el tag específico no existe
    for candidate in ("mistral:7b-instruct", "mistral:latest"):
        if candidate in installed:
            return candidate
    # último intento: hacer pull de un candidato razonable
    for candidate in ("mistral:7b-instruct", "mistral:latest"):
        if _pull_ollama_model(host, candidate):
            installed = set(_list_ollama_models(host))
            if candidate in installed:
                return candidate
    return model

def _resolve_model(requested: str | None) -> str:
    """Elige un modelo válido de Ollama.
    Orden de preferencia:
    1) requested (si existe), 2) $PIPER_OLLAMA_MODEL (si existe), 3) heurística sobre instalados,
    4) fallback fijo 'mistral:7b-instruct'.
    """
    host = _ollama_host()
    installed = _list_ollama_models(host)
    pref = requested or os.environ.get("PIPER_OLLAMA_MODEL")
    if pref and (not installed or pref in installed):
        return pref
    # Heurística: preferir mistral:7b-instruct si está instalado
    for candidate in ("mistral:7b-instruct", "mistral:latest"):
        if candidate in installed:
            return candidate
    # Si hay alguno instalado, tomar el primero
    if installed:
        return installed[0]
    # Fallback final
    return pref or "mistral:7b-instruct"

def _post_json(url: str, payload: dict, timeout: float = 60.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return json.loads(body.decode("utf-8"))


def _extract_json_from_text(text: str) -> Dict[str, Any] | None:
    """Intenta extraer un objeto JSON desde texto que quizá incluya fences ```json ... ```.
    Devuelve dict si logra parsear, o None si falla.
    """
    s = text.strip()
    # Quitar fences tipo ```json ... ```
    if s.startswith("```"):
        # eliminar las primeras 3 tildes y posibles etiquetas como json
        first_newline = s.find("\n")
        if first_newline != -1:
            s = s[first_newline + 1 :]
        if s.endswith("```"):
            s = s[: -3]
        s = s.strip()
    # Intento directo
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # Buscar el primer y último corchete llaves
    try:
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            obj = json.loads(s[start : end + 1])
            if isinstance(obj, dict):
                return obj
    except Exception:
        pass
    return None


def _sanitize_generated_content(text: str) -> str:
    """Limpia contenido generado por la IA que pueda venir envuelto en fences o backticks.
    - Elimina bloques ```lang ... ``` ... ```
    - Si la primera y última línea son solo "`", las elimina
    - Si comienza y termina con un único backtick, lo retira
    - Normaliza saltos de línea y recorta espacios extra al borde
    """
    if text is None:
        return ""
    s = text.replace("\r\n", "\n").replace("\r", "\n")
    s = s.strip()

    # Caso: bloque triple fence
    if s.startswith("```"):
        lines = s.splitlines()
        # quitar primera línea con ```... (posible etiqueta)
        if lines:
            lines = lines[1:]
        # quitar última línea si es ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()

    # Caso: primera y última línea son solo backticks
    lines = s.splitlines()
    if lines and lines[0].strip() == "`" and lines[-1].strip() == "`":
        s = "\n".join(lines[1:-1]).strip()

    # Caso: envuelto en un único backtick al inicio y fin
    if len(s) >= 2 and s.startswith("`") and s.endswith("`"):
        inner = s[1:-1]
        # Evitar recortar si probablemente sea contenido inline sin saltos
        s = inner.strip("\n")

    return s


def ollama_notes(prompt: str, stack: str, model: str) -> str:
    host = _ollama_host()
    user_prompt = (
        "Contexto: Estás operando dentro de Piper CLI (herramienta local de terminal para convertir prompts en proyectos), "
        "no es un producto de Amazon ni Alexa. No confundas ni menciones marcas ajenas, a menos que el usuario lo pida explícitamente.\n\n"
        "Eres un asistente técnico. Con base en el stack y la descripción del usuario, "
        "propón mejoras, pasos siguientes concretos y archivos adicionales sugeridos. "
        "Responde SOLO en Markdown usando los encabezados: \n\n"
        "# Resumen\n\n# Mejoras sugeridas\n\n# Pasos siguientes\n\n# Archivos sugeridos (con rutas)\n\n"
        f"Stack: {stack}\n\nDescripción: {prompt}\n"
    )

    # 1) Intentar /api/generate (no chat)
    gen_url = f"{host}/api/generate"
    gen_payload = {
        "model": model,
        "prompt": user_prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    try:
        obj = _post_json(gen_url, gen_payload)
        txt = (obj.get("response") or "").strip()
        if txt:
            return txt
    except urllib.error.HTTPError as e:
        # 404/405: algunas versiones o despliegues esperan /api/chat (o modelo no encontrado)
        if e.code not in (404, 405):
            raise RuntimeError(f"Ollama error en {gen_url}: {e}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama no accesible en {gen_url}: {e}")

    # 2) Fallback: /api/chat
    chat_url = f"{host}/api/chat"
    chat_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Eres un asistente técnico conciso."},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    try:
        obj = _post_json(chat_url, chat_payload)
        # Respuesta típica: { message: { role: 'assistant', content: '...' }, done: true }
        msg = obj.get("message") or {}
        txt = (msg.get("content") or obj.get("response") or "").strip()
        return txt
    except urllib.error.HTTPError as e:
        # Continuar con compatibilidad OpenAI si tampoco existe /api/chat
        if e.code not in (404, 405):
            raise RuntimeError(f"Ollama error en {chat_url}: {e}")
    except urllib.error.URLError as e:
        # Probar compatibilidad OpenAI /v1
        pass

    # 3) Fallback: OpenAI compatible /v1/chat/completions
    v1_chat_url = f"{host}/v1/chat/completions"
    v1_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Eres un asistente técnico conciso."},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "stream": False,
    }
    try:
        obj = _post_json(v1_chat_url, v1_payload)
        choices = obj.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            txt = (msg.get("content") or "").strip()
            if txt:
                return txt
    except Exception:
        # 4) Último intento: /v1/completions
        v1_comp_url = f"{host}/v1/completions"
        v1_comp_payload = {
            "model": model,
            "prompt": user_prompt,
            "temperature": 0.2,
            "stream": False,
        }
        try:
            obj = _post_json(v1_comp_url, v1_comp_payload)
            choices = obj.get("choices") or []
            if choices:
                txt = (choices[0].get("text") or "").strip()
                if txt:
                    return txt
        except Exception as e2:
            raise RuntimeError(
                "No se pudo llamar a Ollama (probadas rutas /api/generate, /api/chat, /v1/chat/completions, /v1/completions). "
                f"Host: {host}. Error final: {e2}"
            )


def _ollama_chat(messages: List[Dict[str, Any]], model: str) -> str:
    host = _ollama_host()
    # Preferir endpoint OpenAI-compatible
    v1_chat_url = f"{host}/v1/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "stream": False,
    }
    try:
        obj = _post_json(v1_chat_url, payload, timeout=120)
        choices = obj.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            return (msg.get("content") or "").strip()
    except Exception:
        pass
    # Fallback /api/chat
    chat_url = f"{host}/api/chat"
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    obj = _post_json(chat_url, payload, timeout=120)
    msg = obj.get("message") or {}
    return (msg.get("content") or obj.get("response") or "").strip()


def _ollama_chat_json(messages: List[Dict[str, Any]], model: str) -> Dict[str, Any]:
    """Intenta obtener una respuesta estrictamente en JSON.
    1) /v1/chat/completions con response_format json_object (si es compatible)
    2) /api/chat con format=json (Ollama)
    3) Parseo tolerante de fences/cadenas
    """
    host = _ollama_host()
    # 1) OpenAI compatible con response_format json_object
    v1_chat_url = f"{host}/v1/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    try:
        obj = _post_json(v1_chat_url, payload, timeout=180)
        choices = obj.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            content = (msg.get("content") or "").strip()
            parsed = _extract_json_from_text(content)
            if parsed is not None:
                return parsed
    except Exception:
        pass

    # 2) Fallback /api/chat con format=json
    chat_url = f"{host}/api/chat"
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    try:
        obj = _post_json(chat_url, payload, timeout=180)
        msg = obj.get("message") or {}
        content = (msg.get("content") or obj.get("response") or "").strip()
        parsed = _extract_json_from_text(content)
        if parsed is not None:
            return parsed
    except Exception:
        pass

    # 3) Último recurso: usar _ollama_chat normal y parsear
    content = _ollama_chat(messages, model)
    parsed = _extract_json_from_text(content)
    return parsed or {}


def ollama_files(prompt: str, stack: str, model: str, *, max_files: int = 5, mode: str | None = None) -> Dict[str, Any]:
    """
    Pide a la IA un JSON con archivos sugeridos:
    {
      "files": [ {"path": "rel/path", "content": "..."}, ... ]
    }
    """
    system = {
        "role": "system",
        "content": (
            "Contexto: Estás en Piper CLI (herramienta local de terminal para convertir prompts en proyectos). "
            "No confundas ni menciones productos de Amazon/Alexa u otros proyectos llamados 'Piper' a menos que el usuario lo pida. "
            "Tu salida DEBE ser estrictamente JSON y nada más. "
            "Devuelve SOLO un JSON válido con esta forma exacta, sin texto adicional: "
            "{\"files\":[{\"path\":\"rel/ruta\",\"content\":\"...\"}]} "
            "Usa rutas relativas al proyecto, simples (p. ej. 'README.md', 'src/app.py'), nunca rutas de usuario como '~', '/home', '/Users' ni anidar bajo 'home/usuario'. "
            "Incluye contenido mínimo funcional CON CÓDIGO completo (sin placeholders como '...'). "
            "Si el contenido proviene de notas con pasos/orden, respeta el orden sugerido en la lista 'files'."
        ),
    }
    # Mensaje de usuario adaptado: si viene de AI_NOTES.md queremos más archivos y seguir estructura
    if mode == "notes":
        hint = (
            "Este prompt es AI_NOTES.md con secciones como 'Mejoras sugeridas' y 'Pasos siguientes'. "
            "Crea los archivos y scripts mencionados, respetando las carpetas indicadas y el orden. "
            + (f"Máximo {max_files} archivos." if max_files and max_files > 0 else "")
        )
    else:
        hint = (
            (f"Genera 1-{max_files} archivos iniciales útiles." if max_files and max_files > 0 else "Genera archivos iniciales útiles.")
        )
    user = {
        "role": "user",
        "content": f"Stack: {stack}\n\nDescripción o notas:\n{prompt}\n\n{hint}",
    }
    data = _ollama_chat_json([system, user], model)
    if isinstance(data, dict) and isinstance(data.get("files"), list):
        return data
    # Intento extra: hacer una segunda solicitud más estricta y con ejemplo
    user2 = {
        "role": "user",
        "content": (
            f"Stack: {stack}\n\nDescripción o notas:\n{prompt}\n\n"
            "Devuelve SOLO un objeto JSON con EXACTAMENTE esta forma: "
            "{\"files\":[{\"path\":\"index.html\",\"content\":\"<html>...</html>\"}]} "
            + (f"sin explicaciones ni etiquetas de bloque. Máximo {max_files} archivos. " if max_files and max_files > 0 else "sin explicaciones ni etiquetas de bloque. ")
            + "Si hay pasos numerados en las notas, ordena la lista 'files' en ese orden."
        ),
    }
    data2 = _ollama_chat_json([system, user2], model)
    if isinstance(data2, dict) and isinstance(data2.get("files"), list):
        return data2
    return {"files": []}


# -------------------- Detección simple de stack --------------------

def detect_stack(prompt: str) -> str:
    p = prompt.lower()
    if "fastapi" in p:
        return "fastapi"
    if "flask" in p:
        return "flask"
    if any(k in p for k in ["node", "npm", "express"]):
        return "node"
    if "react" in p:
        return "react"
    if "go " in p or p.startswith("go"):
        return "go"
    return "python"


def detect_stack_fs(root: Path) -> str:
    """Heurística simple basada en archivos presentes en el FS."""
    req = root / "requirements.txt"
    if req.exists():
        try:
            txt = req.read_text(encoding="utf-8").lower()
            if "fastapi" in txt:
                return "fastapi"
            if "flask" in txt:
                return "flask"
            return "python"
        except Exception:
            return "python"
    if any(root.rglob("*.py")):
        return "python"
    pkg = root / "package.json"
    if pkg.exists():
        try:
            txt = pkg.read_text(encoding="utf-8").lower()
            if "react" in txt:
                return "react"
            return "node"
        except Exception:
            return "node"
    if (root / "go.mod").exists() or any(root.rglob("*.go")):
        return "go"
    return "python"


# -------------------- Utilidades de investigación web --------------------

class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._texts: list[str] = []
        self._skip_depth = 0
        self.title = ""
        self._in_title = False
        self.meta_desc = ""

    def handle_starttag(self, tag, attrs):  # type: ignore[override]
        if tag in ("script", "style", "code", "pre"):  # evitamos bloques de código
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            attrs_dict = dict(attrs)
            if attrs_dict.get("name", "").lower() == "description" and not self.meta_desc:
                self.meta_desc = attrs_dict.get("content", "")

    def handle_endtag(self, tag):  # type: ignore[override]
        if tag in ("script", "style", "code", "pre") and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):  # type: ignore[override]
        if self._skip_depth > 0:
            return
        s = data.strip()
        if not s:
            return
        if self._in_title:
            self.title += s
        else:
            self._texts.append(s)

    def text(self) -> str:
        return "\n".join(self._texts)


def _fetch_url(url: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "PiperCLI/1.0 (+local)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = resp.headers.get("Content-Type", "")
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
            return ""
        raw = resp.read()
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return raw.decode("latin-1", errors="ignore")


def _summarize_html(url: str, html: str, limit: int = 1200) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    title = parser.title.strip() or url
    desc = parser.meta_desc.strip()
    text = parser.text()
    # Filtrar encabezados/lineas relevantes (H1/H2 suelen estar en texto consolidado)
    lines = [ln for ln in text.splitlines() if len(ln) > 0]
    # Priorizar líneas cortas que parezcan encabezados o bullets
    cand = []
    for ln in lines:
        if len(ln) < 160 or ln.startswith(("- ", "* ")):
            cand.append(ln)
        if len(cand) >= 80:
            break
    body = "\n".join(cand)[:limit]
    host = urlparse(url).netloc
    md = [f"## {title}", f"- URL: {url}", f"- Host: {host}"]
    if desc:
        md.append(f"- Descripción: {desc}")
    if body:
        md.append("\nIdeas/temas detectados (sin código):\n")
        # Evitar incluir bloques largos contiguos que puedan ser código
        md.append("\n".join(["> " + l for l in body.splitlines()[:30]]))
    return "\n".join(md)


def research_urls(urls: List[str], *, timeout: float = 20.0) -> str:
    """Obtiene un resumen Markdown de múltiples URLs, evitando copiar código.
    Extrae título, meta descripción y encabezados/temas.
    """
    parts: list[str] = ["# Investigación", "\nNota: Este resumen evita incluir fragmentos de código. Solo recoge ideas, temas y referencias útiles."]
    for u in urls:
        try:
            html = _fetch_url(u, timeout=timeout)
            if not html:
                parts.append(f"\n## {u}\n(No HTML útil o tipo de contenido no soportado)")
                continue
            parts.append("\n" + _summarize_html(u, html))
        except Exception as e:
            parts.append(f"\n## {u}\nError al obtener: {e}")
    return "\n\n".join(parts).strip() + "\n"


# -------------------- Búsqueda web (DuckDuckGo HTML) --------------------

class _DDGParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_result = False
        self._urls: list[str] = []

    def handle_starttag(self, tag, attrs):  # type: ignore[override]
        if tag == "a":
            attrs_d = dict(attrs)
            href = attrs_d.get("href", "")
            if not href:
                return
            # DuckDuckGo HTML usa redirecciones /l/?uddg=<URL>
            if href.startswith("/l/?"):
                try:
                    qs = parse_qs(href.split("?", 1)[1])
                    uddg = qs.get("uddg", [""])[0]
                    if uddg:
                        url = unquote(uddg)
                        if url.startswith("http") and "duckduckgo.com" not in url:
                            self._urls.append(url)
                except Exception:
                    return
            elif href.startswith("http") and "duckduckgo.com" not in href:
                self._urls.append(href)

    def urls(self) -> list[str]:
        # de-dup preservando orden
        out: list[str] = []
        seen: set[str] = set()
        for u in self._urls:
            if u not in seen:
                out.append(u)
                seen.add(u)
        return out


def search_web(query: str, max_results: int = 5, *, timeout: float = 15.0) -> list[str]:
    """Búsqueda simple: intenta DuckDuckGo HTML y, si falla, Bing HTML.
    Retorna lista de URLs. Sin API keys. Resiliente pero no garantizada.
    """
    q = quote_plus(query.strip())
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) PiperCLI/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    }
    urls: list[str] = []
    for endpoint in (
        f"https://html.duckduckgo.com/html/?q={q}",
        f"https://duckduckgo.com/html/?q={q}",
    ):
        try:
            req = urllib.request.Request(endpoint, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            parser = _DDGParser()
            try:
                parser.feed(html)
            except Exception:
                pass
            urls = [u for u in parser.urls() if u.startswith("http") and not u.startswith("data:")]
            if urls:
                break
        except Exception:
            continue
    # Fallback a Bing si no hay resultados
    if not urls:
        try:
            bing = f"https://www.bing.com/search?q={q}&setlang=es"
            req = urllib.request.Request(bing, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            # Extracción genérica de href con regex (simple y ruidosa)
            hrefs = re.findall(r'href=\"(http[s]?://[^\"#]+)\"', html, flags=re.IGNORECASE)
            # Filtrar dominios de Bing/Microsoft y duplicados
            bad_hosts = ("bing.com", "microsoft.com", "go.microsoft", "msn.com")
            clean: list[str] = []
            seen: set[str] = set()
            for h in hrefs:
                host = urlparse(h).netloc.lower()
                if any(b in host for b in bad_hosts):
                    continue
                if h not in seen:
                    clean.append(h)
                    seen.add(h)
            urls = clean
        except Exception:
            urls = []
    return urls[:max_results]


def _extract_http_urls(text: str) -> list[str]:
    if not text:
        return []
    found = re.findall(r"https?://[\w\-./?%&#=:+]+", text, flags=re.IGNORECASE)
    out: list[str] = []
    seen: set[str] = set()
    for u in found:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


def llm_suggest_urls(query: str, model: str, *, count: int = 3) -> list[str]:
    """Pide al modelo una lista de URLs (homepages) relevantes en JSON.
    Fallback: extraer URLs de texto libre si el JSON no llega perfecto.
    """
    system = {
        "role": "system",
        "content": (
            "Eres un asistente técnico. Devuelve SOLO JSON válido con esta forma exacta: "
            "{\"urls\":[\"https://ejemplo.com\",\"https://otro.com\"]}. "
            "Incluye de 3 a 5 URLs absolutas (https://) de sitios relevantes al pedido. Sin texto adicional."
        ),
    }
    user = {"role": "user", "content": f"Pedido: {query}\n\nDevuelve solo JSON con urls."}
    data = _ollama_chat_json([system, user], model)
    urls: list[str] = []
    if isinstance(data, dict) and isinstance(data.get("urls"), list):
        for u in data.get("urls"):
            if isinstance(u, str) and u.startswith("http"):
                urls.append(u)
    if not urls:
        text = _ollama_chat([system, user], model)
        urls = _extract_http_urls(text)
    # de-dup y límite
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out[:max(1, int(count))]


def _is_probably_binary(text: str) -> bool:
    """Heurística mínima para detectar contenido no textual.
    - Si contiene NUL ('\x00') => binario
    - Si más del 5% de caracteres son de control no comunes (excluye \n,\r,\t) => probablemente binario
    """
    if "\x00" in text:
        return True
    if not text:
        return False
    total = len(text)
    ctrl = sum(1 for ch in text if ord(ch) < 32 and ch not in ("\n", "\r", "\t"))
    return (ctrl / max(total, 1)) > 0.05


# -------------------- Validación estricta de rutas IA --------------------

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/\-]+$")


def _validate_ai_relpath(base: Path, cand: str) -> tuple[bool, str, Path | None]:
    """Valida una ruta propuesta por IA y la restringe al árbol de 'base'.
    Reglas:
    - No absoluta, no ~, no unidades tipo "C:".
    - No segmentos "." ni ".." que salgan de la raíz.
    - Sólo caracteres seguros [A-Za-z0-9._/\\-].
    - Normaliza separadores y recorta espacios.
    Devuelve (ok, motivo_o_rel_normalizada, path_absoluto_o_None)
    """
    if cand is None:
        return False, "ruta vacía", None
    s = str(cand).strip()
    # normalizar separadores y eliminar backslashes (no soportamos rutas Windows)
    s = s.replace("\\", "/")
    # rutas absolutas no permitidas
    if s.startswith("/"):
        return False, "ruta absoluta no permitida", None
    if not s:
        return False, "ruta vacía", None
    # prohibidos
    if s.startswith("~"):
        return False, "ruta con ~ no permitida", None
    first_seg = s.split("/", 1)[0]
    if ":" in first_seg:
        return False, "ruta tipo unidad Windows no permitida", None
    if "/./" in f"/{s}/" or "/../" in f"/{s}/" or s == "." or s.startswith("../"):
        return False, "ruta con . o .. no permitida", None
    # evitar patrones de carpetas tipo sistema al inicio (home, users, usuario, root)
    if first_seg.lower() in {"home", "users", "user", "usuario", "root"}:
        return False, "prefijo de sistema no permitido (p.ej. 'home/', 'Users/')", None
    if not _SAFE_PATH_RE.match(s):
        return False, "caracteres no permitidos en la ruta", None
    # resolver y verificar dentro de base
    base_abs = base.resolve()
    target = (base_abs / s).resolve()
    try:
        _ = target.relative_to(base_abs)
    except Exception:
        return False, "ruta sale fuera del proyecto", None
    # retornar forma relativa normalizada
    rel_norm = str(target.relative_to(base_abs))
    return True, rel_norm, target


# -------------------- Plantillas --------------------

def scaffold_flask(dst: Path, prompt: str) -> None:
    write_file(dst / "requirements.txt", "flask\n")
    write_file(dst / "app.py", """
from flask import Flask
app = Flask(__name__)

@app.get('/')
def hello():
    return 'Hola desde Flask + Piper!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
""".lstrip())
    write_file(dst / "tests" / "test_basic.py", """
def test_truth():
    assert True
""".lstrip())
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (Flask) desde el prompt:\n\n> {prompt}\n\n## Ejecutar\n\npython3 -m venv .venv\nsource .venv/bin/activate\npip install -r requirements.txt\npython app.py\n\n## Probar\n\npython -m unittest discover -s tests -p 'test_*.py'\n""")


def scaffold_fastapi(dst: Path, prompt: str) -> None:
    write_file(dst / "requirements.txt", "fastapi\nuvicorn\n")
    write_file(dst / "main.py", """
from fastapi import FastAPI
app = FastAPI()

@app.get('/')
def hola():
    return {'msg': 'Hola desde FastAPI + Piper!'}

# uvicorn main:app --reload
""".lstrip())
    write_file(dst / "tests" / "test_basic.py", """
def test_truth():
    assert True
""".lstrip())
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (FastAPI) desde el prompt:\n\n> {prompt}\n\n## Ejecutar\n\npython3 -m venv .venv\nsource .venv/bin/activate\npip install -r requirements.txt\nuvicorn main:app --reload\n\n## Probar\n\npython -m unittest discover -s tests -p 'test_*.py'\n""")


def scaffold_python(dst: Path, prompt: str) -> None:
    write_file(dst / "requirements.txt", "")
    write_file(dst / "main.py", """
print('Hola desde Piper CLI!')
""".lstrip())
    write_file(dst / "tests" / "test_basic.py", """
def test_truth():
    assert True
""".lstrip())
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (Python) desde el prompt:\n\n> {prompt}\n\n## Ejecutar\n\npython3 main.py\n\n## Probar\n\npython -m unittest discover -s tests -p 'test_*.py'\n""")


def scaffold_node(dst: Path, prompt: str) -> None:
    write_file(dst / "package.json", """
{
  "name": "%s",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {"start": "node index.js"}
}
""".strip() % dst.name)
    write_file(dst / "index.js", """
console.log('Hola desde Node + Piper!');
""".lstrip())
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (Node) desde el prompt:\n\n> {prompt}\n\n## Ejecutar\n\nnode index.js\n""")


def scaffold_react(dst: Path, prompt: str) -> None:
    write_file(dst / "src" / "App.jsx", """
export default function App() {
  return <h1>Hola desde React + Piper</h1>
}
""".lstrip())
    write_file(dst / "package.json", """
{
  "name": "%s",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {"dev": "echo 'Agrega tu bundler (Vite) y corre'"}
}
""".strip() % dst.name)
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (React) desde el prompt:\n\n> {prompt}\n\n## Siguiente paso\n\nInicializa tu bundler favorito (Vite) y conecta src/App.jsx\n""")


def scaffold_go(dst: Path, prompt: str) -> None:
    write_file(dst / "main.go", """
package main
import "fmt"
func main(){ fmt.Println("Hola desde Go + Piper!") }
""".lstrip())
    write_file(dst / "README.md", f"""# {dst.name}\n\nGenerado por Piper (Go) desde el prompt:\n\n> {prompt}\n\n## Ejecutar\n\ngo run main.go\n""")


# -------------------- Comando principal --------------------

def create_project(prompt: str, name: str | None, base_dir: Path) -> Tuple[Path, str]:
    stack = detect_stack(prompt)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    proj_name = slugify(name or f"piper-{stack}-{ts}")
    dst = base_dir / proj_name
    if dst.exists():
        raise SystemExit(f"[ERROR] Ya existe: {dst}")
    mkdirp(dst)
    if stack == "flask":
        scaffold_flask(dst, prompt)
    elif stack == "fastapi":
        scaffold_fastapi(dst, prompt)
    elif stack == "node":
        scaffold_node(dst, prompt)
    elif stack == "react":
        scaffold_react(dst, prompt)
    elif stack == "go":
        scaffold_go(dst, prompt)
    else:
        scaffold_python(dst, prompt)
    return dst, stack


def cmd_project(args: argparse.Namespace) -> int:
    progress_start("Preparando proyecto", 3)
    # Preguntar SIEMPRE por directorio destino, con default desde memoria o arg
    mem = get_config() or {}
    default_dir = args.dir or mem.get("project", {}).get("default_dir") or str(Path.cwd())
    try:
        user_in = _ask_input(f"Directorio destino del proyecto [{default_dir}]: ")
    except _UserCanceled:
        print("[CANCELADO] Operación interrumpida por el usuario.")
        return 130
    chosen_dir = Path(user_in or default_dir).expanduser().resolve()
    # Persistir preferencia última usada
    mem.setdefault("project", {})["default_dir"] = str(chosen_dir)
    try:
        save_config(mem)
    except Exception:
        pass
    base_dir = chosen_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    dst, stack = create_project(args.prompt, args.name, base_dir)
    progress_end()
    print(f"[OK] Proyecto creado: {dst}  (stack: {stack})")
    speak(os.environ.get("PIPER_ON_CREATE_MSG", "Proyecto creado"))
    # Investigación opcional por URL(s)
    research_md = ""
    if getattr(args, "research_url", None):
        urls = [u for u in (args.research_url or []) if isinstance(u, str) and u.strip()]
        if urls:
            print(f"[INFO] Ejecutando investigación en {len(urls)} URL(s)...")
            research_md = research_urls(urls)
            try:
                write_file(dst / "RESEARCH_NOTES.md", research_md)
                print("[OK] RESEARCH_NOTES.md generado")
            except Exception as e:
                print(f"[WARN] No se pudo escribir RESEARCH_NOTES.md: {e}")
    # Notas AI opcionales vía Ollama
    model = args.ollama_model
    # --fast fuerza un modelo ligero por ejecución
    if getattr(args, "fast", False):
        model = "phi3:mini"
    # Flags por defecto: AI y archivos IA activados; permitir desactivar con --no-ai / --no-ai-files
    ai_enabled = bool(getattr(args, "ai", False)) and not bool(getattr(args, "no_ai", False))
    ai_files_enabled = bool(getattr(args, "ai_files", False)) and not bool(getattr(args, "no_ai_files", False))
    auto_apply = bool(getattr(args, "auto_apply_notes", False)) and not bool(getattr(args, "no_auto_apply_notes", False))
    max_files = int(getattr(args, "max_files", 0) or 0)
    if ai_enabled and not model:
        model = os.environ.get("PIPER_OLLAMA_MODEL") or None
    # Resolver a un modelo instalado/usable sólo si AI está habilitado
    model = _ensure_model_available(_resolve_model(model)) if ai_enabled else None
    # Cargar defaults de configuración persistente
    defaults_cfg = (get_config() or {}).get("defaults", {})
    # Si el usuario no especificó límites (están en default), usar los de config si existen
    if getattr(args, "max_ai_bytes", AI_TOTAL_BYTES_DEFAULT) == AI_TOTAL_BYTES_DEFAULT:
        if isinstance(defaults_cfg.get("max_ai_bytes"), int):
            args.max_ai_bytes = int(defaults_cfg.get("max_ai_bytes"))
    if getattr(args, "max_ai_file_bytes", AI_FILE_BYTES_DEFAULT) == AI_FILE_BYTES_DEFAULT:
        if isinstance(defaults_cfg.get("max_ai_file_bytes"), int):
            args.max_ai_file_bytes = int(defaults_cfg.get("max_ai_file_bytes"))

    if ai_enabled and model:
        try:
            progress_start("Generando notas con IA", 15)
            prompt_for_ai = args.prompt
            if research_md:
                prompt_for_ai = (
                    f"{args.prompt}\n\nContexto de investigación (ideas, referencias, sin código copiado):\n{research_md}\n"
                )
            notes = ollama_notes(prompt=prompt_for_ai, stack=stack, model=model)
            if notes:
                (dst / "AI_NOTES.md").write_text(notes, encoding="utf-8")
                print(f"[OK] AI_NOTES.md generado con {model}")
                if research_md and getattr(args, "research_merge", False):
                    try:
                        with (dst / "AI_NOTES.md").open("a", encoding="utf-8") as fh:
                            fh.write("\n\n" + research_md)
                        print("[OK] Investigación anexada a AI_NOTES.md")
                    except Exception as e:
                        print(f"[WARN] No se pudo anexar investigación a AI_NOTES.md: {e}")
            progress_end()
        except Exception as e:
            print(f"[WARN] No se pudo generar AI_NOTES.md (modelo={model}): {e}")
        # Generar archivos por IA opcionalmente (iniciales)
        if ai_files_enabled:
            try:
                progress_start("Generando archivos con IA", 20)
                max_total = int(getattr(args, "max_ai_bytes", AI_TOTAL_BYTES_DEFAULT) or AI_TOTAL_BYTES_DEFAULT)
                max_file = int(getattr(args, "max_ai_file_bytes", AI_FILE_BYTES_DEFAULT) or AI_FILE_BYTES_DEFAULT)
                used = 0
                files = ollama_files(prompt=args.prompt, stack=stack, model=model, max_files=max_files, mode=None).get("files", [])
                if not files:
                    print("[WARN] La IA no propuso archivos o JSON vacío")
                else:
                    print("[PLAN] Archivos propuestos por IA:")
                    for f in files:
                        print(f" - {f.get('path')}")
                    # Revisión por fichero con diff y confirmación (a menos que -y)
                    for f in files:
                        rel_raw = f.get("path") or ""
                        content = _sanitize_generated_content(f.get("content") or "")
                        ok_path, rel_norm, target = _validate_ai_relpath(dst, rel_raw)
                        if not ok_path or target is None:
                            motivo = rel_norm or "inválida"
                            print(f"[SKIP] Ruta inválida: {rel_raw} (razón: {motivo})")
                            continue
                        # Guardas: tamaño total y por archivo, y evitar binarios aparentes
                        content_bytes = content.encode("utf-8", errors="ignore")
                        size = len(content_bytes)
                        if size > max_file:
                            print(f"[SKIP] {rel_norm}: supera el máximo por archivo ({size} > {max_file} bytes)")
                            continue
                        if used + size > max_total:
                            print(f"[STOP] Límite total de IA alcanzado ({used + size} > {max_total} bytes). Deteniendo escritura.")
                            break
                        if _is_probably_binary(content):
                            print(f"[SKIP] {rel_norm}: contenido parece binario o no textual")
                            continue
                        if getattr(args, "show_diff", False):
                            old = ""
                            if target.exists():
                                try:
                                    old = target.read_text(encoding="utf-8")
                                except Exception:
                                    old = ""
                            if old != content:
                                diff = difflib.unified_diff(
                                    old.splitlines(), content.splitlines(),
                                    fromfile=str(target), tofile=f"new:{rel_norm}", lineterm=""
                                )
                                print("\n--- Diff:")
                                for line in diff:
                                    print(line)
                            else:
                                print(f"[SAME] Sin cambios para {rel_norm}")
                        do_write = bool(getattr(args, "yes", False)) and not bool(getattr(args, "ask", False))
                        if not do_write:
                            ans = input(f"¿Escribir {rel_norm}? (y/N): ").strip().lower()
                            do_write = ans in ("y", "s", "yes", "si")
                        if do_write:
                            write_file(target, content)
                            used += size
                            print(f"[OK] Escrito {rel_norm}")
                    print("\n[OK] Revisión AI completada.")
                progress_end()
            except Exception as e:
                print(f"[WARN] No se pudieron generar archivos AI: {e}")

        # Preguntar si desea aplicar mejoras y pasos de AI_NOTES.md
        notes_path = dst / "AI_NOTES.md"
        if notes_path.exists():
            proceed = auto_apply
            if not proceed:
                try:
                    apply_ans = _ask_input("¿Aplicar ahora las mejoras y pasos de AI_NOTES.md? (y/N): ").lower()
                except _UserCanceled:
                    apply_ans = ""
                proceed = apply_ans in ("y", "s", "yes", "si")
            if proceed:
                try:
                    text = notes_path.read_text(encoding="utf-8")
                except Exception as e:
                    print(f"[ERROR] No se pudo leer AI_NOTES.md: {e}")
                    text = ""
                if text:
                    try:
                        progress_start("Aplicando mejoras desde notas", 20)
                        plan = ollama_files(prompt=text, stack=stack, model=model, max_files=max_files, mode="notes")
                    except Exception as e:
                        print(f"[ERROR] No se pudo obtener archivos de IA desde notas: {e}")
                        plan = {"files": []}
                    files2 = plan.get("files", []) if isinstance(plan, dict) else []
                    if not files2:
                        print("[WARN] Las notas no produjeron archivos para aplicar.")
                    else:
                        print("[PLAN] Archivos desde notas (orden sugerido):")
                        for f in files2:
                            print(f" - {f.get('path')}")
                        for f in files2:
                            rel_raw = f.get("path") or ""
                            content = _sanitize_generated_content(f.get("content") or "")
                            ok_path, rel_norm, target = _validate_ai_relpath(dst, rel_raw)
                            if not ok_path or target is None:
                                motivo = rel_norm or "inválida"
                                print(f"[SKIP] Ruta inválida: {rel_raw} (razón: {motivo})")
                                continue
                            # Guardas: tamaño y binario
                            max_total2 = int(getattr(args, "max_ai_bytes", AI_TOTAL_BYTES_DEFAULT) or AI_TOTAL_BYTES_DEFAULT)
                            max_file2 = int(getattr(args, "max_ai_file_bytes", AI_FILE_BYTES_DEFAULT) or AI_FILE_BYTES_DEFAULT)
                            # reutilizamos 'used' si existe, sino iniciamos
                            try:
                                used
                            except NameError:
                                used = 0
                            content_bytes = content.encode("utf-8", errors="ignore")
                            size = len(content_bytes)
                            if size > max_file2:
                                print(f"[SKIP] {rel_norm}: supera el máximo por archivo ({size} > {max_file2} bytes)")
                                continue
                            if used + size > max_total2:
                                print(f"[STOP] Límite total de IA alcanzado ({used + size} > {max_total2} bytes). Deteniendo escritura.")
                                break
                            if _is_probably_binary(content):
                                print(f"[SKIP] {rel_norm}: contenido parece binario o no textual")
                                continue
                            if getattr(args, "show_diff", False):
                                old = ""
                                if target.exists():
                                    try:
                                        old = target.read_text(encoding="utf-8")
                                    except Exception:
                                        old = ""
                                if old != content:
                                    diff = difflib.unified_diff(
                                        old.splitlines(), content.splitlines(),
                                        fromfile=str(target), tofile=f"new:{rel_norm}", lineterm=""
                                    )
                                    print("\n--- Diff:")
                                    for line in diff:
                                        print(line)
                                else:
                                    print(f"[SAME] Sin cambios para {rel_norm}")
                            # Respetar --ask si se pasó, si no, usar yes por defecto
                            do_write = bool(getattr(args, "yes", True)) and not bool(getattr(args, "ask", False))
                            if not do_write:
                                try:
                                    ans = _ask_input(f"¿Escribir {rel_norm}? (y/N): ").lower()
                                except _UserCanceled:
                                    ans = ""
                                do_write = ans in ("y", "s", "yes", "si")
                            if do_write:
                                write_file(target, content)
                                used += size
                                print(f"[OK] Escrito {rel_norm}")
                        print("\n[OK] Aplicación de notas completada.")
                        progress_end()
    # Verificación rápida post-creación (lint/sintaxis y pruebas básicas si existen)
    try:
        progress_start("Verificando proyecto", 5)
        _summary = verify_project(dst, stack)
        print(_summary)
        progress_end()
    except Exception as e:
        print(f"[WARN] Verificación post-creación falló: {e}")
    # Smoke run: por defecto en stack 'python' simple, o si --smoke-run está presente; desactivable con --no-smoke-run
    smoke_default_python = (defaults_cfg.get("smoke_python_default") if isinstance(defaults_cfg, dict) else None)
    if smoke_default_python is None:
        smoke_default_python = True
    do_smoke = bool(getattr(args, "smoke_run", False)) or (stack == "python" and bool(smoke_default_python) and not bool(getattr(args, "no_smoke_run", False)))
    if do_smoke:
        try:
            progress_start("Prueba rápida (smoke run)", 5)
            ok, msg = smoke_run(dst, stack, timeout=int(getattr(args, "smoke_timeout", 5) or 5))
            print(msg)
            progress_end()
        except Exception as e:
            print(f"[WARN] Smoke run falló: {e}")
    # Resumen con mayordomo y árbol de proyecto
    try:
        summary_lines = [
            f"Listo, se completó la creación del proyecto: {dst.name}",
            "Estructura principal:",
        ]
        for ln in _dir_tree(dst, max_depth=2, max_entries=80):
            summary_lines.append(ln)
        print("\n" + _ascii_butler(summary_lines) + "\n")
    except Exception:
        pass
    # Ofrecer nueva interacción
    try:
        ans = input("¿Gusta agregar o hacer otra opción? (y/N): ").strip().lower()
    except EOFError:
        ans = ""
    if ans in ("y", "s", "yes", "si"):
        try:
            nxt = input("Escribe tu prompt (o ENTER para salir): ").strip()
        except EOFError:
            nxt = ""
        if nxt:
            ns = argparse.Namespace(prompt=nxt, model=None, no_tts=False)
            return cmd_assist(ns)
    return 0


def cmd_assist(args: argparse.Namespace) -> int:
    # --fast fuerza un modelo ligero por ejecución
    if getattr(args, "fast", False):
        args.model = "phi3:mini"
    # Intento local: si el prompt pide la fecha de hoy, responder sin IA
    prompt0 = getattr(args, "prompt", "")
    if _is_date_query(prompt0):
        text = _date_today_text()
        print(text)
        if not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: hora actual
    if _is_time_query(prompt0):
        text = _time_now_text()
        print(text)
        if not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: directorio actual
    if _is_cwd_query(prompt0):
        text = _cwd_text()
        print(text)
        if not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: IP (local o pública)
    is_ip, ip_kind = _is_ip_query(prompt0)
    if is_ip:
        if ip_kind == "publica":
            text = _get_public_ip()
        else:
            text = _get_local_ip()
        print(text)
        if not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: información del sistema operativo
    if _is_os_info_query(prompt0):
        text = _os_info_text()
        print(text)
        if not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: búsqueda de archivo dentro del directorio actual
    if _is_find_file_query(prompt0):
        term = _extract_filename_term(prompt0)
        if not term:
            print("Indica el nombre del archivo, por ejemplo: buscar archivo \"README.md\"")
            return 2
        base = Path.cwd()
        results = _search_files(term, base, max_results=20)
        if not results:
            text = f"No encontré '{term}' bajo {base}"
            print(text)
            if not args.no_tts:
                speak(text)
            _maybe_save_output(base, getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
            return 0
        lines = [f"Resultados (máx 20) buscando '{term}' bajo {base}:"] + [" - " + str(p) for p in results]
        text = "\n".join(lines)
        print(text)
        _maybe_save_output(base, getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Web + LLM: si --web está activo, usar investigación + modelo para responder al prompt (tiene prioridad)
    if getattr(args, "web", False):
        urls = _extract_urls(prompt0)
        # Si no hay URLs explícitas, intentamos buscarlas a partir del prompt
        if not urls:
            web_max = int(getattr(args, "web_max", 5) or 5)
            web_timeout = float(getattr(args, "web_timeout", 15) or 15)
            urls = with_progress("Buscando sitios en la web", 6, search_web, prompt0, max_results=web_max, timeout=web_timeout)
            if not urls:
                # Último recurso: pedir al modelo que sugiera URLs
                model0 = _ensure_model_available(_resolve_model(args.model))
                urls = with_progress("Sugerencias de sitios (modelo)", 8, llm_suggest_urls, prompt0, model0, count=web_max)
                if not urls:
                    print("[ERROR] No se encontraron URLs para la búsqueda web a partir del prompt")
                    return 2
        try:
            web_max = int(getattr(args, "web_max", 5) or 5)
            web_timeout = float(getattr(args, "web_timeout", 15) or 15)
            est = min(5 * len(urls[:web_max]), 25)
            md = with_progress("Investigación web (resumen)", est, research_urls, urls[:web_max], timeout=web_timeout)
        except Exception as e:
            print(f"[ERROR] Investigación web falló: {e}")
            return 1
        model = _ensure_model_available(_resolve_model(args.model))
        system = {
            "role": "system",
            "content": (
                "Eres un asistente técnico en Piper CLI. Usa el CONTEXTO a continuación (resumen web) como referencia; "
                "no copies código textual de las páginas. Responde claro, en Markdown si corresponde."
            ),
        }
        user_msg = {
            "role": "user",
            "content": (
                f"Solicitud: {prompt0}\n\nCONTEXTO (resumen web, sin código copiado):\n{md}\n\n"
                "Responde usando el contexto, citando ideas o temas relevantes, sin pegar código de las páginas."
            ),
        }
        gen_est = int(getattr(args, "gen_estimate", 20) or 20)
        out_text = with_progress("Generando respuesta (modelo)", gen_est, _ollama_chat, [system, user_msg], model)
        print(out_text)
        if not args.no_tts and out_text:
            speak(out_text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), out_text, append=bool(getattr(args, "append", False)))
        return 0
    # Auto-búsqueda web si la intención lo sugiere (sin requerir --web)
    if _wants_web_search(prompt0):
        print("[INFO] Usando búsqueda web para responder...")
        web_max = int(getattr(args, "web_max", 5) or 5)
        web_timeout = float(getattr(args, "web_timeout", 15) or 15)
        urls = with_progress("Buscando sitios en la web", 6, search_web, prompt0, max_results=web_max, timeout=web_timeout)
        if not urls:
            model0 = _ensure_model_available(_resolve_model(args.model))
            urls = with_progress("Sugerencias de sitios (modelo)", 8, llm_suggest_urls, prompt0, model0, count=web_max)
        if urls:
            try:
                est2 = min(5 * len(urls[:web_max]), 25)
                md = with_progress("Investigación web (resumen)", est2, research_urls, urls[:web_max], timeout=web_timeout)
            except Exception as e:
                print(f"[ERROR] Investigación web falló: {e}")
                md = ""
            model0 = _ensure_model_available(_resolve_model(args.model))
            system = {
                "role": "system",
                "content": (
                    "Eres un asistente técnico en Piper CLI. Usa el CONTEXTO (resumen web) como referencia; "
                    "no copies código textual. Responde claro y práctico."
                ),
            }
            user_msg = {"role": "user", "content": f"Solicitud: {prompt0}\n\nCONTEXTO:\n{md}"}
            gen_est = int(getattr(args, "gen_estimate", 20) or 20)
            out_text = with_progress("Generando respuesta (modelo)", gen_est, _ollama_chat, [system, user_msg], model0)
            print(out_text)
            if not args.no_tts and out_text:
                speak(out_text)
            _maybe_save_output(Path.cwd(), getattr(args, "save", None), out_text, append=bool(getattr(args, "append", False)))
            return 0
    # Intento local: si el prompt contiene URL(s) y pide resumen web
    urls0 = _extract_urls(prompt0)
    if urls0 and _wants_web_summary(prompt0):
        try:
            web_timeout = float(getattr(args, "web_timeout", 15) or 15)
            est0 = min(5 * len(urls0[:3]), 15)
            md = with_progress("Investigación web (resumen)", est0, research_urls, urls0[:3], timeout=web_timeout)
            print(md)
            _maybe_save_output(Path.cwd(), getattr(args, "save", None), md, append=bool(getattr(args, "append", False)))
            return 0
        except Exception as e:
            print(f"[ERROR] No se pudo obtener resumen web: {e}")
    # Modo libre tipo chat: respuesta de texto del modelo directamente
    if getattr(args, "freeform", False):
        model = _ensure_model_available(_resolve_model(args.model))
        system = {
            "role": "system",
            "content": (
                "Eres un asistente técnico integrado en Piper CLI (local). "
                "Responde de manera clara y útil. Si el usuario pide crear contenido, redacta en Markdown. "
                "No confundas Piper CLI con productos de Amazon/Alexa u otros 'Piper'."
            ),
        }
        messages: List[Dict[str, Any]] = [system, {"role": "user", "content": prompt0}]
        gen_est = int(getattr(args, "gen_estimate", 20) or 20)
        out_text = with_progress("Generando respuesta (modelo)", gen_est, _ollama_chat, messages, model)
        print(out_text)
        if not args.no_tts and out_text:
            speak(out_text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), out_text, append=bool(getattr(args, "append", False)))
        return 0
    model = _ensure_model_available(_resolve_model(args.model))
    system = {
        "role": "system",
        "content": (
            "Contexto: Estás integrado en Piper CLI, una herramienta local de terminal que ayuda a convertir prompts en proyectos y tareas, "
            "con integración a Ollama y TTS opcional. NO confundas Piper CLI con productos de Amazon, Alexa u otros proyectos llamados 'Piper'. "
            "Si el usuario menciona 'Piper' sin más, asume que se refiere a Piper CLI local de este equipo. "
            "Si percibes ambigüedad entre distintas marcas/tecnologías llamadas igual, pregunta para aclarar antes de afirmar. "
            "Tu objetivo es ayudar a clarificar peticiones ambiguas; si la petición requiere más detalles, formula UNA pregunta específica y útil. "
            "Si ya hay suficiente contexto, responde claramente. "
            "Responde SIEMPRE en este formato JSON, sin texto adicional: "
            "{\"type\":\"question\",\"text\":\"...\"} o {\"type\":\"answer\",\"text\":\"...\"}."
        ),
    }
    user_content = (
        "Nos referimos a 'Piper CLI' (este proyecto local), NO a productos de Amazon ni Alexa. "
        "Si la petición es ambigua, pregunta primero. "
        f"Petición: {args.prompt}"
    )
    messages: List[Dict[str, Any]] = [system, {"role": "user", "content": user_content}]
    while True:
        data = _ollama_chat_json(messages, model)
        # data debería ser {type:"question"|"answer", text:"..."}
        if not isinstance(data, dict) or not data:
            # Fallback: texto simple
            out_text = _ollama_chat(messages, model)
            # Guardarraíl mínimo contra confusión Amazon
            low = (out_text or "").lower()
            if "amazon" in low and "piper" in low:
                data = {"type": "question", "text": "¿Te refieres a Piper CLI (esta herramienta local) o a otro producto llamado Piper?"}
            else:
                print(out_text)
                if not args.no_tts:
                    speak(out_text)
                return 0
        t = (data or {}).get("type")
        text = (data or {}).get("text") or ""
        # Segundo guardarraíl: si el texto confunde con Amazon, pedir aclaración
        lowt = text.lower()
        if "amazon" in lowt and "piper" in lowt:
            t = "question"
            text = "¿Te refieres a Piper CLI (esta herramienta local) o a otro producto llamado Piper?"
        if t == "question":
            # Si la propia pregunta del modelo es sobre la fecha de hoy, responde localmente
            if _is_date_query(text):
                ans = _date_today_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            # Si pregunta la hora
            if _is_time_query(text):
                ans = _time_now_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            # Si pregunta directorio actual
            if _is_cwd_query(text):
                ans = _cwd_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            # Si la pregunta trae URL(s) y parece pedir resumen
            urls_q = _extract_urls(text)
            if urls_q and _wants_web_summary(text):
                try:
                    md = research_urls(urls_q[:3])
                    print(md)
                    _maybe_save_output(Path.cwd(), getattr(args, "save", None), md, append=bool(getattr(args, "append", False)))
                    return 0
                except Exception as e:
                    print(f"[ERROR] No se pudo obtener resumen web: {e}")
            print(text)
            try:
                answer = _ask_input("> ")
            except _UserCanceled:
                print("[CANCELADO] Operación interrumpida por el usuario.")
                return 130
            # Si el usuario responde preguntando por la fecha, resolver localmente
            if _is_date_query(answer):
                ans = _date_today_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            if _is_time_query(answer):
                ans = _time_now_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            if _is_cwd_query(answer):
                ans = _cwd_text()
                print(ans)
                if not args.no_tts:
                    speak(ans)
                _maybe_save_output(Path.cwd(), getattr(args, "save", None), ans, append=bool(getattr(args, "append", False)))
                return 0
            urls_a = _extract_urls(answer)
            if urls_a and _wants_web_summary(answer):
                try:
                    md = research_urls(urls_a[:3])
                    print(md)
                    _maybe_save_output(Path.cwd(), getattr(args, "save", None), md, append=bool(getattr(args, "append", False)))
                    return 0
                except Exception as e:
                    print(f"[ERROR] No se pudo obtener resumen web: {e}")
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": answer})
            continue
        elif t == "answer":
            print(text)
            if not args.no_tts:
                speak(text)
            _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
            return 0
        else:
            print(text)
            if not args.no_tts and text:
                speak(text)
            _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
            return 0


def cmd_say(args: argparse.Namespace) -> int:
    said = speak(args.text)
    return 0 if said else 1


def cmd_service_on(_args: argparse.Namespace) -> int:
    ok, msg = start_ollama_service()
    print(msg or ("[OK] Ollama iniciado" if ok else "[ERROR] No se pudo iniciar Ollama"))
    # Intento de ping rápido
    try:
        tags = _get_json(f"{_ollama_host()}/api/tags")
        if isinstance(tags, dict):
            print("[OK] Ollama responde en", _ollama_host())
    except Exception:
        print("[WARN] No se pudo verificar Ollama vía HTTP ahora mismo")
    return 0 if ok else 1


def cmd_service_off(_args: argparse.Namespace) -> int:
    ok, msg = stop_ollama_service()
    print(msg or ("[OK] Ollama detenido" if ok else "[ERROR] No se pudo detener Ollama"))
    return 0 if ok else 1


def cmd_apply_notes(args: argparse.Namespace) -> int:
    proj_dir = Path(args.dir).expanduser().resolve()
    notes = proj_dir / "AI_NOTES.md"
    if not notes.exists():
        print(f"[ERROR] No existe {notes}")
        return 1
    try:
        text = notes.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[ERROR] No se pudo leer AI_NOTES.md: {e}")
        return 1
    # Intentar detectar stack para orientar a la IA
    stack = detect_stack(text)
    # --fast fuerza modelo ligero
    if getattr(args, "fast", False):
        args.model = "phi3:mini"
    model = _ensure_model_available(_resolve_model(args.model))
    try:
        plan = ollama_files(prompt=text, stack=stack, model=model)
    except Exception as e:
        print(f"[ERROR] No se pudo obtener archivos de IA: {e}")
        return 1
    files = plan.get("files", []) if isinstance(plan, dict) else []
    if not files:
        print("[WARN] La IA no propuso archivos para aplicar.")
        return 0
    print("[PLAN] Archivos propuestos por IA:")
    for f in files:
        print(f" - {f.get('path')}")
    for f in files:
        rel_raw = f.get("path") or ""
        content = _sanitize_generated_content(f.get("content") or "")
        ok_path, rel_norm, target = _validate_ai_relpath(proj_dir, rel_raw)
        if not ok_path or target is None:
            motivo = rel_norm or "inválida"
            print(f"[SKIP] Ruta inválida: {rel_raw} (razón: {motivo})")
            continue
        old = ""
        if target.exists():
            try:
                old = target.read_text(encoding="utf-8")
            except Exception:
                old = ""
        if old != content:
            diff = difflib.unified_diff(
                old.splitlines(), content.splitlines(),
                fromfile=str(target), tofile=f"new:{rel_norm}", lineterm=""
            )
            print("\n--- Diff:")
            for line in diff:
                print(line)
        else:
            print(f"[SAME] Sin cambios para {rel_norm}")
        do_write = getattr(args, "yes", False)
        if not do_write:
            try:
                ans = _ask_input(f"¿Escribir {rel_norm}? (y/N): ").lower()
            except _UserCanceled:
                ans = ""
            do_write = ans in ("y", "s", "yes", "si")
        if do_write:
            write_file(target, content)
            print(f"[OK] Escrito {rel_norm}")
    print("\n[OK] Aplicación de notas completa.")
    return 0


def cmd_research(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    urls = [u for u in (args.url or []) if isinstance(u, str) and u.strip()]
    if not urls:
        print("[ERROR] Debes proporcionar al menos una --url")
        return 2
    print(f"[INFO] Investigando {len(urls)} URL(s)...")
    md = research_urls(urls)
    try:
        write_file(root / "RESEARCH_NOTES.md", md)
        print(f"[OK] RESEARCH_NOTES.md escrito en {root}")
    except Exception as e:
        print(f"[ERROR] No se pudo escribir RESEARCH_NOTES.md: {e}")
        return 1
    if getattr(args, "merge", False) and (root / "AI_NOTES.md").exists():
        try:
            with (root / "AI_NOTES.md").open("a", encoding="utf-8") as fh:
                fh.write("\n\n" + md)
            print("[OK] Investigación anexada a AI_NOTES.md")
        except Exception as e:
            print(f"[WARN] No se pudo anexar a AI_NOTES.md: {e}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    mem = get_config() or {}
    defaults = mem.setdefault("defaults", {})
    changed = False
    if args.set_max_ai_bytes is not None:
        try:
            val = int(args.set_max_ai_bytes)
            if val > 0:
                defaults["max_ai_bytes"] = val
                changed = True
                print(f"[OK] max_ai_bytes = {val}")
        except Exception:
            print("[ERROR] Valor inválido para --set-max-ai-bytes")
    if args.set_max_ai_file_bytes is not None:
        try:
            val = int(args.set_max_ai_file_bytes)
            if val > 0:
                defaults["max_ai_file_bytes"] = val
                changed = True
                print(f"[OK] max_ai_file_bytes = {val}")
        except Exception:
            print("[ERROR] Valor inválido para --set-max-ai-file-bytes")
    if args.enable_smoke_python and args.disable_smoke_python:
        print("[WARN] Ignorando banderas conflictivas: enable y disable a la vez")
    elif args.enable_smoke_python:
        defaults["smoke_python_default"] = True
        changed = True
        print("[OK] smoke_python_default = True")
    elif args.disable_smoke_python:
        defaults["smoke_python_default"] = False
        changed = True
        print("[OK] smoke_python_default = False")
    if changed:
        try:
            save_config(mem)
        except Exception as e:
            print(f"[ERROR] No se pudo guardar configuración: {e}")
            return 1
    # Mostrar configuración si se pidió o si no hubo cambios
    if args.show or not changed:
        cur = get_config() or {}
        d = cur.get("defaults", {})
        print("\n[CONFIG]")
        print(f"max_ai_bytes: {d.get('max_ai_bytes', AI_TOTAL_BYTES_DEFAULT)}")
        print(f"max_ai_file_bytes: {d.get('max_ai_file_bytes', AI_FILE_BYTES_DEFAULT)}")
        print(f"smoke_python_default: {d.get('smoke_python_default', True)}")
    return 0


# -------------------- Verificación y 'fix' --------------------

def _py_compile_all(root: Path) -> list[tuple[Path, str]]:
    """Compila todos los .py bajo root. Devuelve lista de (path, error_str) para fallos."""
    errors: list[tuple[Path, str]] = []
    for py in root.rglob("*.py"):
        try:
            py_compile.compile(str(py), doraise=True)
        except Exception as e:
            errors.append((py, f"{e}"))
    return errors


def _run_unittest_if_present(root: Path, timeout: int = 60) -> tuple[int, str, str]:
    """Ejecuta 'python -m unittest discover' si existe carpeta tests; si no existe, retorna (0, '', '')."""
    if not (root / "tests").exists():
        return 0, "", ""
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-q"]
    try:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout al ejecutar unittest"
    except Exception:
        return 1, "", traceback.format_exc()


def verify_project(root: Path, stack: str, *, timeout: int = 60) -> str:
    """Verifica proyecto tras crearlo.
    - Python (incluye flask/fastapi/python): compila .py y corre unittest si existe.
    - Otros stacks: por ahora, reporte informativo.
    Devuelve un resumen legible.
    """
    root = root.resolve()
    summary_lines: list[str] = []
    if stack in {"python", "flask", "fastapi"}:
        errs = _py_compile_all(root)
        if errs:
            summary_lines.append(f"[FAIL] Errores de sintaxis en {len(errs)} archivo(s):")
            for p, msg in errs[:10]:
                summary_lines.append(f"  - {p.relative_to(root)} :: {msg}")
            if len(errs) > 10:
                summary_lines.append(f"  ... y {len(errs) - 10} más")
        else:
            summary_lines.append("[PASS] Sintaxis Python OK")
        code, out, err = _run_unittest_if_present(root, timeout=timeout)
        if code == 0:
            summary_lines.append("[PASS] Pruebas unitarias OK")
        elif code == 124:
            summary_lines.append("[WARN] Pruebas unitarias: timeout")
        else:
            summary_lines.append("[FAIL] Pruebas unitarias fallaron")
            if err:
                summary_lines.append(err.strip().splitlines()[-1] if err.strip() else "Sin stderr")
    elif stack in {"node", "react"}:
        # Verificación ligera: si hay package.json, intentar npm test si existe script y npm está disponible
        pkg = root / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            scripts = (data.get("scripts") or {}) if isinstance(data, dict) else {}
            if "test" in scripts and shutil.which("npm"):
                try:
                    proc = subprocess.run(["npm", "test", "--silent"], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc.returncode == 0:
                        summary_lines.append("[PASS] npm test OK")
                    else:
                        summary_lines.append("[FAIL] npm test falló")
                        summary_lines.append((proc.stderr or proc.stdout).strip().splitlines()[-1] if (proc.stderr or proc.stdout) else "")
                except subprocess.TimeoutExpired:
                    summary_lines.append("[WARN] npm test timeout")
            else:
                summary_lines.append("[INFO] package.json sin script test o npm no disponible")
        else:
            summary_lines.append("[INFO] No se encontró package.json")
    elif stack == "go":
        # go build/test si go está disponible
        if shutil.which("go"):
            try:
                proc = subprocess.run(["go", "build", "./..."], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                if proc.returncode == 0:
                    summary_lines.append("[PASS] go build OK")
                else:
                    summary_lines.append("[FAIL] go build falló")
            except subprocess.TimeoutExpired:
                summary_lines.append("[WARN] go build timeout")
            # tests si hay *_test.go
            if any(root.rglob("*_test.go")):
                try:
                    proc2 = subprocess.run(["go", "test", "./..."], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc2.returncode == 0:
                        summary_lines.append("[PASS] go test OK")
                    else:
                        summary_lines.append("[FAIL] go test falló")
                except subprocess.TimeoutExpired:
                    summary_lines.append("[WARN] go test timeout")
        else:
            summary_lines.append("[INFO] go no está disponible en PATH")
    else:
        summary_lines.append("[INFO] Stack no reconocido para verificación automática.")
    return "\n".join(summary_lines)


def cmd_fix(args: argparse.Namespace) -> int:
    """Revisa un directorio de proyecto. Primera versión enfocada en Python.
    - Sintaxis (py_compile)
    - Pruebas (unittest) si hay tests/
    Exit code 0 si todo OK; 1 en fallos.
    """
    root = Path(args.dir).expanduser().resolve()
    stack = args.stack or detect_stack_fs(root)
    summary = verify_project(root, stack, timeout=args.timeout)
    print(summary)
    if "[FAIL]" in summary:
        return 1
    return 0


def smoke_run(root: Path, stack: str, *, timeout: int = 5) -> tuple[bool, str]:
    """Ejecuta un arranque breve (2-5s) para algunos stacks.
    - python: python main.py si existe
    - flask: python app.py si existe (sólo si Flask parece instalado, de lo contrario se omite)
    - node: node index.js si existe
    - go: go run main.go si existe
    Devuelve (ok, mensaje resumen). Nunca lanza excepción (captura interna).
    """
    root = root.resolve()
    try:
        if stack == "python":
            main = root / "main.py"
            if main.exists():
                try:
                    proc = subprocess.run([sys.executable, str(main)], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc.returncode == 0:
                        return True, "[PASS] Smoke run python main.py OK"
                    return False, f"[FAIL] Smoke run python main.py salió con código {proc.returncode}"
                except subprocess.TimeoutExpired:
                    return True, "[WARN] Smoke run python main.py timeout (posible servidor en ejecución)"
        elif stack == "flask":
            app = root / "app.py"
            if app.exists():
                # Intentar sólo si Flask parece instalado en el entorno actual
                try:
                    __import__("flask")
                except Exception:
                    return True, "[INFO] Flask no parece instalado; se omite smoke run"
                try:
                    proc = subprocess.run([sys.executable, str(app)], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc.returncode == 0:
                        return True, "[PASS] Smoke run flask app.py OK"
                    return False, f"[FAIL] Smoke run flask app.py salió con código {proc.returncode}"
                except subprocess.TimeoutExpired:
                    return True, "[WARN] Smoke run flask app.py timeout (posible servidor en ejecución)"
        elif stack in {"node", "react"}:
            idx = root / "index.js"
            if idx.exists() and shutil.which("node"):
                try:
                    proc = subprocess.run(["node", str(idx)], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc.returncode == 0:
                        return True, "[PASS] Smoke run node index.js OK"
                    return False, f"[FAIL] Smoke run node index.js salió con código {proc.returncode}"
                except subprocess.TimeoutExpired:
                    return True, "[WARN] Smoke run node index.js timeout"
        elif stack == "go":
            mg = root / "main.go"
            if mg.exists() and shutil.which("go"):
                try:
                    proc = subprocess.run(["go", "run", str(mg)], cwd=str(root), capture_output=True, text=True, timeout=timeout)
                    if proc.returncode == 0:
                        return True, "[PASS] Smoke run go run main.go OK"
                    return False, f"[FAIL] Smoke run go run main.go salió con código {proc.returncode}"
                except subprocess.TimeoutExpired:
                    return True, "[WARN] Smoke run go run main.go timeout"
        return True, "[INFO] Smoke run no aplicable para este stack o archivos de entrada no encontrados"
    except Exception as e:
        return False, f"[WARN] Smoke run error: {e}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="piper", description="Piper CLI — prompt a proyecto")
    sub = p.add_subparsers(dest="cmd")

    p_assist = sub.add_parser("assist", help="Asistente interactivo con aclaraciones")
    p_assist.add_argument("prompt", help="Petición inicial")
    p_assist.add_argument("--model", help="Modelo Ollama (por defecto PIPER_OLLAMA_MODEL o mistral:7b-instruct)")
    p_assist.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_assist.add_argument("--no-tts", action="store_true", help="Desactiva TTS al responder")
    p_assist.add_argument("--freeform", action="store_true", help="Modo estilo chat: respuesta libre de texto (sin JSON)")
    p_assist.add_argument("--web", action="store_true", help="Usa resumen web de URLs del prompt como contexto para la respuesta")
    p_assist.add_argument("--web-max", type=int, default=5, help="Máximo de sitios web a considerar (por defecto 5)")
    p_assist.add_argument("--web-timeout", type=int, default=15, help="Timeout por solicitud web en segundos (por defecto 15s)")
    p_assist.add_argument("--gen-estimate", type=int, default=20, help="Tiempo estimado (s) mostrado para la fase de generación")
    p_assist.add_argument("--save", help="Guardar la salida en un archivo relativo (p. ej. 'notas.md')")
    p_assist.add_argument("--append", action="store_true", help="Anexar en vez de sobrescribir al usar --save")
    p_assist.set_defaults(func=cmd_assist)

    p_project = sub.add_parser("project", help="Genera un proyecto")
    p_project.add_argument("prompt", help="Descripción del proyecto")
    p_project.add_argument("--name", help="Nombre del proyecto")
    p_project.add_argument("--dir", default=str(Path.cwd()), help="Directorio destino (por defecto: cwd)")
    p_project.add_argument("--ollama-model", dest="ollama_model", help="Modelo Ollama para notas AI (ej. mistral:latest)")
    p_project.add_argument("--ai", action="store_true", help="Alias de --ollama-model=$PIPER_OLLAMA_MODEL o valor por defecto")
    p_project.add_argument("--no-ai", action="store_true", help="Desactivar generación de AI_NOTES.md")
    p_project.add_argument("--ai-files", action="store_true", help="Genera archivos sugeridos por IA (JSON)")
    p_project.add_argument("--no-ai-files", action="store_true", help="No generar archivos IA")
    p_project.add_argument("-y", "--yes", action="store_true", help="No preguntar confirmación al escribir archivos IA")
    p_project.add_argument("--ask", action="store_true", help="Pedir confirmación al escribir archivos IA")
    p_project.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_project.add_argument("--auto-apply-notes", action="store_true", help="Aplicar mejoras/pasos de AI_NOTES.md automáticamente")
    p_project.add_argument("--no-auto-apply-notes", action="store_true", help="No aplicar automáticamente AI_NOTES.md")
    p_project.add_argument("--max-files", type=int, default=0, help="Límite de archivos IA por fase (0 = sin límite)")
    p_project.add_argument("--research-url", action="append", help="URL de investigación (repetible)")
    p_project.add_argument("--research-merge", action="store_true", help="Anexar investigación a AI_NOTES.md")
    p_project.add_argument("--smoke-run", action="store_true", help="Intentar una ejecución breve tras crear el proyecto")
    p_project.add_argument("--smoke-timeout", type=int, default=5, help="Timeout de smoke run en segundos (por defecto 5)")
    p_project.add_argument("--no-smoke-run", action="store_true", help="Desactiva el smoke run por defecto en stack 'python'")
    p_project.add_argument("--max-ai-bytes", type=int, default=AI_TOTAL_BYTES_DEFAULT, help=f"Máximo de bytes a escribir por IA en un lote (por defecto {AI_TOTAL_BYTES_DEFAULT} bytes ~ {AI_TOTAL_BYTES_DEFAULT//(1024*1024)}MB)")
    p_project.add_argument("--max-ai-file-bytes", type=int, default=AI_FILE_BYTES_DEFAULT, help=f"Máximo de bytes por archivo IA (por defecto {AI_FILE_BYTES_DEFAULT} bytes ~ {AI_FILE_BYTES_DEFAULT//(1024*1024)}MB)")
    p_project.add_argument("--show-diff", action="store_true", help="Mostrar diff al aplicar archivos IA (por defecto oculto)")
    # Por defecto: AI activado, archivos IA activados, escritura sin preguntar y aplicar notas automáticamente; sin límite de archivos
    p_project.set_defaults(func=cmd_project, ai=True, ai_files=True, yes=True, auto_apply_notes=True, max_files=0)

    p_say = sub.add_parser("say", help="Decir un texto con Piper TTS")
    p_say.add_argument("text")
    p_say.set_defaults(func=cmd_say)

    # Servicio Ollama ON/OFF (acepta mayúsculas y minúsculas)
    p_on = sub.add_parser("on", help="Enciende el servicio Ollama")
    p_on.set_defaults(func=cmd_service_on)
    p_on2 = sub.add_parser("ON", help="Enciende el servicio Ollama")
    p_on2.set_defaults(func=cmd_service_on)
    p_off = sub.add_parser("off", help="Apaga el servicio Ollama")
    p_off.set_defaults(func=cmd_service_off)
    p_off2 = sub.add_parser("OFF", help="Apaga el servicio Ollama")
    p_off2.set_defaults(func=cmd_service_off)

    # Aplicar propuestas desde AI_NOTES.md al proyecto
    p_apply = sub.add_parser("apply-notes", help="Genera y aplica archivos desde AI_NOTES.md con revisión")
    p_apply.add_argument("--dir", default=str(Path.cwd()), help="Directorio del proyecto (por defecto: cwd)")
    p_apply.add_argument("--model", help="Modelo Ollama (por defecto PIPER_OLLAMA_MODEL o mistral:7b-instruct)")
    p_apply.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_apply.add_argument("-y", "--yes", action="store_true", help="Escribir sin preguntar por fichero")
    p_apply.add_argument("--show-diff", action="store_true", help="Mostrar diff al aplicar archivos IA (por defecto oculto)")
    p_apply.set_defaults(func=cmd_apply_notes)

    # Revisar/Arreglar proyecto
    p_fix = sub.add_parser("fix", help="Revisar sintaxis y pruebas básicas del proyecto")
    p_fix.add_argument("--dir", default=str(Path.cwd()), help="Directorio del proyecto (por defecto: cwd)")
    p_fix.add_argument("--stack", help="Forzar stack (python/flask/fastapi/node/react/go)")
    p_fix.add_argument("--timeout", type=int, default=60, help="Timeout para pruebas (s)")
    p_fix.set_defaults(func=cmd_fix)

    # Investigación web por separado
    p_research = sub.add_parser("research", help="Obtiene y resume páginas para inspiración (sin copiar código)")
    p_research.add_argument("--dir", default=str(Path.cwd()), help="Directorio donde guardar RESEARCH_NOTES.md (por defecto: cwd)")
    p_research.add_argument("--url", action="append", required=True, help="URL a investigar (repetible)")
    p_research.add_argument("--merge", action="store_true", help="Anexar a AI_NOTES.md si existe")
    p_research.set_defaults(func=cmd_research)

    # Configuración persistente (memoria de Piper)
    p_conf = sub.add_parser("config", help="Configura defaults persistentes (límites IA, smoke-run)")
    p_conf.add_argument("--show", action="store_true", help="Mostrar configuración actual")
    p_conf.add_argument("--set-max-ai-bytes", type=int, help="Fija máximo total de bytes IA por lote")
    p_conf.add_argument("--set-max-ai-file-bytes", type=int, help="Fija máximo de bytes IA por archivo")
    p_conf.add_argument("--enable-smoke-python", action="store_true", help="Activa smoke run por defecto en stack 'python'")
    p_conf.add_argument("--disable-smoke-python", action="store_true", help="Desactiva smoke run por defecto en stack 'python'")
    p_conf.set_defaults(func=cmd_config)

    # Positional opcional sólo si no hay subcomando
    p.add_argument("default_prompt", nargs="?", help=argparse.SUPPRESS)
    return p


def main(argv: list[str]) -> int:
    # Banner global al inicio, desactivable con PIPER_NO_BANNER=1
    if os.environ.get("PIPER_NO_BANNER", "0") not in ("1", "true", "yes"): 
        try:
            print(_ascii_banner())
        except Exception:
            pass
    parser = build_parser()
    # Permitir modo "piper \"haz X\"" sin subcomando, tolerando flags desconocidas
    args, extras = parser.parse_known_args(argv[1:])
    if not getattr(args, "cmd", None):
        # Sin subcomando explícito -> asistente rápido
        default_prompt = getattr(args, "default_prompt", None) or (extras[0] if extras else (argv[1] if len(argv) > 1 else None))
        if not default_prompt:
            parser.print_help(sys.stderr)
            return 2
        # Detectar bandera --no-tts en extras si se pasó en modo rápido
        no_tts = any(x == "--no-tts" for x in extras)
        ns = argparse.Namespace(
            prompt=default_prompt,
            model=None,
            no_tts=no_tts,
            web=False,
            freeform=False,
            web_max=5,
            web_timeout=15,
            gen_estimate=20,
            save=None,
            append=False,
        )
        return cmd_assist(ns)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
