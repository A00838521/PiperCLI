#!/usr/bin/env python3
"""
Piper CLI — asistente estilo Copilot para terminal local.

Comandos:
    assist        Asistente interactivo (respuestas concisas; web opcional)
    agent         Planifica y ejecuta comandos (con asistencia y streaming)
    apply-notes   Aplica archivos sugeridos desde AI_NOTES.md
    fix           Revisa sintaxis y prueba proyectos (inicialmente Python)
    say           Reproduce TTS con Piper (si está disponible)

Ejemplos:
    piper assist "Explica brevemente qué hace Piper"
    piper assist "Compara librerías de scraping" --web
    piper agent  "Inicializa un proyecto con Vite y React"
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import secrets
import base64
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
import threading

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
_CTX: dict[str, Any] | None = None


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


def _tts_on(_args: argparse.Namespace | None = None) -> bool:
    """Control global de TTS por defecto desactivado.
    Activa TTS sólo si PIPER_ENABLE_TTS=1/true/yes o si el caller lo pide explícitamente.
    En cmd_assist también se requiere que no se pase --no-tts.
    """
    v = str(os.environ.get("PIPER_ENABLE_TTS", "0")).lower()
    return v in ("1", "true", "yes")


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

# -------------------- Spinner global ligero (indicador de actividad) --------------------
_SPINNER_STATE = {
    "thread": None,
    "stop": None,
    "paused": False,
    "enabled": True,
}


def _spinner_enabled() -> bool:
    if os.environ.get("PIPER_NO_SPINNER", "0").lower() in ("1", "true", "yes"):
        return False
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


def _spinner_loop(stop_event: threading.Event) -> None:
    symbols = ['⣾', '⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽']
    i = 0
    while not stop_event.is_set():
        try:
            if _SPINNER_STATE.get("paused") or not _SPINNER_STATE.get("enabled", True):
                time.sleep(0.1)
                continue
            sym = symbols[i % len(symbols)]
            i += 1
            # Imprimir en stderr para no mezclar con stdout y mantenerlo pequeño
            sys.stderr.write("\r" + sym + " ")
            sys.stderr.flush()
            time.sleep(0.12)
        except Exception:
            # Si algo falla, salir silenciosamente
            break
    # limpiar rastro del spinner
    try:
        sys.stderr.write("\r  \r")
        sys.stderr.flush()
    except Exception:
        pass


def _spinner_start() -> None:
    if _SPINNER_STATE.get("thread") is not None:
        return
    _SPINNER_STATE["enabled"] = _spinner_enabled()
    if not _SPINNER_STATE["enabled"]:
        return
    stop_event = threading.Event()
    th = threading.Thread(target=_spinner_loop, args=(stop_event,), daemon=True)
    _SPINNER_STATE["stop"] = stop_event
    _SPINNER_STATE["thread"] = th
    _SPINNER_STATE["paused"] = False
    th.start()


def _spinner_stop() -> None:
    ev = _SPINNER_STATE.get("stop")
    th = _SPINNER_STATE.get("thread")
    _SPINNER_STATE["paused"] = True
    if isinstance(ev, threading.Event):
        ev.set()
    if isinstance(th, threading.Thread):
        try:
            th.join(timeout=0.5)
        except Exception:
            pass
    _SPINNER_STATE["thread"] = None
    _SPINNER_STATE["stop"] = None


def _spinner_pause() -> None:
    _SPINNER_STATE["paused"] = True
    # limpiar línea por si quedó el símbolo
    try:
        sys.stderr.write("\r  \r")
        sys.stderr.flush()
    except Exception:
        pass


def _spinner_resume() -> None:
    if _SPINNER_STATE.get("thread") is not None:
        _SPINNER_STATE["paused"] = False

def progress_start(name: str, estimated_seconds: int | None = None) -> None:
    est = int(estimated_seconds or 0)
    _PHASE_STACK.append((name, time.time(), est))
    est_txt = f" ~{est}s" if est else ""
    print(f"⏳ {name}{est_txt}...")
    # Asegurar spinner activo cuando hay fases en progreso
    _spinner_start()


def progress_end() -> None:
    if not _PHASE_STACK:
        return
    name, start, est = _PHASE_STACK.pop()
    dur = time.time() - start
    print(f"✓ {name} — {dur:.1f}s")
    if not _PHASE_STACK:
        # Dejamos el spinner activo globalmente, pero lo pausamos si no hay fases
        _spinner_pause()


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


# -------------------- Contexto inteligente persistente --------------------

def _load_context() -> dict:
    global _CTX
    if _CTX is not None:
        return _CTX
    cfg = get_config() or {}
    ctx = cfg.get("context") or {}
    if not isinstance(ctx, dict):
        ctx = {}
    # Estructura mínima
    ctx.setdefault("version", 1)
    ctx.setdefault("last_run_ts", None)
    ctx.setdefault("runs", [])            # lista de últimos N runs
    ctx.setdefault("tools", {})           # mapa nombre-> {installed: bool, last_checked_ts}
    ctx.setdefault("decisions", {})       # decisiones del usuario (p.ej., instalar git: declined)
    _CTX = ctx
    return ctx


def _save_context() -> None:
    ctx = _load_context()
    cfg = get_config() or {}
    cfg["context"] = ctx
    try:
        save_config(cfg)
    except Exception:
        pass


# -------------------- Seguridad (CTF y API key) --------------------

def _security_section() -> dict:
    cfg = get_config() or {}
    sec = cfg.get("security")
    if not isinstance(sec, dict):
        sec = {}
    return sec


def _security_save(sec: dict) -> None:
    cfg = get_config() or {}
    cfg["security"] = sec
    try:
        save_config(cfg)
    except Exception:
        pass


def _get_server_api_key() -> str | None:
    sec = _security_section()
    key = sec.get("server_api_key")
    return key if isinstance(key, str) and key.strip() else None


def _set_server_api_key(val: str | None) -> None:
    sec = _security_section()
    if val:
        sec["server_api_key"] = str(val).strip()
    else:
        if "server_api_key" in sec:
            sec.pop("server_api_key", None)
    _security_save(sec)


def _ctf_secret_record() -> dict | None:
    sec = _security_section()
    rec = sec.get("ctf_secret")
    return rec if isinstance(rec, dict) else None


def _ctf_set_secret(secret: str) -> None:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 200_000)
    rec = {
        "algo": "pbkdf2_sha256",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "hash_hex": dk.hex(),
        "iters": 200_000,
    }
    sec = _security_section()
    sec["ctf_secret"] = rec
    _security_save(sec)


def _ctf_check_secret(secret: str) -> bool:
    rec = _ctf_secret_record()
    if not rec or (rec.get("algo") != "pbkdf2_sha256"):
        return False
    try:
        salt = base64.b64decode(rec.get("salt_b64") or "")
        iters = int(rec.get("iters") or 200_000)
        target = (rec.get("hash_hex") or "").lower()
        dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iters)
        return dk.hex().lower() == target
    except Exception:
        return False


def _ctf_require_secret(provided: str | None = None) -> bool:
    """Devuelve True si la clave proporcionada o solicitada es válida.
    Busca en: argumento, env PIPER_CTF_KEY, prompt interactivo (getpass)."""
    if _ctf_secret_record() is None:
        print("[ERROR] CTF no está habilitado. Define una clave con: piper ctf set-key")
        return False
    secret = (provided or os.environ.get("PIPER_CTF_KEY") or "").strip()
    if not secret:
        try:
            _spinner_pause()
            secret = getpass.getpass("Clave CTF: ")
        except Exception:
            secret = ""
        finally:
            _spinner_resume()
    if not secret:
        print("[ERROR] No se proporcionó clave CTF")
        return False
    if not _ctf_check_secret(secret):
        print("[ERROR] Clave CTF inválida")
        return False
    return True


def _ctx_mark_tool(name: str, installed: bool) -> None:
    ctx = _load_context()
    tools = ctx.setdefault("tools", {})
    entry = tools.setdefault(name, {})
    entry["installed"] = bool(installed)
    entry["last_checked_ts"] = datetime.now().isoformat(timespec="seconds")


def _ctx_tool_installed(name: str) -> bool:
    ctx = _load_context()
    tools = ctx.get("tools", {})
    entry = tools.get(name) or {}
    return bool(entry.get("installed"))


def _ctx_record_decision(key: str, value: str) -> None:
    ctx = _load_context()
    dec = ctx.setdefault("decisions", {})
    dec[key] = value


def _ctx_get_decision(key: str) -> str | None:
    ctx = _load_context()
    dec = ctx.get("decisions", {})
    v = dec.get(key)
    return v if isinstance(v, str) else None


def _ctx_record_run(cmd: str, args_summary: dict, exit_code: int, extra: dict | None = None) -> None:
    ctx = _load_context()
    run = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "cmd": cmd,
        "args": args_summary,
        "exit": int(exit_code),
    }
    if extra:
        run.update({k: v for k, v in extra.items() if k not in ("args", "exit", "cmd", "ts")})
    runs: list = ctx.setdefault("runs", [])
    runs.append(run)
    # Mantener últimos 100
    if len(runs) > 100:
        del runs[: len(runs) - 100]
    ctx["last_run_ts"] = run["ts"]
    _save_context()


def _ctx_refresh_tools_presence() -> None:
    """Refresca presencia de herramientas comunes en PATH y actualiza contexto.
    Herramientas: git, gh, node, npm, python3, go
    """
    tools = {
        "git": _ensure_tool("git"),
        "gh": _ensure_tool("gh"),
        "node": _ensure_tool("node"),
        "npm": _ensure_tool("npm"),
        "python3": _ensure_tool("python3"),
        "go": _ensure_tool("go"),
    }
    for name, present in tools.items():
        _ctx_mark_tool(name, bool(present))


# -------------------- Entrada interactiva con cancelación q() --------------------

class _UserCanceled(Exception):
    pass


def _ask_input(prompt: str) -> str:
    _spinner_pause()
    try:
        s = input(prompt)
    except EOFError:
        raise _UserCanceled()
    finally:
        _spinner_resume()
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


# -------------------- Intents locales (estado del sistema, carpeta, servicios) --------------------

def _is_system_status_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = [
        "estado del sistema", "estatus del sistema", "estatus actual", "estado actual",
        "uso de cpu", "uso de memoria", "memoria disponible", "espacio en disco",
        "temperatura", "bateria", "batería", "uptime", "tiempo encendido",
    ]
    return any(k in t for k in keys)


def _run_cmd_capture(cmd: list[str], timeout: float = 3.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or proc.stderr or "").strip()
    except Exception:
        return ""


def _system_status_text() -> str:
    # CPU load
    try:
        la1, la5, la15 = os.getloadavg()
        load_txt = f"loadavg: {la1:.2f}/{la5:.2f}/{la15:.2f}"
    except Exception:
        load_txt = "loadavg: n/a"
    # Memoria (macOS: vm_stat)
    mem_txt = "mem: n/a"
    try:
        if platform.system() == "Darwin":
            out = _run_cmd_capture(["vm_stat"])  # páginas de 4096 bytes
            m = re.findall(r"(\w+):\s+(\d+)\.", out)
            stats = {k: int(v) for k, v in m}
            page = 4096
            free = (stats.get("Pages free", 0) + stats.get("Pages speculative", 0)) * page
            active = stats.get("Pages active", 0) * page
            wired = stats.get("Pages wired down", 0) * page
            # Total aproximado
            total_str = _run_cmd_capture(["sysctl", "-n", "hw.memsize"]) or "0"
            total = int(total_str.strip() or "0")
            mem_txt = f"mem: total={total//(1024**3)}GB, libre={(free)//(1024**2)}MB, activa={active//(1024**2)}MB, cableada={wired//(1024**2)}MB"
    except Exception:
        pass
    # Disco
    try:
        du = shutil.disk_usage("/")
        disk_txt = f"disk: usado={du.used//(1024**3)}GB/{du.total//(1024**3)}GB"
    except Exception:
        disk_txt = "disk: n/a"
    # Uptime
    up_txt = _run_cmd_capture(["uptime", "-p"]) or "uptime: n/a"
    # Batería (macOS pmset)
    bat_txt = _run_cmd_capture(["pmset", "-g", "batt"]) if platform.system() == "Darwin" else ""
    if bat_txt:
        # compáctalo
        bat_txt = "bat: " + bat_txt.splitlines()[-1]
    # Temperatura (istats, si existe)
    temp_txt = ""
    if shutil.which("istats"):
        t = _run_cmd_capture(["istats", "--value-only", "CPU temp"]) or ""
        temp_txt = f"temp: {t.strip()}" if t else ""
    parts = [p for p in [load_txt, mem_txt, disk_txt, up_txt, bat_txt, temp_txt] if p]
    return " | ".join(parts)


def _is_create_folder_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = ["crear carpeta", "nueva carpeta", "make folder", "create folder"]
    return any(k in t for k in keys)


def _extract_folder_name(s: str) -> str | None:
    m = re.search(r"['\"]([^'\"]{1,80})['\"]", s)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"carpeta\s+([\w ._-]{1,80})", _normalize_text(s))
    if m2:
        return m2.group(1).strip()
    return None


def _create_folder_in_downloads(name: str) -> tuple[bool, str]:
    safe = re.sub(r"[^A-Za-z0-9._ \-]", "_", name).strip()
    if not safe:
        return False, "Nombre de carpeta inválido."
    # Evitar subrutas
    if "/" in safe or ".." in safe:
        return False, "Nombre de carpeta no debe contener rutas."
    dst = Path.home() / "Downloads" / safe
    try:
        dst.mkdir(parents=True, exist_ok=True)
        return True, f"[OK] Carpeta creada: {dst}"
    except Exception as e:
        return False, f"[ERROR] No se pudo crear carpeta: {e}"


def _is_service_control_query(s: str) -> tuple[bool, str | None]:
    t = _normalize_text(s)
    if "activar servicio" in t or "iniciar servicio" in t or "start service" in t:
        return True, "start"
    if "detener servicio" in t or "desactivar servicio" in t or "stop service" in t:
        return True, "stop"
    return False, None


def _extract_service_name(s: str) -> str | None:
    m = re.search(r"servicio\s+['\"]([^'\"]{1,80})['\"]", s, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"servicio\s+([\w._\-]{1,80})", _normalize_text(s))
    if m2:
        return m2.group(1).strip()
    # fallback: última palabra tipo token simple
    toks = re.findall(r"[A-Za-z0-9._\-]{2,}", s)
    return toks[-1] if toks else None


def _service_control(action: str, name: str) -> tuple[bool, str]:
    if platform.system() == "Darwin" and shutil.which("brew"):
        cmd = ["brew", "services", "start" if action == "start" else "stop", name]
        out = _run_cmd_capture(cmd, timeout=10)
        ok = "Successfully" in out or "already" in out or out != ""
        return ok, out or f"brew services {action} {name}"
    # Linux user services
    if shutil.which("systemctl"):
        cmd = ["systemctl", "--user", "start" if action == "start" else "stop", f"{name}.service"]
        out = _run_cmd_capture(cmd, timeout=10)
        ok = "Started" in out or "Stopped" in out or out != ""
        return ok, out or f"systemctl --user {action} {name}.service"
    return False, "No encontré gestor de servicios compatible (brew/systemctl)."


def _is_find_file_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = ["donde esta", "dónde está", "ubica archivo", "buscar archivo", "encuentra archivo", "find file", "locate file"]
    return any(k in t for k in keys)


# -------------------- Intent local: clima/tiempo (respuestas limpias) --------------------

def _is_weather_query(s: str) -> bool:
    t = _normalize_text(s)
    keys = [
        "clima", "tiempo", "pronostico", "pronóstico", "weather", "forecast",
    ]
    return any(k in t for k in keys)


def _extract_weather_params(s: str) -> tuple[str | None, str]:
    """Devuelve (ciudad, dia) donde dia ∈ {"hoy","mañana"}. Por defecto infiere por texto.
    Heurística simple: busca "en <ciudad>" o comillas; si no, None.
    """
    t = _normalize_text(s)
    # Día
    day = "mañana" if "manana" in t or "mañana" in s.lower() else ("hoy" if "hoy" in t else "mañana")
    # Ciudad: entre comillas
    m = re.search(r"['\"]([^'\"]+)['\"]", s)
    if m:
        return m.group(1).strip(), day
    # después de "en "
    m2 = re.search(r"\ben\s+([\wÁÉÍÓÚÜÑáéíóúüñ .\-]{2,})", s)
    if m2:
        # cortar en signos de pregunta o fin
        city = m2.group(1).strip()
        city = re.split(r"[\?\n]", city)[0].strip()
        return city, day
    # última palabra capitalizada como candidato (arriesgado)
    words = re.findall(r"[A-ZÁÉÍÓÚÜÑ][\wÁÉÍÓÚÜÑáéíóúüñ.\-]+", s)
    if words:
        return words[-1], day
    return None, day


def _fetch_weather_wttr(city: str, day: str, *, timeout: float = 12.0) -> tuple[bool, str]:
    """Obtiene pronóstico desde wttr.in en JSON y devuelve texto legible.
    day: "hoy" o "mañana". Usa índice 0 u 1 del arreglo weather.
    """
    try:
        url = f"https://wttr.in/{quote_plus(city)}?format=j1"
        req = urllib.request.Request(url, headers={"User-Agent": "PiperCLI/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return False, f"No pude obtener el clima ahora mismo ({e})."
    try:
        days = data.get("weather") or []
        idx = 1 if day == "mañana" else 0
        if idx >= len(days):
            idx = min(len(days) - 1, 0)
        d = days[idx]
        date = d.get("date")
        maxC = d.get("maxtempC")
        minC = d.get("mintempC")
        hourly = d.get("hourly") or []
        # seleccionar alrededor del mediodía si existe
        mid = None
        for h in hourly:
            if str(h.get("time", "")) in ("1200", "120", "12:00", "1200.0"):
                mid = h
                break
        if mid is None and hourly:
            mid = hourly[len(hourly)//2]
        desc = (mid.get("weatherDesc", [{}])[0].get("value") if isinstance(mid, dict) else None) or "(sin descripción)"
        precip = (mid.get("chanceofrain") if isinstance(mid, dict) else None) or (mid.get("chanceofprecipitation") if isinstance(mid, dict) else None) or "-"
        windKmph = (mid.get("windspeedKmph") if isinstance(mid, dict) else None) or "-"
        feels = (mid.get("FeelsLikeC") if isinstance(mid, dict) else None) or (mid.get("FeelsLikeC") if isinstance(mid, dict) else None)
        parts = [
            f"Pronóstico para {city} — {day} ({date}):",
            f"- Máx {maxC}°C, Mín {minC}°C",
            f"- Al mediodía: {desc}",
            f"- Lluvia: {precip}%  •  Viento: {windKmph} km/h" + (f"  •  Sensación: {feels}°C" if feels else ""),
            "Fuente: wttr.in (datos agregados)",
        ]
        return True, "\n".join(parts)
    except Exception:
        return False, "No pude interpretar la respuesta del servicio del clima."


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


# -------------------- Inspector de carpeta/proyecto --------------------

def _py_functions_and_imports(text: str) -> tuple[list[str], list[tuple[str,str]]]:
    """Extrae nombres de funciones definidas y relaciones importadas (import x / from a import b)."""
    funcs = re.findall(r"^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text, flags=re.MULTILINE)
    imports: list[tuple[str,str]] = []
    for m in re.finditer(r"^\s*import\s+([A-Za-z0-9_\.]+)", text, flags=re.MULTILINE):
        imports.append((m.group(1), "*"))
    for m in re.finditer(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import\s+([A-Za-z0-9_\*, ]+)", text, flags=re.MULTILINE):
        imports.append((m.group(1), m.group(2)))
    return funcs, imports


def cmd_inspect(args: argparse.Namespace) -> int:
    # Permitir que args.cwd sea None o "" sin reventar
    _cwd_arg = getattr(args, "cwd", None)
    base_in = _cwd_arg if (_cwd_arg and str(_cwd_arg).strip()) else str(Path.cwd())
    base = Path(base_in).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        print(f"[ERROR] Directorio inválido: {base}")
        return 2
    max_files = int(getattr(args, "max_files", 500) or 500)
    max_lines = int(getattr(args, "max_lines", 2000) or 2000)
    print(f"[PLAN] Inspección de {base} (hasta {max_files} archivos)")
    files: list[Path] = []
    try:
        for p in base.rglob("**/*"):
            if len(files) >= max_files:
                break
            if p.is_file():
                files.append(p)
    except Exception:
        pass
    files = sorted(files, key=lambda p: p.suffix + "/" + p.name)
    summary_lines: list[str] = []
    summary_lines.append(f"# Inspector Report\n\n- Carpeta: {base}\n- Archivos analizados: {len(files)}\n")
    # Índice por extensión
    by_ext: dict[str, list[Path]] = {}
    for f in files:
        by_ext.setdefault(f.suffix.lower() or "(sin ext)", []).append(f)
    summary_lines.append("## Conteo por extensión\n")
    for ext, lst in sorted(by_ext.items(), key=lambda kv: (kv[0], len(kv[1]))):
        summary_lines.append(f"- {ext}: {len(lst)}")
    # Detalles Python: funciones e imports + conexiones de módulos locales
    summary_lines.append("\n## Python: funciones e interconexiones\n")
    module_map: dict[str, Path] = {}
    for f in by_ext.get(".py", [])[:max_files]:
        mod = f.stem
        module_map[mod] = f
    edges: list[tuple[str,str]] = []
    for f in by_ext.get(".py", [])[:max_files]:
        try:
            text = "\n".join(f.read_text(encoding="utf-8", errors="ignore").splitlines()[:max_lines])
        except Exception:
            continue
        funcs, imports = _py_functions_and_imports(text)
        summary_lines.append(f"### {f.relative_to(base)}\n- Funciones: {', '.join(funcs) if funcs else '(ninguna)'}")
        if imports:
            summary_lines.append("- Imports:")
            for src, names in imports[:30]:
                summary_lines.append(f"  - {src} :: {names}")
                # Si apunta a un módulo local, registrar arista
                key = src.split(".")[0]
                if key in module_map and module_map[key] != f:
                    edges.append((f.stem, key))
        summary_lines.append("")
    if edges:
        summary_lines.append("## Interconexiones (módulo -> módulo)\n")
        for a, b in sorted(set(edges)):
            summary_lines.append(f"- {a} -> {b}")
    # Intentar resumen con modelo Ollama si disponible
    try:
        # Compactar contexto: top archivos .py, funciones y aristas
        py_files = [str(f.relative_to(base)) for f in by_ext.get(".py", [])[: min(20, len(by_ext.get('.py', [])) )]]
        edge_lines = [f"{a}->{b}" for a,b in sorted(set(edges))][:30]
        context = [
            "Archivos Python (top):" , ", ".join(py_files) or "(ninguno)",
            "Funciones por archivo (recortado):",
        ]
        # Añade primeras funciones por archivo (hasta 10 archivos, 8 funcs cada uno)
        count = 0
        for f in by_ext.get(".py", [])[:10]:
            try:
                t = "\n".join(f.read_text(encoding="utf-8", errors="ignore").splitlines()[:400])
            except Exception:
                continue
            funcs, _imps = _py_functions_and_imports(t)
            context.append(f"- {f.name}: {', '.join(funcs[:8]) if funcs else '(ninguna)'}")
            count += 1
        if edge_lines:
            context.append("Interconexiones (módulo->módulo): ")
            context.append(", ".join(edge_lines))
        ctx = "\n".join(context)
        model = _ensure_model_available(_resolve_model(getattr(args, "model", None)))
        system = {"role":"system","content":(
            "Eres un analista de repos que redacta una sinopsis ejecutiva clara y pragmática. "
            "Con el contexto, explica de qué trata el proyecto, sus capacidades principales, arquitectura a alto nivel y cómo se usa en 6–10 líneas. "
            "Evita listar archivos uno a uno; resume. Responde en español."
        )}
        user = {"role":"user","content":f"Contexto del repo (extracto):\n{ctx}\n\nRedacta la sinopsis."}
        brief = _ollama_chat([system, user], model).strip()
        if brief:
            summary_lines.insert(1, "## Resumen IA\n" + brief + "\n")
    except Exception:
        # Fallback estático si algo falla
        summary_lines.insert(1, "## Resumen IA\nProyecto Piper CLI: asistente local que convierte prompts en acciones (chat, agente que ejecuta comandos, modo CTF seguro, instalación de herramientas, contexto persistente y generación de código con validación). Integra Ollama para modelos LLM, ofrece investigación web opcional, TTS y análisis de proyecto.\n")
    # Guardar
    report_path = base / "Inspector-Report.md"
    try:
        write_file(report_path, "\n".join(summary_lines) + "\n")
        print(f"[OK] Inspector-Report.md generado en {report_path}")
        return 0
    except Exception as e:
        print(f"[ERROR] No se pudo escribir el reporte: {e}")
        return 1


def _wants_web_summary(s: str) -> bool:
    t = _normalize_text(s)
    keys = ["resume", "resumen", "que dice", "que hay", "investiga", "busca", "summary"]
    return any(k in t for k in keys)


def _wants_web_search(s: str) -> bool:
    t = _normalize_text(s)
    keys = [
        "sitios web", "paginas web", "websites", "links", "fuentes",
        "dime", "recomienda", "donde puedo", "donde encontrar", "where can i find",
        "que es", "qué es", "como", "cómo", "tutorial", "guia", "guía", "mejores",
        "comparativa", "review", "latest", "ultimo", "último", "hoy", "noticias",
    ]
    # debe pedir sitios/links y no incluir URLs ya
    return any(k in t for k in keys) and not bool(_extract_urls(s))


# -------------------- Control de servicio Ollama (ON/OFF) --------------------

def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_windows() -> bool:
    return platform.system() == "Windows"


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
        elif _is_windows():
            # Windows: lanzar proceso en background con flags de detach
            log = _ollama_logs_dir() / "ollama.out.log"
            mkdirp(log.parent)
            try:
                DETACHED_PROCESS = 0x00000008
                CREATE_NEW_PROCESS_GROUP = 0x00000200
            except Exception:
                DETACHED_PROCESS = 0
                CREATE_NEW_PROCESS_GROUP = 0
            try:
                with open(log, "ab", buffering=0) as fh:
                    proc = subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=fh,
                        stderr=fh,
                        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
                    )
                return True, f"ollama serve lanzado en background (pid {proc.pid})"
            except Exception as e:
                return False, f"No se pudo iniciar ollama en Windows: {e}"
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
        elif _is_windows():
            # Intentar detener proceso ollama.exe con taskkill
            out = []
            try:
                p = subprocess.run(["taskkill", "/F", "/IM", "ollama.exe"], capture_output=True, text=True)
                out.append(p.stdout or p.stderr or "")
            except Exception:
                pass
            # Fallback: PowerShell Stop-Process
            try:
                p2 = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Process ollama -ErrorAction SilentlyContinue | Stop-Process -Force"], capture_output=True, text=True)
                out.append(p2.stdout or p2.stderr or "")
            except Exception:
                pass
            return True, "; ".join([s.strip() for s in out if s.strip()]) or "ollama detenido"
        else:
            if _exists("systemctl"):
                proc = subprocess.run(["systemctl", "--user", "stop", "ollama.service"], capture_output=True, text=True)
                subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
                return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
            subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
            return True, "ollama detenido"
    except Exception as e:
        return False, f"Error al detener Ollama: {e}"


# -------------------- Piper Server (HTTP local) --------------------

def _server_logs_dir() -> Path:
    return _ollama_logs_dir().parent / "logs"


def _server_pidfile() -> Path:
    return _server_logs_dir() / "piper-server.pid"


class _PiperHTTPHandler:
    def __init__(self, reader, writer, model: str):
        self.reader = reader
        self.writer = writer
        self.model = model

    async def handle(self):
        try:
            data = await self.reader.read(65536)
            req = data.decode("utf-8", errors="ignore")
            # muy simple: solo GET /ping y /ask?prompt=
            first = req.splitlines()[0] if req else ""
            path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/"
            # parse headers mínimos
            headers_in: dict[str, str] = {}
            try:
                lines = req.split("\r\n")
                for ln in lines[1:]:
                    if not ln:
                        break
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        headers_in[k.strip().lower()] = v.strip()
            except Exception:
                pass
            status = "200 OK"
            body = "{}"
            headers = "Content-Type: application/json\r\n"
            # Enforce API key si está configurada
            api_key = _get_server_api_key()
            if api_key:
                # aceptar X-API-Key header o query ?key=
                provided = headers_in.get("x-api-key")
                if not provided:
                    try:
                        from urllib.parse import parse_qs, urlparse
                        q = parse_qs(urlparse(path).query)
                        provided = (q.get("key", [""])[0] or "").strip()
                    except Exception:
                        provided = ""
                if provided != api_key:
                    status = "401 Unauthorized"
                    body = json.dumps({"ok": False, "error": "invalid api key"})
                    resp = (
                        f"HTTP/1.1 {status}\r\n"
                        + headers
                        + f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                        + "Connection: close\r\n\r\n"
                        + body
                    )
                    self.writer.write(resp.encode("utf-8"))
                    await self.writer.drain()
                    return
            if path.startswith("/ping"):
                body = json.dumps({"ok": True, "ts": datetime.now().isoformat(timespec="seconds")})
            elif path.startswith("/ask"):
                # soporta GET /ask?prompt=...
                try:
                    from urllib.parse import parse_qs, urlparse
                    q = parse_qs(urlparse(path).query)
                    prompt = (q.get("prompt", [""])[0] or "").strip()
                except Exception:
                    prompt = ""
                if not prompt:
                    status = "400 Bad Request"
                    body = json.dumps({"ok": False, "error": "missing prompt"})
                else:
                    # Intents rápidos primero (clima)
                    txt = None
                    if _is_weather_query(prompt):
                        city, day = _extract_weather_params(prompt)
                        if city:
                            ok, txt2 = _fetch_weather_wttr(city, day)
                            txt = txt2 if ok else txt2
                    if not txt:
                        # respuesta concisa tipo assist
                        system = {"role": "system", "content": (
                            "Eres un asistente técnico en Piper CLI. Responde conciso y útil. "
                            "Si falta un dato crítico, formula UNA pregunta corta."
                        )}
                        user = {"role": "user", "content": prompt}
                        txt = _ollama_chat([system, user], self.model)
                    body = json.dumps({"ok": True, "text": txt or ""})
            else:
                status = "404 Not Found"
                body = json.dumps({"ok": False, "error": "not found"})
            resp = (
                f"HTTP/1.1 {status}\r\n"
                + headers
                + f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                + "Connection: close\r\n\r\n"
                + body
            )
            self.writer.write(resp.encode("utf-8"))
            await self.writer.drain()
        except Exception:
            try:
                self.writer.close()
            except Exception:
                pass


def _serve_http(host: str, port: int, model: str):
    # Implementación sencilla con asyncio Streams para evitar dependencias
    import asyncio
    async def client_connected(reader, writer):
        handler = _PiperHTTPHandler(reader, writer, model)
        await handler.handle()
    async def main_loop():
        server = await asyncio.start_server(client_connected, host, port)
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"[SERVER] Piper en {addrs}")
        async with server:
            await server.serve_forever()
    asyncio.run(main_loop())


def _server_background_cmd(port: int) -> str:
    py = sys.executable
    this = str(Path(__file__).resolve())
    logdir = _server_logs_dir()
    mkdirp(logdir)
    log = logdir / "piper-server.log"
    return f"nohup {py} {json.dumps(this)} server run --port {port} >>{json.dumps(str(log))} 2>&1 & echo $! > {json.dumps(str(_server_pidfile()))}"


def cmd_server_on(args: argparse.Namespace) -> int:
    port = int(getattr(args, "port", 8787) or 8787)
    # Si ya hay pidfile, informar
    pidf = _server_pidfile()
    if pidf.exists():
        try:
            pid = int(pidf.read_text().strip())
            if pid > 0:
                print(f"[INFO] Piper server ya parece activo (pid {pid}).")
                return 0
        except Exception:
            pass
    cmd = _server_background_cmd(port)
    os.system(cmd)
    print(f"[OK] Piper server iniciado en 127.0.0.1:{port}")
    return 0


def cmd_server_off(_args: argparse.Namespace) -> int:
    pidf = _server_pidfile()
    if pidf.exists():
        try:
            pid = int(pidf.read_text().strip())
            os.kill(pid, 15)
            time.sleep(0.3)
        except Exception:
            pass
        try:
            pidf.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        print("[OK] Piper server detenido")
        return 0
    # Fallback: pkill
    os.system("pkill -f 'piper_cli.py server run'")
    print("[INFO] Intento de detener procesos 'piper server run'")
    return 0


def cmd_server_status(_args: argparse.Namespace) -> int:
    pidf = _server_pidfile()
    if pidf.exists():
        try:
            pid = int(pidf.read_text().strip())
            os.kill(pid, 0)
            print(f"[OK] Piper server activo (pid {pid})")
            return 0
        except Exception:
            pass
    print("[INFO] Piper server no está activo")
    return 1


def cmd_server_run(args: argparse.Namespace) -> int:
    port = int(getattr(args, "port", 8787) or 8787)
    model = _ensure_model_available(_resolve_model(getattr(args, "model", None)))
    # Escribir pidfile
    pidf = _server_pidfile()
    mkdirp(pidf.parent)
    try:
        pidf.write_text(str(os.getpid()))
    except Exception:
        pass
    try:
        _serve_http("127.0.0.1", port, model)
    finally:
        try:
            pidf.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
    return 0


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
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


def scaffold_fastapi(dst: Path, prompt: str) -> None:
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


def scaffold_python(dst: Path, prompt: str) -> None:
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


def scaffold_node(dst: Path, prompt: str) -> None:
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


def scaffold_react(dst: Path, prompt: str) -> None:
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


def scaffold_go(dst: Path, prompt: str) -> None:
    """[DEPRECATED] Esta función ya no se usa (se retiró 'piper project')."""
    pass


# -------------------- Comando principal --------------------

def create_project(prompt: str, name: str | None, base_dir: Path) -> Tuple[Path, str]:
    """[DEPRECATED] Crear proyecto ya no está soportado directamente. Usa 'piper agent'."""
    raise SystemExit("[ERROR] 'piper project' fue retirado. Usa 'piper agent' para automatizar pasos.")


def cmd_project(_args: argparse.Namespace) -> int:
    print("[ERROR] El subcomando 'project' fue retirado. Usa 'piper agent'.")
    return 2


def cmd_assist(args: argparse.Namespace) -> int:
    # --fast fuerza un modelo ligero por ejecución
    if getattr(args, "fast", False):
        args.model = "phi3:mini"
    # Intento local: si el prompt pide la fecha de hoy, responder sin IA
    prompt0 = getattr(args, "prompt", "")
    if _is_date_query(prompt0):
        text = _date_today_text()
        print(text)
        if _tts_on(args) and not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: hora actual
    if _is_time_query(prompt0):
        text = _time_now_text()
        print(text)
        if _tts_on(args) and not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: directorio actual
    if _is_cwd_query(prompt0):
        text = _cwd_text()
        print(text)
        if _tts_on(args) and not args.no_tts:
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
        if _tts_on(args) and not args.no_tts:
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
    # Intento local: estado del sistema
    if _is_system_status_query(prompt0):
        text = _system_status_text()
        print(text)
        if _tts_on(args) and not args.no_tts:
            speak(text)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: crear carpeta en Descargas
    if _is_create_folder_query(prompt0):
        name = _extract_folder_name(prompt0)
        if not name:
            try:
                name = _ask_input("Nombre de la carpeta en Descargas: ")
            except _UserCanceled:
                name = ""
        if not name:
            print("[CANCELADO] Sin nombre de carpeta.")
            return 2
        ok, msg = _create_folder_in_downloads(name)
        print(msg)
        return 0 if ok else 1
    # Intento local: control de servicios
    svc_hit, action = _is_service_control_query(prompt0)
    if svc_hit:
        name = _extract_service_name(prompt0)
        if not name:
            try:
                name = _ask_input("Nombre del servicio: ")
            except _UserCanceled:
                name = ""
        if not name:
            print("[CANCELADO] Sin nombre de servicio.")
            return 2
        ok, out = _service_control(action or "start", name)
        print(out or ("[OK]" if ok else "[ERROR]"))
        return 0 if ok else 1
    # Intento local: búsqueda de archivo (por defecto, busca desde la raíz del sistema)
    if _is_find_file_query(prompt0):
        term = _extract_filename_term(prompt0)
        if not term:
            print("Indica el nombre del archivo, por ejemplo: buscar archivo \"README.md\"")
            return 2
        if getattr(args, "find_current_only", False):
            base = Path.cwd()
        else:
            fb = getattr(args, "find_base", None)
            base = Path(fb).expanduser().resolve() if fb else Path("/")
        results = _search_files(term, base, max_results=20)
        if not results:
            text = f"No encontré '{term}' bajo {base}"
            print(text)
            if _tts_on(args) and not args.no_tts:
                speak(text)
            _maybe_save_output(base, getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
            return 0
        lines = [f"Resultados (máx 20) buscando '{term}' bajo {base}:"] + [" - " + str(p) for p in results]
        text = "\n".join(lines)
        print(text)
        _maybe_save_output(base, getattr(args, "save", None), text, append=bool(getattr(args, "append", False)))
        return 0
    # Intento local: clima/tiempo (evita bucles, respuesta directa)
    if _is_weather_query(prompt0):
        city, day = _extract_weather_params(prompt0)
        if not city:
            try:
                ans = _ask_input("¿Qué ciudad deseas consultar? (ENTER para cancelar): ")
            except _UserCanceled:
                ans = ""
            city = ans.strip() or None
        if not city:
            print("[CANCELADO] Sin ciudad, no puedo responder.")
            return 2
        ok, txt = _fetch_weather_wttr(city, day)
        if not ok:
            # Fallback a búsqueda web simple
            try:
                q = f"clima {day} {city}"
                urls = search_web(q, max_results=3, timeout=float(getattr(args, "web_timeout", 15) or 15))
                md = research_urls(urls[:3]) if urls else ""
            except Exception as e:
                md = f"No se pudo obtener info web: {e}"
            txt = f"No pude obtener datos en tiempo real. A continuación, un resumen web:\n{md}"
        print(txt)
        if _tts_on(args) and not args.no_tts:
            speak(txt)
        _maybe_save_output(Path.cwd(), getattr(args, "save", None), txt, append=bool(getattr(args, "append", False)))
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
        if _tts_on(args) and not args.no_tts and out_text:
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
            if _tts_on(args) and not args.no_tts and out_text:
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
    # Respuesta libre tipo Copilot: concisa por defecto (sin bucle de preguntas)
    model = _ensure_model_available(_resolve_model(args.model))
    system = {
        "role": "system",
        "content": (
            "Eres un asistente técnico integrado en Piper CLI. Responde conciso, claro y accionable. "
            "Evita hacer preguntas a menos que sea estrictamente necesario; si falta un dato crítico, formula UNA pregunta corta. "
            "Si se solicita código o ejemplos, usa Markdown. No confundas Piper CLI con productos de Amazon/Alexa u otros 'Piper'."
        ),
    }
    messages: List[Dict[str, Any]] = [system, {"role": "user", "content": prompt0}]
    gen_est = int(getattr(args, "gen_estimate", 20) or 20)
    out_text = with_progress("Generando respuesta (modelo)", gen_est, _ollama_chat, messages, model)
    print(out_text)
    if _tts_on(args) and not args.no_tts and out_text:
        speak(out_text)
    _maybe_save_output(Path.cwd(), getattr(args, "save", None), out_text, append=bool(getattr(args, "append", False)))
    return 0


def cmd_say(args: argparse.Namespace) -> int:
    said = speak(args.text)
    return 0 if said else 1


def _ensure_tool(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _agent_logs_dir() -> Path:
    p = _ollama_logs_dir().parent  # ~/.local/share/piper-cli
    mkdirp(p / "logs")
    return p / "logs"


def _agent_plan(prompt: str, model: str, os_info: str, web_context: str | None = None) -> dict:
    """Pide al modelo un plan JSON de pasos con comandos shell seguros.
    Forma esperada: {"steps":[{"desc":"...","cmd":"..."}, ...]}
    """
    system = {
        "role": "system",
        "content": (
            "Eres un agente que traduce una instrucción de alto nivel en pasos concretos con comandos shell. "
            "Entorno: " + os_info + ". "
            "Devuelve SOLO JSON válido con la forma {\"steps\":[{\"desc\":\"...\",\"cmd\":\"...\"}]}. "
            "Usa comandos estándar. Evita destructivos como rm -rf sin confirmación."
        ),
    }
    extra = f"\n\nCONTEXTO WEB:\n{web_context}\n" if web_context else ""
    user = {"role": "user", "content": f"Tarea: {prompt}{extra}\nDevuelve solo JSON con los pasos y comandos."}
    data = _ollama_chat_json([system, user], model)
    if isinstance(data, dict) and isinstance(data.get("steps"), list):
        return data
    # Fallback sencillo: pedir de nuevo con ejemplo
    user2 = {"role": "user", "content": (
        f"Tarea: {prompt}\n"
        "Forma exacta: {\"steps\":[{\"desc\":\"crear carpeta\",\"cmd\":\"mkdir -p nueva\"}]}\n"
        "Devuelve solo JSON."
    )}
    data2 = _ollama_chat_json([system, user2], model)
    if isinstance(data2, dict) and isinstance(data2.get("steps"), list):
        return data2
    return {"steps": []}


def _run_shell(cmd: str, cwd: Path, background: bool, *, stream: bool = True) -> tuple[int, str]:
    cwd = cwd.resolve()
    if background:
        logdir = _agent_logs_dir()
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        log = logdir / f"agent-{ts}.log"
        # nohup background
        full = f"nohup bash -lc {json.dumps(cmd)} >>{json.dumps(str(log))} 2>&1 &"
        code = os.system(full)
        return (0 if code == 0 else 1), f"[BG] {cmd}\nLogs: {log}"
    try:
        if stream:
            # Adjuntar IO al TTY para permitir interacción en vivo
            _spinner_pause()
            try:
                code = subprocess.call(["bash", "-lc", cmd], cwd=str(cwd))
            finally:
                _spinner_resume()
            return int(code), ""
        else:
            proc = subprocess.run(["bash", "-lc", cmd], cwd=str(cwd), capture_output=True, text=True)
            out = (proc.stdout or "") + (proc.stderr or "")
            return proc.returncode, out.strip()
    except Exception as e:
        return 1, f"Error al ejecutar: {e}"


def _render_agent_tree(steps: list[dict], *, cwd: Path, background: bool) -> str:
    """Devuelve una representación en árbol del plan del agente.
    Estructura:
    Agent plan (N pasos)
    └── Ejecutará en: <cwd> (foreground|background)
        ├── 1. <desc>
        │   └── $ <cmd>
        └── ...
    """
    lines: list[str] = []
    n = len(steps)
    mode = "background" if background else "foreground"
    lines.append(f"Agent plan ({n} paso{'s' if n != 1 else ''})")
    lines.append(f"└── Ejecutará en: {str(cwd)} ({mode})")
    if not steps:
        return "\n".join(lines)
    for idx, st in enumerate(steps, 1):
        is_last = (idx == n)
        branch = "└── " if is_last else "├── "
        subpref = "    " if is_last else "│   "
        desc = st.get("desc", "(sin desc)")
        cmd = st.get("cmd", "")
        lines.append(f"{subpref}{branch}{idx}. {desc}")
        if cmd:
            lines.append(f"{subpref}    └── $ {cmd}")
    return "\n".join(lines)


def _first_token(cmd: str) -> str:
    """Extrae el primer comando ejecutable del string shell.
    - Ignora asignaciones (var=...)
    - Si usa sustitución $(), intenta extraer el comando interno
    - Usa shlex para tokenizar cuando sea posible
    """
    s = cmd.strip()
    if not s:
        return ""
    # Detectar asignación al inicio: var=... o export VAR=...
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", s) or s.startswith("export "):
        # Intentar capturar comando dentro de $()
        m = re.search(r"\$\(([^\s)]+)", s)
        if m:
            return m.group(1)
        # Como fallback, buscar después del primer espacio
        parts = s.split(None, 1)
        if len(parts) == 2:
            return _first_token(parts[1])
        return ""
    # Backticks `cmd`
    m2 = re.search(r"`([^\s`]+)", s)
    if m2:
        return m2.group(1)
    # $() sustitución
    m3 = re.search(r"\$\(([^\s)]+)", s)
    if m3:
        return m3.group(1)
    # shlex tokenización básica
    try:
        import shlex
        toks = shlex.split(s)
        return toks[0] if toks else ""
    except Exception:
        return s.split()[0]


def _is_known_command(token: str) -> bool:
    if not token:
        return False
    builtins = {"bash", "sh", "cd", "mkdir", "echo", "ls", "pwd", "cp", "mv", "rm", "cat", "python", "python3"}
    return token in builtins or _ensure_tool(token)


def _build_allowed_commands(steps: list[dict]) -> set[str]:
    allowed = {
        "bash", "sh", "echo", "cd", "mkdir", "rm", "cp", "mv", "ls", "pwd",
        "pgrep", "ps", "pkill", "kill", "lsof", "grep", "awk", "sed", "find",
        "npm", "npx", "yarn", "pnpm", "node", "vue", "vite",
        "git", "gh", "brew", "python", "python3",
    }
    for st in steps:
        c = st.get("cmd") or ""
        tok = _first_token(c)
        if tok:
            allowed.add(tok)
    return allowed


def _ollama_chat_json_quick(messages: List[Dict[str, Any]], model: str, *, timeout: float = 30.0) -> Dict[str, Any]:
    """Variante rápida de _ollama_chat_json con timeout configurable y una sola ruta preferente.
    Intenta primero /v1/chat/completions con response_format json_object y luego /api/chat con format=json.
    """
    host = _ollama_host()
    # Intento OpenAI compatible
    v1_chat_url = f"{host}/v1/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    try:
        obj = _post_json(v1_chat_url, payload, timeout=timeout)
        choices = obj.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            content = (msg.get("content") or "").strip()
            parsed = _extract_json_from_text(content)
            if parsed is not None:
                return parsed
    except Exception:
        pass
    # Fallback Ollama /api/chat format=json
    chat_url = f"{host}/api/chat"
    payload2 = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    try:
        obj2 = _post_json(chat_url, payload2, timeout=timeout)
        msg = obj2.get("message") or {}
        content = (msg.get("content") or obj2.get("response") or "").strip()
        parsed = _extract_json_from_text(content)
        if parsed is not None:
            return parsed
    except Exception:
        pass
    return {}


def _agent_suggest_alternatives(cmd: str, error_text: str, model: str, os_info: str, prompt_context: str | None = None, *, goal: str | None = None, allowed: set[str] | None = None, timeout: float = 30.0) -> dict:
    """Pide al modelo alternativas de comando para resolver un fallo.
    Forma: {"alternatives":[{"desc":"...","cmd":"..."}]}
    Incluye el error y un resumen opcional de investigación web.
    """
    system = {
        "role": "system",
        "content": (
            "Eres un asistente técnico estricto. Dado un comando fallido, sugiere de 1 a 3 alternativas DIRECTAMENTE relevantes, "
            "con comandos shell exactos y seguros. NO propongas abrir sitios, apps gráficas ni comandos ajenos al contexto. "
            "Mantente en el objetivo y el sistema operativo. Devuelve SOLO JSON válido: {\"alternatives\":[{\"desc\":\"...\",\"cmd\":\"...\"}]}."
        ),
    }
    policy = ""
    if allowed:
        policy = "\nComandos permitidos prioritarios: " + ", ".join(sorted(list(allowed))[:20]) + "."
    goal_line = f"\nObjetivo: {goal}" if goal else ""
    extra = f"\n\nContexto web:\n{prompt_context}\n" if prompt_context else ""
    user = {"role": "user", "content": f"OS: {os_info}{goal_line}\nComando fallido: {cmd}\nError:\n{error_text}{policy}{extra}\nResponde SOLO con el JSON solicitado."}
    data = _ollama_chat_json_quick([system, user], model, timeout=timeout)
    if isinstance(data, dict) and isinstance(data.get("alternatives"), list):
        return data
    # Fallback: pedir de nuevo con ejemplo
    user2 = {"role": "user", "content": (
        f"OS: {os_info}\nComando: {cmd}\nError:\n{error_text}\n"
        "Ejemplo de salida esperada: {\"alternatives\":[{\"desc\":\"instalar dependencia\",\"cmd\":\"brew install <tool>\"}]}\n"
        "Ahora devuelve SOLO JSON con alternativas viables."
    )}
    data2 = _ollama_chat_json_quick([system, user2], model, timeout=timeout)
    if isinstance(data2, dict) and isinstance(data2.get("alternatives"), list):
        out = data2
    else:
        out = {"alternatives": []}
    # Filtrado: mantener alternativas que respeten allowed y que no abran navegadores o comandos ajenos
    alts_in = out.get("alternatives", []) if isinstance(out, dict) else []
    alts_out = []
    for a in alts_in:
        if not isinstance(a, dict):
            continue
        c = (a.get("cmd") or "").strip()
        if not c:
            continue
        tok = _first_token(c)
        if allowed and tok and tok not in allowed:
            continue
        # Bloquear 'open http', 'say', u otros que no sean shell útil
        low = c.lower()
        if low.startswith("open http") or low.startswith("open https") or low.startswith("say "):
            continue
        alts_out.append(a)
        if len(alts_out) >= 3:
            break
    return {"alternatives": alts_out}


def cmd_agent(args: argparse.Namespace) -> int:
    # Modelo
    if getattr(args, "fast", False):
        args.model = "phi3:mini"
    model = _ensure_model_available(_resolve_model(args.model))
    # Contexto OS
    os_info = _os_info_text().replace("\n", "; ")
    # CWD para ejecución
    workdir = Path(args.cwd).expanduser().resolve() if getattr(args, "cwd", None) else Path.cwd()
    # Contexto web opcional
    web_ctx = None
    if getattr(args, "web", False):
        try:
            urls = with_progress("Buscando sitios en la web", 6, search_web, args.prompt, max_results=int(getattr(args, "web_max", 5) or 5), timeout=float(getattr(args, "web_timeout", 15) or 15))
        except Exception:
            urls = []
        if not urls:
            try:
                urls = with_progress("Sugerencias de sitios (modelo)", 8, llm_suggest_urls, args.prompt, model, count=int(getattr(args, "web_max", 5) or 5))
            except Exception:
                urls = []
        if urls:
            try:
                est = min(5 * len(urls[: int(getattr(args, "web_max", 5) or 5)]), 25)
                web_ctx = with_progress("Investigación web (resumen)", est, research_urls, urls[: int(getattr(args, "web_max", 5) or 5)], timeout=float(getattr(args, "web_timeout", 15) or 15))
            except Exception:
                web_ctx = None
    # Obtener plan
    plan = with_progress("Planificando con modelo", 8, _agent_plan, args.prompt, model, os_info, web_ctx)
    # Inferir carpeta destino implícita: si el prompt incluye 'crear una carpeta' y un nombre <> usarla como cwd para pasos siguientes
    implicit_dir: Path | None = None
    normp = _normalize_text(args.prompt)
    m_dir = re.search(r"crear (?:una )?carpeta (?:en )?(?:downloads|descargas)?\s*['\"]?([\w._\-]{3,40})['\"]?", normp)
    if m_dir:
        raw = m_dir.group(1).strip()
        base = Path.home() / "Downloads" if "downloads" in normp or "descargas" in normp else workdir
        implicit_dir = (base / raw).resolve()
    # Ajustar pasos: si se detectó carpeta y futuros comandos no especifican ruta absoluta, prefijar (sólo mkdir inicial y luego trabajar dentro)
    if implicit_dir:
        for st in plan.get("steps", []):
            c = (st.get("cmd") or "").strip()
            # Si es mkdir de la carpeta destino, mantener; si es comando de creación de venv/archivo sin ruta usar implicit_dir
            if c.startswith("python") or c.startswith("python3") or c.startswith("pip") or re.match(r"touch \w", c) or re.match(r"nano \w", c):
                # Prefijar cd si no estamos ya dentro; se manejará luego
                pass  # Lo gestionaremos al ejecutar
    steps = plan.get("steps", []) if isinstance(plan, dict) else []
    if not steps:
        print("[ERROR] El modelo no devolvió un plan ejecutable.")
        return 1

    # Mostrar plan como árbol y confirmar
    tree = _render_agent_tree(steps, cwd=workdir, background=bool(getattr(args, "background", False)))
    print("\n" + tree + "\n")

    if getattr(args, "dry_run", False):
        print("[DRY-RUN] Vista previa del plan mostrada. No se ejecutó ningún comando.")
        return 0
    if not getattr(args, "yes", False):
        try:
            ans = _ask_input("¿Deseas proceder con la ejecución de estos comandos? (y/N): ").lower()
        except _UserCanceled:
            ans = ""
        if ans not in ("y", "s", "yes", "si"):
            print("[CANCELADO] Ejecución abortada por el usuario.")
            return 130

    # Verificar herramientas clave según plan
    # Necesidades de herramientas y contexto
    need_git = any("git" in (st.get("cmd") or "") for st in steps)
    need_gh = any((st.get("cmd") or "").strip().startswith("gh ") or " gh " in (st.get("cmd") or " ") for st in steps)
    need_node = any((st.get("cmd") or "").strip().startswith("node ") or " node " in (st.get("cmd") or " ") for st in steps)
    need_npm = any((st.get("cmd") or "").strip().startswith("npm ") or " npm " in (st.get("cmd") or " ") for st in steps)
    need_go = any((st.get("cmd") or "").strip().startswith("go ") or " go " in (st.get("cmd") or " ") for st in steps)
    need_py = any(
        (st.get("cmd") or "").strip().startswith("python3 ") or " python3 " in (st.get("cmd") or " ") or " pip " in (st.get("cmd") or " ")
        for st in steps
    )

    # Marcar estado actual al contexto (detección rápida)
    for t in ("git", "gh", "node", "npm", "python3", "go"):
        _ctx_mark_tool(t, _ensure_tool(t))

    # Git
    if need_git and not _ensure_tool("git"):
        # Consultar contexto antes de preguntar
        if _ctx_tool_installed("git"):
            print("[CTX] Contexto indica que 'git' está instalado previamente. Continuando sin instalar.")
        else:
            prior = _ctx_get_decision("install.git")
            consent: bool
            if getattr(args, "yes", False):
                print("[CTX] Usando -y: se procederá sin preguntar a instalar 'git'.")
                consent = True
                _ctx_record_decision("install.git", "accepted")
            elif prior == "declined":
                print("[CTX] Recordada decisión previa: install.git=declined; no se preguntará.")
                consent = False
            elif prior == "accepted":
                print("[CTX] Recordada decisión previa: install.git=accepted; se procederá sin preguntar.")
                consent = True
            elif prior == "declined":
                print("[CTX] Se había rechazado instalar 'git' anteriormente. Omitiendo prompt.")
                consent = False
            else:
                try:
                    ans = _ask_input("No se encontró 'git'. ¿Deseas instalarlo con Homebrew? (y/N): ").lower()
                except _UserCanceled:
                    ans = ""
                consent = ans in ("y", "s", "yes", "si")
                _ctx_record_decision("install.git", "accepted" if consent else "declined")
            if consent:
                print("[INFO] Instalando git via brew...")
                code, out = _run_shell("brew install git", workdir, background=False, stream=bool(getattr(args, "stream", True)))
                print(out)
                if code == 0 and _ensure_tool("git"):
                    _ctx_mark_tool("git", True)
                if code != 0:
                    print("[WARN] No se pudo instalar git automáticamente.")
            else:
                print("[INFO] Omitiendo instalación de git.")

    # GitHub CLI (gh)
    if need_gh and not _ensure_tool("gh"):
        if _ctx_tool_installed("gh"):
            print("[CTX] Contexto indica que 'gh' está instalado previamente. Continuando sin instalar.")
        else:
            prior = _ctx_get_decision("install.gh")
            consent: bool
            if getattr(args, "yes", False):
                print("[CTX] Usando -y: se procederá sin preguntar a instalar 'gh'.")
                consent = True
                _ctx_record_decision("install.gh", "accepted")
            elif prior == "declined":
                print("[CTX] Recordada decisión previa: install.gh=declined; no se preguntará.")
                consent = False
            elif prior == "accepted":
                print("[CTX] Recordada decisión previa: install.gh=accepted; se procederá sin preguntar.")
                consent = True
            else:
                try:
                    ans = _ask_input("No se encontró 'gh' (GitHub CLI). ¿Instalar con Homebrew? (y/N): ").lower()
                except _UserCanceled:
                    ans = ""
                consent = ans in ("y", "s", "yes", "si")
                _ctx_record_decision("install.gh", "accepted" if consent else "declined")
            if consent:
                print("[INFO] Instalando gh via brew...")
                code, out = _run_shell("brew install gh", workdir, background=False, stream=bool(getattr(args, "stream", True)))
                print(out)
                if code == 0 and _ensure_tool("gh"):
                    _ctx_mark_tool("gh", True)
                if code != 0:
                    print("[WARN] No se pudo instalar gh automáticamente.")
            else:
                print("[INFO] Omitiendo instalación de gh.")

    # Node.js / npm
    if (need_node or need_npm) and not _ensure_tool("node"):
        if _ctx_tool_installed("node"):
            print("[CTX] Contexto indica que 'node' está instalado previamente. Continuando.")
        else:
            prior = _ctx_get_decision("install.node")
            if getattr(args, "yes", False):
                print("[CTX] Usando -y: se procederá sin preguntar a instalar 'node'.")
                consent = True
                _ctx_record_decision("install.node", "accepted")
            elif prior == "declined":
                print("[CTX] Recordada decisión previa: install.node=declined; no se preguntará.")
                consent = False
            elif prior == "accepted":
                print("[CTX] Recordada decisión previa: install.node=accepted; se procederá sin preguntar.")
                consent = True
            else:
                try:
                    ans = _ask_input("No se encontró 'node'. ¿Instalar con Homebrew? (y/N): ").lower()
                except _UserCanceled:
                    ans = ""
                consent = ans in ("y", "s", "yes", "si")
                _ctx_record_decision("install.node", "accepted" if consent else "declined")
            if consent:
                print("[INFO] Instalando node via brew...")
                code, out = _run_shell("brew install node", workdir, background=False, stream=bool(getattr(args, "stream", True)))
                print(out)
                if code == 0 and _ensure_tool("node"):
                    _ctx_mark_tool("node", True)
                    _ctx_mark_tool("npm", _ensure_tool("npm"))
                if code != 0:
                    print("[WARN] No se pudo instalar node automáticamente.")
            else:
                print("[INFO] Omitiendo instalación de node.")

    # Go
    if need_go and not _ensure_tool("go"):
        if _ctx_tool_installed("go"):
            print("[CTX] Contexto indica que 'go' está instalado previamente. Continuando.")
        else:
            prior = _ctx_get_decision("install.go")
            if getattr(args, "yes", False):
                print("[CTX] Usando -y: se procederá sin preguntar a instalar 'go'.")
                consent = True
                _ctx_record_decision("install.go", "accepted")
            elif prior == "declined":
                print("[CTX] Recordada decisión previa: install.go=declined; no se preguntará.")
                consent = False
            elif prior == "accepted":
                print("[CTX] Recordada decisión previa: install.go=accepted; se procederá sin preguntar.")
                consent = True
            else:
                try:
                    ans = _ask_input("No se encontró 'go'. ¿Instalar con Homebrew? (y/N): ").lower()
                except _UserCanceled:
                    ans = ""
                consent = ans in ("y", "s", "yes", "si")
                _ctx_record_decision("install.go", "accepted" if consent else "declined")
            if consent:
                print("[INFO] Instalando go via brew...")
                code, out = _run_shell("brew install go", workdir, background=False, stream=bool(getattr(args, "stream", True)))
                print(out)
                if code == 0 and _ensure_tool("go"):
                    _ctx_mark_tool("go", True)
                if code != 0:
                    print("[WARN] No se pudo instalar go automáticamente.")
            else:
                print("[INFO] Omitiendo instalación de go.")

    # Python3
    if need_py and not _ensure_tool("python3"):
        if _ctx_tool_installed("python3"):
            print("[CTX] Contexto indica que 'python3' está instalado previamente. Continuando.")
        else:
            prior = _ctx_get_decision("install.python3")
            if getattr(args, "yes", False):
                print("[CTX] Usando -y: se procederá sin preguntar a instalar 'python3'.")
                consent = True
                _ctx_record_decision("install.python3", "accepted")
            elif prior == "declined":
                print("[CTX] Recordada decisión previa: install.python3=declined; no se preguntará.")
                consent = False
            elif prior == "accepted":
                print("[CTX] Recordada decisión previa: install.python3=accepted; se procederá sin preguntar.")
                consent = True
            else:
                try:
                    ans = _ask_input("No se encontró 'python3'. ¿Instalar con Homebrew? (y/N): ").lower()
                except _UserCanceled:
                    ans = ""
                consent = ans in ("y", "s", "yes", "si")
                _ctx_record_decision("install.python3", "accepted" if consent else "declined")
            if consent:
                print("[INFO] Instalando python3 via brew...")
                code, out = _run_shell("brew install python", workdir, background=False, stream=bool(getattr(args, "stream", True)))
                print(out)
                if code == 0 and _ensure_tool("python3"):
                    _ctx_mark_tool("python3", True)
                if code != 0:
                    print("[WARN] No se pudo instalar python3 automáticamente.")
            else:
                print("[INFO] Omitiendo instalación de python3.")

    # Ejecutar pasos
    any_fail = False
    allowed_cmds = _build_allowed_commands(steps)
    assist_timeout = int(getattr(args, "assist_timeout", 30) or 30)
    # Seguimiento de venv y archivos
    venv_dir: Path | None = None
    last_py_file: Path | None = None
    saw_cd: bool = False
    preferred_dir: Path | None = None

    def _venv_bin(name: str) -> str | None:
        if venv_dir is None:
            return None
        p = venv_dir / "bin" / name
        return str(p) if p.exists() else None

    def _rewrite_for_venv(c: str) -> str:
        if venv_dir is None:
            return c
        # Reescribir 'pip', 'python', 'python3' al binario del venv si existen
        toks = c.strip().split()
        if not toks:
            return c
        head = toks[0]
        tail = " ".join(toks[1:])
        if head in ("pip", "pip3"):
            vb = _venv_bin("pip") or _venv_bin("pip3")
            if vb:
                return vb + (" " + tail if tail else "")
        if head in ("python", "python3"):
            vb = _venv_bin("python") or _venv_bin("python3")
            if vb:
                return vb + (" " + tail if tail else "")
        # Caso 'python -m pip install ...'
        if c.startswith("python -m pip") or c.startswith("python3 -m pip"):
            vb = _venv_bin("python") or _venv_bin("python3")
            if vb:
                return vb + c[c.find(" "):]
        return c

    def _extract_python_block(text: str) -> str | None:
        # Busca ```python ... ```
        m = re.search(r"```python\s+([\s\S]+?)```", text, flags=re.IGNORECASE)
        if m:
            return m.group(1).strip()
        # Fallback: cualquier bloque ``` ... ```
        m2 = re.search(r"```\s+([\s\S]+?)```", text)
        if m2:
            return m2.group(1).strip()
        return None

    def _maybe_generate_code(prompt_text: str, file_path: Path) -> bool:
        """Genera código automáticamente según el prompt si detectamos un patrón conocido.
        Devuelve True si se escribió el archivo.
        """
        pt = _normalize_text(prompt_text)
        out = None
        # Inspiración web breve (no copiar código): buscar si hay término algoritmo
        algo_term = None
        for key in ["delaunay","bfs","dfs","a*","a star","dijkstra","quicksort","merge sort","mergesort","astar","k-means","kmeans"]:
            if key.replace(" ", "") in pt.replace(" ", ""):
                algo_term = key
                break
        web_inspo = ""
        if algo_term and getattr(args, "auto_code", True):
            try:
                q = f"python {algo_term} algorithm explanation"
                urls = search_web(q, max_results=3, timeout=10)
                if urls:
                    web_inspo = research_urls(urls[:2])[:1000]
            except Exception:
                web_inspo = ""
        def _header(doc: str) -> str:
            if not web_inspo:
                return doc
            lines = ["# " + ln[:160] for ln in web_inspo.splitlines() if ln.strip()]
            if len(lines) > 15:
                lines = lines[:15]
            return doc + "\n# Contexto (resumen web, sin código literal):\n" + "\n".join(lines) + "\n"
        # Plantillas ampliadas
        if algo_term and algo_term.startswith("delaunay"):
            out = _header(
                "#!/usr/bin/env python3\n"
                "\"\"\"Triangulación de Delaunay - ejemplo autocontenido con matplotlib.\n\n"
                "Requisitos: scipy, numpy, matplotlib (instálalos en tu venv).\n\"\"\"\n\n"
                "import numpy as np\n"
                "import matplotlib.pyplot as plt\n"
                "from scipy.spatial import Delaunay\n\n"
                "def demo_points():\n"
                "    # Conjunto de puntos 2D (puedes ajustarlos)\n"
                "    return np.array([\n"
                "        [1.0, 1.0],\n"
                "        [3.0, 0.5],\n"
                "        [5.0, 4.0],\n"
                "        [7.0, 6.0],\n"
                "        [2.0, 4.0],\n"
                "        [6.0, 2.0],\n"
                "        [4.0, 3.0],\n"
                "        [3.5, 5.5],\n"
                "    ])\n\n"
                "def plot_delaunay(points: np.ndarray) -> None:\n"
                "    \"\"\"Calcula la triangulación de Delaunay y grafica puntos y aristas.\"\"\"\n"
                "    tri = Delaunay(points)\n"
                "    fig, ax = plt.subplots(figsize=(6, 5))\n"
                "    ax.plot(points[:, 0], points[:, 1], 'ko', label='Puntos')\n"
                "    for simplex in tri.simplices:\n"
                "        triangle = np.vstack([points[simplex], points[simplex[0]]])\n"
                "        ax.plot(triangle[:, 0], triangle[:, 1], '-', color='#1f77b4', linewidth=1.8)\n"
                "    ax.set_title('Triangulación de Delaunay')\n"
                "    ax.set_xlabel('x')\n"
                "    ax.set_ylabel('y')\n"
                "    ax.set_aspect('equal', adjustable='box')\n"
                "    ax.grid(True, alpha=0.3)\n"
                "    ax.legend(loc='best')\n"
                "    plt.tight_layout()\n"
                "    plt.show()\n\n"
                "if __name__ == '__main__':\n"
                "    pts = demo_points()\n"
                "    plot_delaunay(pts)\n"
            )
        elif algo_term in ("quicksort","mergesort","merge sort"):
            out = _header(
                "#!/usr/bin/env python3\n"
                "\"\"\"Implementación educativa de QuickSort y MergeSort con pruebas simples.\n\n"
                "Evitar peor caso usando pivote medio; MergeSort estable.\n\"\"\"\n\n"
                "from __future__ import annotations\n"
                "import random\n\n"
                "def quicksort(arr):\n"
                "    if len(arr) < 2: return arr[:]\n"
                "    pivot = arr[len(arr)//2]\n"
                "    left = [x for x in arr if x < pivot]\n"
                "    mid  = [x for x in arr if x == pivot]\n"
                "    right= [x for x in arr if x > pivot]\n"
                "    return quicksort(left) + mid + quicksort(right)\n\n"
                "def mergesort(arr):\n"
                "    if len(arr) < 2: return arr[:]\n"
                "    m = len(arr)//2\n"
                "    return _merge(mergesort(arr[:m]), mergesort(arr[m:]))\n\n"
                "def _merge(a,b):\n"
                "    i=j=0; out=[]\n"
                "    while i < len(a) and j < len(b):\n"
                "        if a[i] <= b[j]: out.append(a[i]); i+=1\n"
                "        else: out.append(b[j]); j+=1\n"
                "    out.extend(a[i:]); out.extend(b[j:]); return out\n\n"
                "if __name__=='__main__':\n"
                "    data = [random.randint(0,50) for _ in range(15)]\n"
                "    print('Original', data)\n"
                "    print('QuickSort', quicksort(data))\n"
                "    print('MergeSort', mergesort(data))\n"
            )
        elif algo_term in ("bfs","dfs"):
            out = _header(
                "#!/usr/bin/env python3\n"
                "\"\"\"BFS y DFS sobre grafo no dirigido representado con listas de adyacencia.\n\"\"\"\n\n"
                "from collections import deque\n\n"
                "def bfs(graph, start):\n"
                "    visited=set([start]); order=[]; q=deque([start])\n"
                "    while q:\n"
                "        v=q.popleft(); order.append(v)\n"
                "        for w in graph.get(v,[]):\n"
                "            if w not in visited:\n"
                "                visited.add(w); q.append(w)\n"
                "    return order\n\n"
                "def dfs(graph, start):\n"
                "    visited=set(); order=[]\n"
                "    def _rec(v):\n"
                "        visited.add(v); order.append(v)\n"
                "        for w in graph.get(v,[]):\n"
                "            if w not in visited: _rec(w)\n"
                "    _rec(start); return order\n\n"
                "if __name__=='__main__':\n"
                "    g={'A':['B','C'],'B':['D'],'C':['E'],'D':[],'E':[]}\n"
                "    print('BFS', bfs(g,'A'))\n"
                "    print('DFS', dfs(g,'A'))\n"
            )
        elif algo_term in ("dijkstra","a*","astar","a star"):
            out = _header(
                "#!/usr/bin/env python3\n"
                "\"\"\"Dijkstra y A* (heurística Manhattan) sobre grafo ponderado.\n\"\"\"\n\n"
                "import heapq\n\n"
                "def dijkstra(graph, start):\n"
                "    dist={start:0}; pq=[(0,start)]; prev={}\n"
                "    while pq:\n"
                "        d,v=heapq.heappop(pq)\n"
                "        if d>dist.get(v,1e18): continue\n"
                "        for w,c in graph.get(v,[]):\n"
                "            nd=d+c\n"
                "            if nd<dist.get(w,1e18):\n"
                "                dist[w]=nd; prev[w]=v; heapq.heappush(pq,(nd,w))\n"
                "    return dist, prev\n\n"
                "def heuristic(a,b): x1,y1=a; x2,y2=b; return abs(x1-x2)+abs(y1-y2)\n\n"
                "def astar(graph, start, goal):\n"
                "    open=[(0,start)]; g={start:0}; came={}\n"
                "    while open:\n"
                "        _,current=heapq.heappop(open)\n"
                "        if current==goal: break\n"
                "        for neigh,cost in graph.get(current,[]):\n"
                "            tentative=g[current]+cost\n"
                "            if tentative < g.get(neigh,1e18):\n"
                "                g[neigh]=tentative; f=tentative+heuristic(neigh,goal); heapq.heappush(open,(f,neigh)); came[neigh]=current\n"
                "    return g, came\n\n"
                "if __name__=='__main__':\n"
                "    G={(0,0):[((1,0),1),((0,1),1)],(1,0):[((1,1),1)],(0,1):[((1,1),1)],(1,1):[]}\n"
                "    print('Dijkstra', dijkstra(G,(0,0))[0])\n"
                "    print('A*', astar(G,(0,0),(1,1))[0])\n"
            )
        if out:
            write_file(file_path, out + "\n")
            print(f"[OK] Código generado automáticamente en {file_path.name}")
            return True
        return False
    for i, st in enumerate(steps, 1):
        desc = st.get("desc") or f"paso {i}"
        cmd = st.get("cmd") or ""
        if not cmd:
            print(f"[SKIP] {desc}: no hay comando")
            continue
        # Si tenemos implicit_dir y el comando crea venv/archivo, asegurarnos de que la carpeta exista y operar dentro
        if implicit_dir and not implicit_dir.exists() and ("mkdir" in cmd and str(implicit_dir.name) in cmd):
            # Crear carpeta explícitamente aquí
            try:
                implicit_dir.mkdir(parents=True, exist_ok=True)
                print(f"[OK] Carpeta implícita creada: {implicit_dir}")
            except Exception as e:
                print(f"[ERROR] No se pudo crear carpeta implícita {implicit_dir}: {e}")
        # Cambiar workdir dinámicamente tras creación
        if implicit_dir and implicit_dir.exists():
            workdir = implicit_dir
        # Detectar 'cd <path>' para cambiar directorio de trabajo
        m_cd = re.match(r"cd\s+(.+)$", cmd)
        if m_cd:
            newdir = (workdir / m_cd.group(1)).expanduser().resolve()
            if newdir.exists() and newdir.is_dir():
                workdir = newdir
                saw_cd = True
                print(f"[CTX] cwd -> {workdir}")
                continue
        # Detectar creación de venv para reescrituras siguientes
        m_venv = re.match(r"python3?\s+-m\s+venv\s+([\w./\-]+)", cmd)
        if m_venv:
            vdir = (workdir / m_venv.group(1)).expanduser().resolve()
            venv_dir = vdir
        # Recordar mkdir como preferencia de carpeta si no habrá 'cd'
        m_mkdir = re.match(r"mkdir\s+-p\s+(.+)$", cmd)
        if m_mkdir and not saw_cd:
            preferred_dir = (workdir / m_mkdir.group(1)).expanduser().resolve()
        # Evitar 'source venv/bin/activate' (no persiste entre subprocess); usaremos binarios del venv directamente
        if " activate" in cmd and cmd.strip().startswith("source ") and \
           ("/bin/activate" in cmd or cmd.endswith("activate")):
            print("[INFO] Omitiendo 'source' (subshell). Usaré binarios del venv para pip/python.")
            continue
        # Recordar último archivo .py si se toca/edita
        m_touch = re.match(r"touch\s+([^\s]+\.py)\s*$", cmd)
        if m_touch:
            last_py_file = (workdir / m_touch.group(1)).expanduser().resolve()
        m_nano = re.match(r"nano\s+([^\s]+\.py)\s*$", cmd)
        if m_nano:
            target = (workdir / m_nano.group(1)).expanduser().resolve()
            last_py_file = target
            # Generar código automáticamente si es un patrón conocido y auto_code activo
            if getattr(args, "auto_code", True) and _maybe_generate_code(args.prompt, target):
                continue
        # Si el "comando" es en realidad un bloque de código, extraer y escribir
        if getattr(args, "auto_code", True) and ("```" in cmd or "import " in cmd):
            code_block = _extract_python_block(cmd)
            if code_block and last_py_file:
                write_file(last_py_file, code_block + "\n")
                print(f"[OK] Código escrito en {last_py_file.name}")
                continue
        # Si no hubo 'cd' explícito pero hay preferred_dir, operar dentro de esa carpeta
        if preferred_dir and preferred_dir.exists() and not saw_cd:
            workdir = preferred_dir
        # Reescritura de pip/python hacia venv si aplica
        cmd = _rewrite_for_venv(cmd)
        # Asistencia previa: si el comando parece desconocido y auto-web-assist está activo
        if getattr(args, "auto_web_assist", True):
            tok = _first_token(cmd)
            if tok and not _is_known_command(tok):
                print(f"[CTX] Comando no reconocido en PATH: '{tok}'. Buscando cómo ejecutarlo...")
                try:
                    q = f"how to use {tok} command macos"
                    urls = search_web(q, max_results=int(getattr(args, "web_max", 5) or 5), timeout=float(getattr(args, "web_timeout", 15) or 15))
                    web_ctx = research_urls(urls[:3]) if urls else ""
                except Exception:
                    web_ctx = ""
                if web_ctx:
                    print("[INFO] Sugerencias (resumen web):\n" + web_ctx[:1200] + ("..." if len(web_ctx) > 1200 else ""))
                model2 = _ensure_model_available(_resolve_model(args.model))
                print(f"[INFO] Consultando modelo por alternativas (máx {assist_timeout}s)...")
                alts = _agent_suggest_alternatives(cmd, "comando desconocido", model2, os_info, web_ctx, goal=args.prompt, allowed=allowed_cmds, timeout=assist_timeout)
                alt_list = alts.get("alternatives", []) if isinstance(alts, dict) else []
                if alt_list:
                    print("[PLAN] Alternativas propuestas:")
                    for j, a in enumerate(alt_list, 1):
                        print(f" {j}. {a.get('desc','(sin desc)')}")
                        print(f"    $ {a.get('cmd','')}")
                    try:
                        sel = _ask_input("¿Intentar una alternativa? (número / ENTER para continuar / q() para abortar): ")
                    except _UserCanceled:
                        sel = ""
                    if sel.strip().isdigit():
                        k = int(sel.strip())
                        if 1 <= k <= len(alt_list):
                            cmd = alt_list[k-1].get("cmd") or cmd
                            print(f"[USE] Usando alternativa seleccionada: $ {cmd}")
                else:
                    print("[INFO] No se encontraron alternativas relevantes o expiró el tiempo.")
        print(f"\n[RUN] {desc}\n$ {cmd}")
        code, out = _run_shell(
            cmd,
            workdir,
            background=bool(getattr(args, "background", False)),
            stream=bool(getattr(args, "stream", True)),
        )
        if out:
            print(out)
        # Validación sintaxis y auto-fix para archivos .py generados
        if getattr(args, "auto_code", True) and last_py_file and last_py_file.exists() and last_py_file.suffix == ".py":
            try:
                py_compile.compile(str(last_py_file), doraise=True)
                # Generación de tests mínimos si no existen
                tests_dir = last_py_file.parent / "tests"
                mkdirp(tests_dir)
                test_file = tests_dir / f"test_{last_py_file.stem}.py"
                if not test_file.exists():
                    try:
                        code_txt = last_py_file.read_text(encoding="utf-8")
                        fn_names = re.findall(r"^def\s+([a-zA-Z_][a-zA-Z0-9_]*)\(", code_txt, flags=re.MULTILINE)
                        lines = ["#!/usr/bin/env python3", "import importlib, pathlib, sys"]
                        lines.append("THIS_DIR = pathlib.Path(__file__).parent")
                        lines.append("MOD_PATH = (THIS_DIR.parent / '%s').resolve()" % last_py_file.name)
                        lines.append("spec = importlib.util.spec_from_file_location('%s_mod','%s')" % (last_py_file.stem, last_py_file.name))
                        lines.append("module = importlib.util.module_from_spec(spec)")
                        lines.append("spec.loader.exec_module(module)")
                        for fn in fn_names[:6]:
                            if fn in ("main",):
                                continue
                            lines.append(f"assert callable(getattr(module, '{fn}', None)), 'Funcion {fn} no encontrada' ")
                        if "quicksort" in fn_names:
                            lines.append("assert module.quicksort([3,1,2]) == [1,2,3]")
                        if "mergesort" in fn_names:
                            lines.append("assert module.mergesort([5,4,1]) == [1,4,5]")
                        if "bfs" in fn_names:
                            lines.append("assert module.bfs({'A':['B'],'B':[]},'A')[0]=='A'")
                        if "dfs" in fn_names:
                            lines.append("assert module.dfs({'A':['B'],'B':[]},'A')[0]=='A'")
                        if "dijkstra" in fn_names:
                            lines.append("dist,_ = module.dijkstra({0:[(1,1)],1:[]},0); assert dist[1]==1")
                        if "astar" in code_txt or "a*" in code_txt:
                            lines.append("g,_ = module.astar({(0,0):[((0,1),1)],(0,1):[]},(0,0),(0,1)); assert (0,1) in g")
                        lines.append("print('Tests básicos OK')")
                        write_file(test_file, "\n".join(lines)+"\n")
                        print(f"[OK] Tests generados: {test_file}")
                    except Exception as et:
                        print(f"[WARN] No se pudieron generar tests: {et}")
            except Exception as e:
                print(f"[WARN] Error de sintaxis en {last_py_file.name}: {e}. Intentando corrección automática...")
                try:
                    content = last_py_file.read_text(encoding="utf-8")
                    fix_prompt = (
                        "Corrige errores de sintaxis sin cambiar el propósito ni comentarios. Devuelve SOLO el código final sin explicaciones.\n" +
                        "Código actual:\n" + content + "\nError:\n" + str(e)
                    )
                    model_fix = _ensure_model_available(_resolve_model(args.model))
                    msgs = [
                        {"role":"system","content":"Eres un asistente que corrige sintaxis de Python y mantiene comentarios."},
                        {"role":"user","content":fix_prompt}
                    ]
                    resp = _ollama_chat_json_quick(msgs, model_fix, timeout=25)
                    # resp puede no ser JSON; intentar extraer bloque de código
                    def _extract_code(txt: str) -> str:
                        m = re.search(r"```python\s+([\s\S]+?)```", txt)
                        if m: return m.group(1).strip()
                        m2 = re.search(r"```\s+([\s\S]+?)```", txt)
                        if m2: return m2.group(1).strip()
                        return txt.strip()
                    if isinstance(resp, dict) and resp.get("alternatives"):
                        # poco probable aquí; ignorar
                        pass
                    # Fallback obtener 'content' si formato original
                    fixed = None
                    if isinstance(resp, dict) and "response" in resp:
                        fixed = _extract_code(resp.get("response",""))
                    else:
                        # resp puede ser dict vacío -> volver a pedir rápido
                        fixed = None
                    if not fixed:
                        # Intento simple vía segunda llamada cruda
                        msgs2 = [{"role":"system","content":"Devuelve solo código Python corregido."},{"role":"user","content":fix_prompt}]
                        raw2 = _ollama_chat_json_quick(msgs2, model_fix, timeout=25)
                        if isinstance(raw2, dict) and raw2.get("response"):
                            fixed = _extract_code(raw2.get("response",""))
                    if fixed:
                        write_file(last_py_file, fixed + "\n")
                        try:
                            py_compile.compile(str(last_py_file), doraise=True)
                            print(f"[OK] Corrección aplicada a {last_py_file.name}")
                        except Exception as e2:
                            print(f"[FAIL] Corrección no resolvió el problema: {e2}")
                except Exception as efix:
                    print(f"[WARN] Falló intento de corrección automática: {efix}")
        if code != 0:
            any_fail = True
            print(f"[FAIL] Comando salió con código {code}")
            # Asistencia posterior a fallo
            if getattr(args, "auto_web_assist", True):
                print("[INFO] Buscando soluciones/alternativas en la web y con el modelo...")
                web_ctx2 = ""
                try:
                    q2 = f"{_first_token(cmd)} error {str(out)[:60]} macos"
                    urls2 = search_web(q2, max_results=int(getattr(args, "web_max", 5) or 5), timeout=float(getattr(args, "web_timeout", 15) or 15))
                    web_ctx2 = research_urls(urls2[:3]) if urls2 else ""
                except Exception:
                    pass
                model3 = _ensure_model_available(_resolve_model(args.model))
                print(f"[INFO] Consultando modelo por alternativas (máx {assist_timeout}s)...")
                alts2 = _agent_suggest_alternatives(cmd, out[-800:] if isinstance(out, str) else str(out), model3, os_info, web_ctx2, goal=args.prompt, allowed=allowed_cmds, timeout=assist_timeout)
                alt2_list = alts2.get("alternatives", []) if isinstance(alts2, dict) else []
                if alt2_list:
                    print("[PLAN] Alternativas:")
                    for j, a in enumerate(alt2_list, 1):
                        print(f" {j}. {a.get('desc','(sin desc)')}")
                        print(f"    $ {a.get('cmd','')}")
                    try:
                        sel2 = _ask_input("¿Intentar una alternativa ahora? (número / ENTER para saltar / q() para abortar): ")
                    except _UserCanceled:
                        print("[CANCELADO] Operación interrumpida por el usuario.")
                        return 130
                    if sel2.strip().isdigit():
                        k2 = int(sel2.strip())
                        if 1 <= k2 <= len(alt2_list):
                            alt_cmd = alt2_list[k2-1].get("cmd") or ""
                            if alt_cmd:
                                print(f"\n[RUN-ALT] {desc}\n$ {alt_cmd}")
                                code2, out2 = _run_shell(
                                    alt_cmd,
                                    workdir,
                                    background=bool(getattr(args, "background", False)),
                                    stream=bool(getattr(args, "stream", True)),
                                )
                                if out2:
                                    print(out2)
                                if code2 == 0:
                                    print("[OK] Alternativa ejecutada con éxito.")
                                    any_fail = False
                                    continue
                                else:
                                    print(f"[FAIL] Alternativa falló con código {code2}")
                else:
                    print("[INFO] No se encontraron alternativas relevantes o expiró el tiempo.")

    # Actualizar contexto tras ejecución de pasos
    for t in ("git", "gh", "node", "npm", "python3", "go"):
        _ctx_mark_tool(t, _ensure_tool(t))
    _save_context()

    if any_fail:
        print("\n[WARN] Uno o más comandos fallaron. Revisa la salida anterior.")
        _ctx_record_run("agent", {"prompt": args.prompt[:200], "cwd": str(workdir)}, 1, extra={"background": bool(getattr(args, "background", False))})
        exec_status = "fallo parcial"
    else:
        exec_status = "exito"
    # Reporte de plan si se solicitó
    if getattr(args, "plan_report", None):
        try:
            rpt_lines = ["# Piper Agent Report", f"- Prompt: {args.prompt}", f"- Estado: {exec_status}"]
            for st in steps:
                rpt_lines.append(f"* {st.get('desc','(sin desc)')}: {st.get('cmd','')}")
            _maybe_save_output(Path.cwd(), args.plan_report, "\n".join(rpt_lines)+"\n")
        except Exception as erpt:
            print(f"[WARN] No se pudo escribir plan_report: {erpt}")
    if any_fail:
        return 1
    print("\n[OK] Agent completó los pasos.")
    _ctx_record_run("agent", {"prompt": args.prompt[:200], "cwd": str(workdir)}, 0, extra={"background": bool(getattr(args, "background", False))})
    return 0


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


# -------------------- CTF MODE (pro) --------------------

def _ctf_tools_status() -> dict[str, bool]:
    tools = [
        "sqlmap", "gobuster", "hydra", "nmap", "nikto", "whatweb", "ffuf", "binwalk", "strings"
    ]
    return {t: _ensure_tool(t) for t in tools}


# Recetas de instalación por herramienta y gestor de paquetes
_CTF_INSTALL_RECIPES: dict[str, dict[str, list[str]]] = {
    # Básicas de recon/web
    "sqlmap": {
        "brew": ["brew install sqlmap"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y sqlmap"],
        "pacman": ["sudo pacman -Sy --noconfirm sqlmap"],
        "dnf": ["sudo dnf install -y sqlmap"],
    },
    "gobuster": {
        "brew": ["brew install gobuster"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y gobuster"],
        "pacman": ["sudo pacman -Sy --noconfirm gobuster"],
        "dnf": ["sudo dnf install -y gobuster"],
    },
    "nmap": {
        "brew": ["brew install nmap"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y nmap"],
        "pacman": ["sudo pacman -Sy --noconfirm nmap"],
        "dnf": ["sudo dnf install -y nmap"],
    },
    "nikto": {
        "brew": ["brew install nikto"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y nikto"],
        "pacman": ["sudo pacman -Sy --noconfirm nikto"],
        "dnf": ["sudo dnf install -y nikto"],
    },
    "whatweb": {
        "brew": ["brew install whatweb"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y whatweb"],
        "pacman": ["sudo pacman -Sy --noconfirm whatweb"],
        "dnf": ["sudo dnf install -y whatweb"],
    },
    "ffuf": {
        "brew": ["brew install ffuf"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y ffuf"],
        "pacman": ["sudo pacman -Sy --noconfirm ffuf"],
        "dnf": ["sudo dnf install -y ffuf"],
        "go": ["go install github.com/ffuf/ffuf/v2@latest"],
    },
    "binwalk": {
        "brew": ["brew install binwalk"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y binwalk"],
        "pacman": ["sudo pacman -Sy --noconfirm binwalk"],
        "dnf": ["sudo dnf install -y binwalk"],
        "pip": ["pip3 install --user binwalk"],
    },
    "hydra": {
        "brew": ["brew install hydra"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y hydra"],
        "pacman": ["sudo pacman -Sy --noconfirm hydra"],
        "dnf": ["sudo dnf install -y hydra"],
    },
    # Complementarias
    "exiftool": {
        "brew": ["brew install exiftool"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y libimage-exiftool-perl"],
        "pacman": ["sudo pacman -Sy --noconfirm exiftool"],
        "dnf": ["sudo dnf install -y perl-Image-ExifTool"],
    },
    "rabin2": {  # via radare2
        "brew": ["brew install radare2"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y radare2"],
        "pacman": ["sudo pacman -Sy --noconfirm radare2"],
        "dnf": ["sudo dnf install -y radare2"],
    },
    "ciphey": {
        "brew": ["brew install ciphey"],
        "pip": ["pip3 install --user ciphey"],
    },
    "httpx": {
        "brew": ["brew install httpx"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y httpx"],
        "go": ["go install github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    },
    "amass": {
        "brew": ["brew install amass"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y amass"],
        "dnf": ["sudo dnf install -y amass"],
    },
    "assetfinder": {
        "brew": ["brew install assetfinder"],
        "go": ["go install github.com/tomnomnom/assetfinder@latest"],
    },
    "subfinder": {
        "brew": ["brew install subfinder"],
        "apt": ["sudo apt-get update", "sudo apt-get install -y subfinder"],
        "go": ["go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    },
    "strings": {
        "apt": ["sudo apt-get update", "sudo apt-get install -y binutils"],
        "pacman": ["sudo pacman -Sy --noconfirm binutils"],
        "dnf": ["sudo dnf install -y binutils"],
        # macOS suele tener /usr/bin/strings; en caso extremo, brew binutils ofrece gstrings
        "brew": ["brew install binutils"],
    },
}


def _detect_pkg_manager() -> str | None:
    if _is_macos() and _exists("brew"):
        return "brew"
    # Linux
    for mgr in ("apt", "pacman", "dnf"):
        if mgr == "apt" and (_exists("apt") or _exists("apt-get")):
            return "apt"
        if mgr == "pacman" and _exists("pacman"):
            return "pacman"
        if mgr == "dnf" and _exists("dnf"):
            return "dnf"
    return None


def _try_install(tool: str, *, manager: str | None = None, dry_run: bool = False) -> bool:
    recipes = _CTF_INSTALL_RECIPES.get(tool) or {}
    order: list[str] = []
    if manager:
        order = [manager]
    else:
        pm = _detect_pkg_manager()
        if pm:
            order.append(pm)
        # Fallbacks según naturaleza de la herramienta
        for alt in ("pip", "go"):
            if alt not in order and alt in recipes:
                order.append(alt)
    cwd = Path.cwd()
    for m in order:
        cmds = recipes.get(m) or []
        if not cmds:
            continue
        print(f"[INFO] Intentando instalar {tool} con {m}...")
        all_ok = True
        for c in cmds:
            if dry_run:
                print("  $", c)
                continue
            code, out = _run_shell(c, cwd, background=False, stream=False)
            if code != 0:
                all_ok = False
                print(_limit_lines(out, 60))
                break
        if dry_run:
            # En dry-run asumimos que este método sería el usado
            return True
        if all_ok:
            # Verificar presencia
            if _ensure_tool(tool):
                return True
    return False


def cmd_ctf_install(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    only: list[str] = getattr(args, "tool", []) or []
    install_all = bool(getattr(args, "all", False))
    dry_run = bool(getattr(args, "dry_run", False))
    manager = getattr(args, "manager", None)
    # Lista objetivo
    all_tools = sorted(set(list(_CTF_INSTALL_RECIPES.keys())))
    if only and install_all:
        print("[ERROR] Usa --all o --tool repetido, no ambos")
        return 2
    targets = all_tools if install_all or not only else only
    # Filtrar ya presentes
    missing = [t for t in targets if not _ensure_tool(t)]
    if not missing and not dry_run:
        print("[OK] No hay herramientas faltantes de la lista objetivo.")
        return 0
    print("[PLAN] Instalar herramientas:", ", ".join(missing if missing else targets))
    ok_all = True
    for t in (missing if missing else targets):
        ok = _try_install(t, manager=manager, dry_run=dry_run)
        if not dry_run:
            # comprobar nuevamente
            ok = ok and _ensure_tool(t)
        print(f"[{'OK' if ok else 'FAIL'}] {t}")
        if not ok:
            ok_all = False
            # sugerencias web conocidas
            hints = {
                "sqlmap": ["https://sqlmap.org/", "https://formulae.brew.sh/formula/sqlmap"],
                "gobuster": ["https://github.com/OJ/gobuster", "https://formulae.brew.sh/formula/gobuster"],
                "nmap": ["https://nmap.org/download", "https://formulae.brew.sh/formula/nmap"],
                "nikto": ["https://github.com/sullo/nikto", "https://formulae.brew.sh/formula/nikto"],
                "whatweb": ["https://github.com/urbanadventurer/WhatWeb", "https://formulae.brew.sh/formula/whatweb"],
                "ffuf": ["https://github.com/ffuf/ffuf", "https://formulae.brew.sh/formula/ffuf"],
                "binwalk": ["https://github.com/ReFirmLabs/binwalk", "https://formulae.brew.sh/formula/binwalk"],
                "hydra": ["https://github.com/vanhauser-thc/thc-hydra", "https://formulae.brew.sh/formula/hydra"],
                "exiftool": ["https://exiftool.org/", "https://formulae.brew.sh/formula/exiftool"],
                "rabin2": ["https://rada.re/n/", "https://formulae.brew.sh/formula/radare2"],
                "ciphey": ["https://github.com/ciphey/ciphey", "https://pypi.org/project/ciphey/"],
                "httpx": ["https://github.com/projectdiscovery/httpx", "https://formulae.brew.sh/formula/httpx"],
                "amass": ["https://github.com/owasp-amass/amass", "https://formulae.brew.sh/formula/amass"],
                "assetfinder": ["https://github.com/tomnomnom/assetfinder", "https://formulae.brew.sh/formula/assetfinder"],
                "subfinder": ["https://github.com/projectdiscovery/subfinder", "https://formulae.brew.sh/formula/subfinder"],
                "strings": ["https://www.gnu.org/software/binutils/"],
            }
            urls = hints.get(t, [])
            if urls:
                print("[HINT] Consulta documentación de instalación:")
                for u in urls:
                    print("  -", u)
    if dry_run:
        print("[DRY-RUN] No se ejecutó ninguna instalación.")
        return 0
    return 0 if ok_all else 1


def cmd_ctf_set_key(_args: argparse.Namespace) -> int:
    try:
        _spinner_pause()
        s1 = getpass.getpass("Nueva clave CTF: ")
        s2 = getpass.getpass("Repite clave CTF: ")
    finally:
        _spinner_resume()
    if not s1:
        print("[ERROR] Clave vacía")
        return 2
    if s1 != s2:
        print("[ERROR] Las claves no coinciden")
        return 2
    _ctf_set_secret(s1)
    print("[OK] Clave CTF establecida")
    return 0


def cmd_ctf_status(_args: argparse.Namespace) -> int:
    st = _ctf_tools_status()
    enabled = bool(_ctf_secret_record())
    print("[CTF] estado: enabled=" + str(enabled))
    for k, v in sorted(st.items()):
        print(f" - {k}: {'OK' if v else 'no'}")
    return 0


def cmd_ctf_unset_key(_args: argparse.Namespace) -> int:
    sec = _security_section()
    if "ctf_secret" in sec:
        sec.pop("ctf_secret", None)
        _security_save(sec)
        print("[OK] Clave CTF eliminada. Debes definir una nueva con: piper ctf set-key")
        return 0
    print("[INFO] No había clave CTF definida")
    return 0


def _limit_lines(s: str, n: int = 200) -> str:
    try:
        lines = (s or "").splitlines()
        if len(lines) <= n:
            return (s or "").strip()
        return "\n".join(lines[:n] + [f"... ({len(lines)-n} líneas más)"])
    except Exception:
        return (s or "")


def _host_from_url(url: str) -> str | None:
    try:
        u = urlparse(url)
        if u.hostname:
            return u.hostname
        # fallback: si no tiene esquema, tratar como hostname
        if "://" not in url and "/" not in url:
            return url
    except Exception:
        pass
    return None


def cmd_ctf_web(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    target = getattr(args, "target", "")
    if not target:
        print("[ERROR] Debes pasar --target URL")
        return 2
    workdir = Path.cwd()
    status = _ctf_tools_status()
    print("[PLAN] Recon web rápido para:", target)
    report: list[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    report.append(f"# Piper CTF — Recon web\n\n- Fecha: {ts}\n- Objetivo: {target}\n")
    host = _host_from_url(target) or ""
    # whatweb o headers
    if status.get("whatweb"):
        print("\n[RUN] whatweb")
        code, out = _run_shell(f"whatweb --color=never -a 3 {json.dumps(target)}", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## whatweb\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    else:
        print("\n[RUN] Encabezados HTTP (curl)")
        code, out = _run_shell(f"curl -sSL -D - -o /dev/null {json.dumps(target)}", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## curl -I\n\n" + "```\n" + _limit_lines(out, 120) + "\n```")
    # nmap si hay host
    if host and status.get("nmap"):
        print("\n[RUN] nmap top-100 puertos + versiones")
        code, out = _run_shell(f"nmap -Pn -sV --top-ports 100 --open {json.dumps(host)}", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## nmap\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # gobuster dir (si URL http)
    if status.get("gobuster") and target.startswith(("http://", "https://")):
        wl = getattr(args, "wordlist", None) or "/usr/share/wordlists/dirb/common.txt"
        print("\n[RUN] gobuster dir (rápido)")
        code, out = _run_shell(f"gobuster dir -u {json.dumps(target)} -w {json.dumps(wl)} -q -t 30 -k", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## gobuster dir\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # nikto (si disponible)
    if status.get("nikto") and target.startswith(("http://", "https://")):
        print("\n[RUN] nikto (chequeos básicos)")
        code, out = _run_shell(f"nikto -host {json.dumps(target)} -nolookup -Tuning x 2>/dev/null", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## nikto\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # sqlmap (mínimo invasivo)
    if status.get("sqlmap"):
        print("\n[RUN] sqlmap (ligero)")
        code, out = _run_shell(f"sqlmap -u {json.dumps(target)} --batch --random-agent --level=1 --risk=1 --crawl=1 --smart --timeout=10 --technique=BEUSTQ 2>/dev/null", workdir, background=False, stream=False)
        if out:
            print(out)
            report.append("## sqlmap\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    print("\n[OK] Recon web básico completado.")
    rpt = getattr(args, "report", None)
    if rpt:
        md = "\n\n".join(report) + "\n"
        _maybe_save_output(Path.cwd(), str(rpt), md)
    return 0


def _read_small(file: Path, max_bytes: int = 1024 * 1024) -> bytes:
    try:
        with file.open("rb") as fh:
            return fh.read(max_bytes)
    except Exception:
        return b""


def _try_b64(s: str) -> str | None:
    t = s.strip()
    if not t or len(t) < 16:
        return None
    try:
        b = base64.b64decode(t + ("=" * ((4 - len(t) % 4) % 4)), validate=True)
        decoded = b.decode("utf-8", errors="ignore")
        if decoded and any(ch.isprintable() for ch in decoded):
            return decoded
    except Exception:
        return None
    return None


def cmd_ctf_code(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    root = Path(getattr(args, "path", ".")).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] Carpeta no válida: {root}")
        return 2
    status = _ctf_tools_status()
    report: list[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    report.append(f"# Piper CTF — Análisis de carpeta\n\n- Fecha: {ts}\n- Carpeta: {root}\n")
    print(f"[PLAN] Escaneo estático de {root}")
    total_exam = 0
    flags_found: list[str] = []
    for p in root.rglob("*"):
        if total_exam > 2000:
            break
        if p.is_dir():
            continue
        total_exam += 1
        try:
            sz = p.stat().st_size
        except Exception:
            sz = 0
        # Buscar flag{...}
        content_preview = b""
        if sz <= 5 * 1024 * 1024:  # 5MB
            content_preview = _read_small(p, max_bytes=256 * 1024)
            txt = content_preview.decode("utf-8", errors="ignore")
            for m in re.findall(r"flag\{[^}]{3,100}\}", txt, flags=re.IGNORECASE):
                flags_found.append(f"{p}: {m}")
            # base64 líneas
            for line in txt.splitlines():
                dec = _try_b64(line.strip())
                if dec and re.search(r"flag\{[^}]+\}", dec, flags=re.IGNORECASE):
                    flags_found.append(f"{p}: {dec.strip()[:200]}")
        # Ejecutables/bins: strings y binwalk
        if status.get("strings") and sz and sz <= 50 * 1024 * 1024:
            code, out = _run_shell(f"strings {json.dumps(str(p))}", root, background=False, stream=False)
            if code == 0 and out:
                sample = "\n".join(out.splitlines()[:200])
                print(sample)
                report.append(f"## strings {p.name}\n\n" + "```\n" + _limit_lines(sample, 200) + "\n```")
                for m in re.findall(r"flag\{[^}]{3,100}\}", sample, flags=re.IGNORECASE):
                    flags_found.append(f"{p}: {m}")
        if status.get("binwalk") and sz and sz <= 100 * 1024 * 1024:
            # análisis superficial sin extraer
            code, out = _run_shell(f"binwalk {json.dumps(str(p))}", root, background=False, stream=False)
            if out:
                sample = "\n".join(out.splitlines()[:20])
                print(sample)
                report.append(f"## binwalk {p.name}\n\n" + "```\n" + _limit_lines(sample, 40) + "\n```")
    if flags_found:
        print("\n[HALLAZGOS] Posibles flags detectadas:")
        for h in flags_found[:20]:
            print(" - ", h)
        if len(flags_found) > 20:
            print(f" ... y {len(flags_found) - 20} más")
    else:
        print("\n[HALLAZGOS] No se detectaron patrones de flag obvios.")
        report.append("## Hallazgos (flags)\n\nNo se detectaron patrones obvios.")
    print("\n[OK] Escaneo estático finalizado.")
    rpt = getattr(args, "report", None)
    if rpt:
        md = "\n\n".join(report) + "\n"
        _maybe_save_output(Path.cwd(), str(rpt), md)
    return 0


def cmd_ctf_osint(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    domain = getattr(args, "domain", "").strip()
    if not domain:
        print("[ERROR] Debes indicar --domain")
        return 2
    max_lines = int(getattr(args, "max", 200) or 200)
    workdir = Path.cwd()
    status = _ctf_tools_status()
    print(f"[PLAN] OSINT para {domain}")
    report: list[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    report.append(f"# Piper CTF — OSINT\n\n- Fecha: {ts}\n- Dominio: {domain}\n")
    # subfinder
    if status.get("subfinder"):
        print("\n[RUN] subfinder (pasivo)")
        code, out = _run_shell(f"subfinder -silent -d {json.dumps(domain)}", workdir, background=False, stream=False)
        out = "\n".join(out.splitlines()[:max_lines]) if out else ""
        if out:
            print(out)
            report.append("## subfinder\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # amass
    if status.get("amass"):
        print("\n[RUN] amass enum (pasivo)")
        code, out = _run_shell(f"amass enum -passive -d {json.dumps(domain)}", workdir, background=False, stream=False)
        out = "\n".join(out.splitlines()[:max_lines]) if out else ""
        if out:
            print(out)
            report.append("## amass\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # assetfinder
    if status.get("assetfinder"):
        print("\n[RUN] assetfinder")
        code, out = _run_shell(f"assetfinder --subs-only {json.dumps(domain)}", workdir, background=False, stream=False)
        out = "\n".join(out.splitlines()[:max_lines]) if out else ""
        if out:
            print(out)
            report.append("## assetfinder\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    # httpx probing
    if status.get("httpx"):
        print("\n[RUN] httpx (probar HTTP vivo)")
        cmd = f"(echo {json.dumps(domain)}; echo www.{domain}) | httpx -silent -timeout 5 -status-code -title -tech-detect"
        code, out = _run_shell(cmd, workdir, background=False, stream=False)
        out = "\n".join(out.splitlines()[:max_lines]) if out else ""
        if out:
            print(out)
            report.append("## httpx\n\n" + "```\n" + _limit_lines(out, 200) + "\n```")
    print("\n[OK] OSINT básico completado.")
    rpt = getattr(args, "report", None)
    if rpt:
        md = "\n\n".join(report) + "\n"
        _maybe_save_output(Path.cwd(), str(rpt), md)
    return 0


def _decode_attempts(data: bytes) -> list[tuple[str,str]]:
    outs: list[tuple[str,str]] = []
    txt = data.decode("utf-8", errors="ignore")
    # hex
    try:
        if re.fullmatch(r"[0-9a-fA-F\s]+", txt.strip()) and len(txt.strip()) % 2 == 0:
            raw = bytes.fromhex(re.sub(r"\s+", "", txt))
            outs.append(("hex->utf8", raw.decode("utf-8", errors="ignore")))
    except Exception:
        pass
    # base64
    for name, enc in [("base64", base64.b64decode), ("base32", base64.b32decode), ("base85", base64.b85decode), ("a85", base64.a85decode)]:
        try:
            s = txt.strip()
            b = enc(s + ("=" * ((4 - len(s) % 4) % 4))) if name=="base64" else enc(s)
            dec = b.decode("utf-8", errors="ignore")
            if dec:
                outs.append((name+"->utf8", dec))
        except Exception:
            pass
    # rot13
    try:
        import codecs
        outs.append(("rot13", codecs.decode(txt, "rot_13")))
    except Exception:
        pass
    # caesar brute (A-Z)
    def caesar(s: str, k: int) -> str:
        out = []
        for ch in s:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch)-97+k)%26 + 97))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch)-65+k)%26 + 65))
            else:
                out.append(ch)
        return "".join(out)
    sample = txt[:2000]
    for k in range(1, 26):
        c = caesar(sample, k)
        if re.search(r"flag\{[^}]+\}", c, flags=re.IGNORECASE):
            outs.append((f"caesar+{k}", caesar(txt, k)))
            break
    return outs


def cmd_ctf_crypto(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    data: bytes
    if getattr(args, "text", None):
        data = args.text.encode("utf-8")
    else:
        path = Path(getattr(args, "file", "")).expanduser().resolve()
        if not path.exists():
            print(f"[ERROR] No existe archivo: {path}")
            return 2
        data = _read_small(path, max_bytes=2*1024*1024)
    outs = _decode_attempts(data)
    if outs:
        print("[OK] Decodificaciones potenciales:")
        for name, val in outs[:5]:
            preview = val.strip().splitlines()[:8]
            print(f"- {name}:")
            for ln in preview:
                print("  ", ln)
            if len(preview) == 8:
                print("  ...")
    else:
        # ciphey si está
        if _ensure_tool("ciphey"):
            print("[RUN] ciphey (auto-decode)")
            _run_shell("ciphey -q -t " + json.dumps(data.decode("utf-8", errors="ignore")), Path.cwd(), background=False, stream=True)
        else:
            print("[INFO] No se detectó decodificación obvia. Instala 'ciphey' para análisis más profundo.")
    return 0


def cmd_ctf_reverse(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    f = Path(getattr(args, "file", "")).expanduser().resolve()
    if not f.exists() or not f.is_file():
        print(f"[ERROR] Archivo inválido: {f}")
        return 2
    st = _ctf_tools_status()
    report: list[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    report.append(f"# Piper CTF — Reverse básico\n\n- Fecha: {ts}\n- Archivo: {f}\n")
    print(f"[PLAN] Reverse básico de {f}")
    if _ensure_tool("file"):
        code, out = _run_shell("file " + json.dumps(str(f)), f.parent, background=False, stream=False)
        if out:
            print(out)
            report.append("## file\n\n" + "```\n" + _limit_lines(out, 60) + "\n```")
    if st.get("exiftool"):
        code, out = _run_shell("exiftool " + json.dumps(str(f)), f.parent, background=False, stream=False)
        if out:
            sample = "\n".join(out.splitlines()[:40])
            print(sample)
            report.append("## exiftool\n\n" + "```\n" + _limit_lines(sample, 60) + "\n```")
    if st.get("strings"):
        code, out = _run_shell("strings " + json.dumps(str(f)), f.parent, background=False, stream=False)
        if out:
            sample = "\n".join(out.splitlines()[:200])
            print(sample)
            report.append("## strings\n\n" + "```\n" + _limit_lines(sample, 220) + "\n```")
    if st.get("binwalk"):
        code, out = _run_shell("binwalk " + json.dumps(str(f)), f.parent, background=False, stream=False)
        if out:
            sample = "\n".join(out.splitlines()[:20])
            print(sample)
            report.append("## binwalk\n\n" + "```\n" + _limit_lines(sample, 40) + "\n```")
    if st.get("rabin2"):
        code, out = _run_shell("rabin2 -I " + json.dumps(str(f)), f.parent, background=False, stream=False)
        if out:
            print(out)
            report.append("## rabin2 -I\n\n" + "```\n" + _limit_lines(out, 120) + "\n```")
    print("\n[OK] Reverse básico completado.")
    rpt = getattr(args, "report", None)
    if rpt:
        md = "\n\n".join(report) + "\n"
        _maybe_save_output(Path.cwd(), str(rpt), md)
    return 0


def _http_get(url: str, headers: dict[str,str] | None = None, timeout: float = 8.0) -> tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers=headers or {"User-Agent":"PiperCTF/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return resp.getcode() or 0, body
    except Exception as e:
        return 0, str(e)


def _inject_param(url: str, param: str, payload: str) -> str:
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        u = urlparse(url)
        q = parse_qs(u.query)
        q[param] = [payload]
        new_q = urlencode(q, doseq=True)
        return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))
    except Exception:
        return url


def cmd_ctf_probe(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    base = getattr(args, "url", "").strip()
    param = getattr(args, "param", "").strip()
    if not base or not param:
        print("[ERROR] Debes pasar --url y --param")
        return 2
    print(f"[PLAN] Probe SSTI en {base} param={param}")
    payloads = [
        ("jinja2", "{{7*7}}", "49"),
        ("django", "{{7*7}}", "49"),
        ("twig", "{{7*7}}", "49"),
        ("erb", "<%= 7*7 %>", "49"),
    ]
    for name, pl, expect in payloads:
        url = _inject_param(base, param, pl)
        code, body = _http_get(url)
        if code and expect in body:
            print(f"[VULN] Posible SSTI ({name}): payload {pl!r} produjo {expect}")
    print("[OK] Probe SSTI finalizado.")
    return 0


def cmd_ctf_creds(args: argparse.Namespace) -> int:
    if not _ctf_require_secret(getattr(args, "key", None)):
        return 1
    if not getattr(args, "legal", False):
        print("[ERROR] Debes confirmar --legal para ejecutar hydra en un entorno autorizado.")
        return 2
    if not _ensure_tool("hydra"):
        print("[ERROR] 'hydra' no está instalado en PATH")
        return 1
    host = getattr(args, "host", "").strip()
    service = getattr(args, "service", "").strip()
    users = Path(getattr(args, "users", "")).expanduser().resolve()
    passes = Path(getattr(args, "passwords", "")).expanduser().resolve()
    if not host or not service or not users.exists() or not passes.exists():
        print("[ERROR] Parámetros inválidos (host/service/users/passwords)")
        return 2
    threads = int(getattr(args, "threads", 4) or 4)
    print(f"[RUN] hydra contra {host} servicio {service} (threads={threads})")
    cmd = f"hydra -L {json.dumps(str(users))} -P {json.dumps(str(passes))} {json.dumps(host)} {json.dumps(service)} -t {threads} -f -I -W 3 -vV"
    _run_shell(cmd, Path.cwd(), background=False, stream=True)
    return 0


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
    # Seguridad: server api key
    if hasattr(args, "set_server_api_key") and args.set_server_api_key is not None:
        _set_server_api_key(str(args.set_server_api_key))
        changed = True
        print("[OK] server_api_key establecido (requerido en /ask)")
    if getattr(args, "unset_server_api_key", False):
        _set_server_api_key(None)
        changed = True
        print("[OK] server_api_key eliminado (no se requerirá en /ask)")
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
        sec = cur.get("security", {}) if isinstance(cur.get("security"), dict) else {}
        srv = bool((sec.get("server_api_key") or ""))
        ctf = bool(isinstance(sec.get("ctf_secret"), dict))
        print(f"server_api_key_set: {srv}")
        print(f"ctf_enabled: {ctf}")
    return 0


def _format_context(ctx: dict) -> str:
    lines: list[str] = []
    lines.append("[CONTEXT]")
    lines.append(f"version: {ctx.get('version')}")
    lines.append(f"last_run_ts: {ctx.get('last_run_ts')}")
    # Tools
    tools = ctx.get("tools", {}) or {}
    if isinstance(tools, dict) and tools:
        lines.append("tools:")
        for name, meta in sorted(tools.items()):
            if isinstance(meta, dict):
                inst = meta.get("installed")
                ts = meta.get("last_checked_ts")
                lines.append(f"  - {name}: installed={bool(inst)} last_checked={ts}")
            else:
                lines.append(f"  - {name}: {meta}")
    # Decisions
    dec = ctx.get("decisions", {}) or {}
    if isinstance(dec, dict) and dec:
        lines.append("decisions:")
        for k, v in sorted(dec.items()):
            lines.append(f"  - {k}: {v}")
    # Runs
    runs = ctx.get("runs", []) or []
    lines.append(f"runs: {len(runs)} (most recent last)")
    for r in runs[-5:]:  # mostrar últimos 5
        try:
            lines.append(f"  - {r.get('ts')} :: {r.get('cmd')} exit={r.get('exit')}")
        except Exception:
            continue
    return "\n".join(lines)


def cmd_context(args: argparse.Namespace) -> int:
    ctx = _load_context()
    changed = False
    if getattr(args, "clear", False):
        # Reiniciar a estructura mínima
        ctx.clear()
        ctx.update({
            "version": 1,
            "last_run_ts": None,
            "runs": [],
            "tools": {},
            "decisions": {},
        })
        changed = True
        print("[OK] Contexto limpiado")
    forget = getattr(args, "forget", None)
    if forget:
        dec = ctx.setdefault("decisions", {})
        if forget in dec:
            dec.pop(forget, None)
            changed = True
            print(f"[OK] Olvidada decisión: {forget}")
        else:
            print(f"[INFO] No existía decisión: {forget}")
    if changed:
        _save_context()
    if getattr(args, "show", False) or (not getattr(args, "clear", False) and not forget):
        # Refrescar presencia de herramientas antes de mostrar
        try:
            _ctx_refresh_tools_presence()
            _save_context()
        except Exception:
            pass
        print(_format_context(_load_context()))
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


def _print_full_help(parser: argparse.ArgumentParser) -> None:
    try:
        print(parser.format_help())
    except Exception:
        pass
    # Mostrar ayuda detallada para cada subcomando
    try:
        for action in parser._actions:  # type: ignore[attr-defined]
            if isinstance(action, argparse._SubParsersAction):  # type: ignore[attr-defined]
                for name, sp in action.choices.items():
                    print("\n===", name, "===\n")
                    try:
                        print(sp.format_help())
                    except Exception:
                        pass
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="piper", description="Piper CLI — prompt a proyecto", add_help=False)
    p.add_argument("-h", "--help", action="store_true", help="Muestra ayuda completa con todas las flags y subcomandos")
    sub = p.add_subparsers(dest="cmd")

    p_assist = sub.add_parser("assist", help="Asistente interactivo con aclaraciones")
    p_assist.add_argument("prompt", help="Petición inicial")
    p_assist.add_argument("--model", help="Modelo Ollama (por defecto PIPER_OLLAMA_MODEL o mistral:7b-instruct)")
    p_assist.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_assist.add_argument("--no-tts", action="store_true", help="Desactiva TTS al responder (por defecto TTS está desactivado)")
    p_assist.add_argument("--freeform", action="store_true", help="Modo estilo chat: respuesta libre de texto (sin JSON)")
    p_assist.add_argument("--web", action="store_true", help="Usa resumen web de URLs del prompt como contexto para la respuesta")
    p_assist.add_argument("--web-max", type=int, default=5, help="Máximo de sitios web a considerar (por defecto 5)")
    p_assist.add_argument("--web-timeout", type=int, default=15, help="Timeout por solicitud web en segundos (por defecto 15s)")
    p_assist.add_argument("--gen-estimate", type=int, default=20, help="Tiempo estimado (s) mostrado para la fase de generación")
    # Búsqueda de archivos (por defecto buscará en todo el sistema si aplica el intent)
    p_assist.add_argument("--find-base", help="Directorio base para búsqueda de archivos (default: /)")
    p_assist.add_argument("--find-current-only", action="store_true", help="Limita la búsqueda de archivos al directorio actual")
    p_assist.add_argument("--save", help="Guardar la salida en un archivo relativo (p. ej. 'notas.md')")
    p_assist.add_argument("--append", action="store_true", help="Anexar en vez de sobrescribir al usar --save")
    p_assist.set_defaults(func=cmd_assist, no_tts=True)

    # Subcomando 'project' retirado: mantenemos un alias que informa el cambio
    p_project = sub.add_parser("project", help="[RETIRADO] Usa 'piper agent' en su lugar")
    p_project.set_defaults(func=cmd_project)

    p_say = sub.add_parser("say", help="Decir un texto con Piper TTS")
    p_say.add_argument("text")
    p_say.set_defaults(func=cmd_say)

    # Agente de ejecución de comandos
    p_agent = sub.add_parser("agent", help="Agente que infiere y ejecuta comandos a partir de una instrucción")
    p_agent.add_argument("prompt", help="Instrucción de alto nivel (qué hacer)")
    p_agent.add_argument("--model", help="Modelo Ollama a usar para planificar (por defecto heurístico)")
    p_agent.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_agent.add_argument("--no-tts", action="store_true", help="Desactiva TTS al responder (por defecto desactivado)")
    p_agent.add_argument("--cwd", help="Directorio de trabajo para ejecutar los comandos (por defecto: cwd)")
    p_agent.add_argument("--background", action="store_true", help="Ejecuta los comandos en background y guarda logs")
    p_agent.add_argument("-y", "--yes", action="store_true", help="No preguntar confirmaciones (instalaciones u operaciones sensibles)")
    p_agent.add_argument("--no-stream", dest="stream", action="store_false", help="No adjuntar IO; captura salida y muéstrala al final (por defecto: streaming on)")
    p_agent.add_argument("--dry-run", action="store_true", help="Mostrar el plan en formato árbol y salir sin ejecutar nada")
    p_agent.add_argument("--assist-timeout", type=int, default=30, help="Tiempo máx (s) para pedir alternativas al modelo (por defecto 30s)")
    # Web como contexto previo a la planificación
    p_agent.add_argument("--web", action="store_true", help="Investiga en la web y usa ese contexto para planificar los comandos")
    p_agent.add_argument("--web-max", type=int, default=5, help="Máximo de sitios web a considerar (por defecto 5)")
    p_agent.add_argument("--web-timeout", type=int, default=15, help="Timeout por solicitud web en segundos (por defecto 15s)")
    p_agent.add_argument("--no-auto-web-assist", dest="auto_web_assist", action="store_false", help="Desactiva asistencia automática web (predeterminado: activada)")
    # Auto-code: generar archivos automáticamente (evita abrir editores interactivos)
    p_agent.add_argument("--no-auto-code", dest="auto_code", action="store_false", help="Desactiva la generación automática de archivos de código")
    p_agent.add_argument("--plan-report", help="Guardar plan y resultados en Markdown (ruta relativa segura)")
    p_agent.set_defaults(func=cmd_agent, auto_web_assist=True, auto_code=True, stream=True)

    # Servicio Ollama ON/OFF (acepta mayúsculas y minúsculas)
    p_on = sub.add_parser("on", help="Enciende el servicio Ollama")
    p_on.set_defaults(func=cmd_service_on)
    p_on2 = sub.add_parser("ON", help="Enciende el servicio Ollama")
    p_on2.set_defaults(func=cmd_service_on)
    p_off = sub.add_parser("off", help="Apaga el servicio Ollama")
    p_off.set_defaults(func=cmd_service_off)
    p_off2 = sub.add_parser("OFF", help="Apaga el servicio Ollama")
    p_off2.set_defaults(func=cmd_service_off)

    # Servidor local Piper (HTTP)
    p_srv = sub.add_parser("server", help="Servidor local HTTP de Piper (on/off/status/run)")
    srv_sub = p_srv.add_subparsers(dest="server_cmd")
    p_srv_on = srv_sub.add_parser("on", help="Inicia servidor en background")
    p_srv_on.add_argument("--port", type=int, default=8787, help="Puerto (por defecto 8787)")
    p_srv_on.set_defaults(func=cmd_server_on)

    p_srv_off = srv_sub.add_parser("off", help="Detiene servidor en background")
    p_srv_off.set_defaults(func=cmd_server_off)

    p_srv_status = srv_sub.add_parser("status", help="Estado del servidor")
    p_srv_status.set_defaults(func=cmd_server_status)

    p_srv_run = srv_sub.add_parser("run", help="Ejecuta el servidor en foreground (uso interno)")
    p_srv_run.add_argument("--port", type=int, default=8787, help="Puerto (por defecto 8787)")
    p_srv_run.add_argument("--model", help="Modelo Ollama (opcional)")
    p_srv_run.set_defaults(func=cmd_server_run)

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

    # Inspector de carpeta/proyecto
    p_inspect = sub.add_parser("inspect", help="Analiza la carpeta (archivos, funciones e interconexiones) y genera Inspector-Report.md")
    p_inspect.add_argument("--cwd", help="Directorio a inspeccionar (por defecto: cwd)")
    p_inspect.add_argument("--max-files", type=int, default=500, help="Máximo de archivos a analizar")
    p_inspect.add_argument("--max-lines", type=int, default=2000, help="Máximo de líneas leídas por archivo")
    p_inspect.set_defaults(func=cmd_inspect)

    # Configuración persistente (memoria de Piper)
    p_conf = sub.add_parser("config", help="Configura defaults persistentes (límites IA, smoke-run)")
    p_conf.add_argument("--show", action="store_true", help="Mostrar configuración actual")
    p_conf.add_argument("--set-max-ai-bytes", type=int, help="Fija máximo total de bytes IA por lote")
    p_conf.add_argument("--set-max-ai-file-bytes", type=int, help="Fija máximo de bytes IA por archivo")
    p_conf.add_argument("--enable-smoke-python", action="store_true", help="Activa smoke run por defecto en stack 'python'")
    p_conf.add_argument("--disable-smoke-python", action="store_true", help="Desactiva smoke run por defecto en stack 'python'")
    # Seguridad
    p_conf.add_argument("--set-server-api-key", help="Establece API key para el servidor HTTP (X-API-Key)")
    p_conf.add_argument("--unset-server-api-key", action="store_true", help="Elimina la API key del servidor HTTP")
    p_conf.set_defaults(func=cmd_config)

    # CTF mode (protegido por clave)
    p_ctf = sub.add_parser("ctf", help="Modo CTF profesional (requiere clave)")
    ctf_sub = p_ctf.add_subparsers(dest="ctf_cmd")

    p_ctf_key = ctf_sub.add_parser("set-key", help="Define/actualiza la clave del modo CTF")
    p_ctf_key.set_defaults(func=cmd_ctf_set_key)

    p_ctf_unkey = ctf_sub.add_parser("unset-key", help="Elimina la clave del modo CTF (revoca acceso)")
    p_ctf_unkey.set_defaults(func=cmd_ctf_unset_key)

    p_ctf_status = ctf_sub.add_parser("status", help="Muestra herramientas CTF detectadas")
    p_ctf_status.set_defaults(func=cmd_ctf_status)

    # Instalación de herramientas CTF
    p_ctf_install = ctf_sub.add_parser("install", help="Instala herramientas CTF faltantes (brew/apt/pacman/dnf/pip/go)")
    p_ctf_install.add_argument("--all", action="store_true", help="Instalar todas las herramientas recomendadas")
    p_ctf_install.add_argument("--tool", action="append", help="Instalar sólo esta herramienta (repetible)")
    p_ctf_install.add_argument("--manager", choices=["brew","apt","pacman","dnf","pip","go"], help="Forzar gestor de instalación")
    p_ctf_install.add_argument("--dry-run", action="store_true", help="Mostrar comandos sin ejecutarlos")
    p_ctf_install.add_argument("--key", help="Clave CTF")
    p_ctf_install.set_defaults(func=cmd_ctf_install)

    p_ctf_web = ctf_sub.add_parser("web", help="Recon web rápida contra un objetivo URL (sqlmap/gobuster/nikto si disponibles)")
    p_ctf_web.add_argument("--target", required=True, help="URL objetivo (http/https)")
    p_ctf_web.add_argument("--key", help="Clave CTF (si no se pasa, se solicitará o se usará $PIPER_CTF_KEY)")
    p_ctf_web.add_argument("--wordlist", help="Wordlist para gobuster (opcional)")
    p_ctf_web.add_argument("--limit", type=int, default=90, help="Límite de tiempo aprox por herramienta (s)")
    p_ctf_web.add_argument("--report", help="Guardar reporte Markdown en ruta relativa (p. ej. 'recon_web.md')")
    p_ctf_web.set_defaults(func=cmd_ctf_web)

    p_ctf_code = ctf_sub.add_parser("code", help="Análisis estático de carpeta (strings/binwalk/patrones)")
    p_ctf_code.add_argument("--path", required=True, help="Carpeta con material del reto")
    p_ctf_code.add_argument("--key", help="Clave CTF (si no se pasa, se solicitará o se usará $PIPER_CTF_KEY)")
    p_ctf_code.add_argument("--report", help="Guardar reporte Markdown en ruta relativa (p. ej. 'analisis_code.md')")
    p_ctf_code.set_defaults(func=cmd_ctf_code)

    # OSINT
    p_ctf_osint = ctf_sub.add_parser("osint", help="OSINT para dominio: subdominios y probing HTTP")
    p_ctf_osint.add_argument("--domain", required=True, help="Dominio base (ej. example.com)")
    p_ctf_osint.add_argument("--key", help="Clave CTF")
    p_ctf_osint.add_argument("--max", type=int, default=200, help="Límite de líneas por herramienta")
    p_ctf_osint.add_argument("--report", help="Guardar reporte Markdown (p. ej. 'osint.md')")
    p_ctf_osint.set_defaults(func=cmd_ctf_osint)

    # Crypto/encodings
    p_ctf_crypto = ctf_sub.add_parser("crypto", help="Decodifica/analiza textos (base64/hex/rot13/caesar)")
    src = p_ctf_crypto.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="Texto a analizar")
    src.add_argument("--file", help="Archivo a analizar")
    p_ctf_crypto.add_argument("--key", help="Clave CTF")
    p_ctf_crypto.set_defaults(func=cmd_ctf_crypto)

    # Reverse básico
    p_ctf_rev = ctf_sub.add_parser("reverse", help="Inspección binaria (file/strings/binwalk/exiftool)")
    p_ctf_rev.add_argument("--file", required=True, help="Archivo binario a inspeccionar")
    p_ctf_rev.add_argument("--key", help="Clave CTF")
    p_ctf_rev.add_argument("--report", help="Guardar reporte Markdown (p. ej. 'reverse.md')")
    p_ctf_rev.set_defaults(func=cmd_ctf_reverse)

    # Probe (SSTI simples GET)
    p_ctf_probe = ctf_sub.add_parser("probe", help="Pruebas sencillas de SSTI (no destructivas)")
    p_ctf_probe.add_argument("--url", required=True, help="URL base (ej. https://host/path?param=VAL)")
    p_ctf_probe.add_argument("--param", required=True, help="Nombre del parámetro donde inyectar payloads")
    p_ctf_probe.add_argument("--key", help="Clave CTF")
    p_ctf_probe.set_defaults(func=cmd_ctf_probe)

    # Credenciales controladas (hydra)
    p_ctf_creds = ctf_sub.add_parser("creds", help="Ataques de credenciales controlados con hydra (autorizado)")
    p_ctf_creds.add_argument("--host", required=True, help="Host o IP")
    p_ctf_creds.add_argument("--service", required=True, choices=["ssh","ftp"], help="Servicio objetivo")
    p_ctf_creds.add_argument("--users", required=True, help="Ruta a lista de usuarios (-L)")
    p_ctf_creds.add_argument("--passwords", required=True, help="Ruta a lista de contraseñas (-P)")
    p_ctf_creds.add_argument("--threads", type=int, default=4, help="Hilos (hydra -t)")
    p_ctf_creds.add_argument("--legal", action="store_true", help="Confirmo que es un entorno autorizado para pruebas")
    p_ctf_creds.add_argument("--key", help="Clave CTF")
    p_ctf_creds.set_defaults(func=cmd_ctf_creds)

    # Contexto inteligente: mostrar/limpiar/olvidar
    p_ctx = sub.add_parser("context", help="Gestiona el contexto inteligente (herramientas, decisiones, historial)")
    p_ctx.add_argument("--show", action="store_true", help="Muestra el contexto actual")
    p_ctx.add_argument("--clear", action="store_true", help="Limpia el contexto (mantiene otras configuraciones)")
    p_ctx.add_argument("--forget", help="Olvida una decisión (clave), p. ej. install.git")
    p_ctx.set_defaults(func=cmd_context)

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
    # Cargar contexto al inicio de cualquier ejecución
    try:
        _load_context()
        _ctx_refresh_tools_presence()
    except Exception:
        pass
    parser = build_parser()
    # Permitir modo "piper \"haz X\"" sin subcomando, tolerando flags desconocidas
    # Activar spinner global (se pausará si hay input o no hay fases activas)
    try:
        _spinner_start()
    except Exception:
        pass
    args, extras = parser.parse_known_args(argv[1:])
    if getattr(args, "help", False):
        _print_full_help(parser)
        _spinner_stop()
        return 0
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
            no_tts=True if no_tts or True else False,
            web=False,
            freeform=False,
            web_max=5,
            web_timeout=15,
            gen_estimate=20,
            find_base=None,
            find_current_only=False,
            save=None,
            append=False,
        )
        code = 0
        try:
            code = cmd_assist(ns)
        finally:
            try:
                _spinner_stop()
            except Exception:
                pass
        try:
            _ctx_record_run("assist-quick", {"prompt": default_prompt[:200]}, code, extra={})
        except Exception:
            pass
        return code
    # Ejecutar subcomando y registrar en contexto
    code = 0
    try:
        code = args.func(args)
    finally:
        try:
            # Resumen compacto de args (evitar objetos no serializables o largos)
            summary: dict[str, Any] = {}
            for k, v in vars(args).items():
                if k in ("func",):
                    continue
                if isinstance(v, (str, int, float, bool, type(None))):
                    summary[k] = v if not (isinstance(v, str) and len(v) > 200) else v[:200]
                else:
                    summary[k] = str(v)[:120]
            _ctx_record_run(getattr(args, "cmd", "unknown"), summary, int(code), extra={})
        except Exception:
            pass
        try:
            _spinner_stop()
        except Exception:
            pass
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
