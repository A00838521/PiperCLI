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
from urllib.parse import urlparse

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
            "Eres un asistente que genera archivos de inicio de un proyecto. "
            "Devuelve SOLO un JSON válido con esta forma exacta, sin texto adicional: "
            "{\"files\":[{\"path\":\"rel/ruta\",\"content\":\"...\"}]} "
            "Usa rutas relativas simples y contenido mínimo funcional CON CÓDIGO completo (sin placeholders como '...'). "
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


def research_urls(urls: List[str]) -> str:
    """Obtiene un resumen Markdown de múltiples URLs, evitando copiar código.
    Extrae título, meta descripción y encabezados/temas.
    """
    parts: list[str] = ["# Investigación", "\nNota: Este resumen evita incluir fragmentos de código. Solo recoge ideas, temas y referencias útiles."]
    for u in urls:
        try:
            html = _fetch_url(u)
            if not html:
                parts.append(f"\n## {u}\n(No HTML útil o tipo de contenido no soportado)")
                continue
            parts.append("\n" + _summarize_html(u, html))
        except Exception as e:
            parts.append(f"\n## {u}\nError al obtener: {e}")
    return "\n\n".join(parts).strip() + "\n"


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
    # Preguntar SIEMPRE por directorio destino, con default desde memoria o arg
    mem = get_config() or {}
    default_dir = args.dir or mem.get("project", {}).get("default_dir") or str(Path.cwd())
    try:
        user_in = input(f"Directorio destino del proyecto [{default_dir}]: ").strip()
    except EOFError:
        user_in = ""
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
        except Exception as e:
            print(f"[WARN] No se pudo generar AI_NOTES.md (modelo={model}): {e}")
        # Generar archivos por IA opcionalmente (iniciales)
        if ai_files_enabled:
            try:
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
                        rel = (f.get("path") or "").lstrip("/\\")
                        content = _sanitize_generated_content(f.get("content") or "")
                        target = (dst / rel).resolve()
                        if not str(target).startswith(str(dst.resolve())):
                            print(f"[SKIP] Ruta fuera del proyecto: {rel}")
                            continue
                        # Guardas: tamaño total y por archivo, y evitar binarios aparentes
                        content_bytes = content.encode("utf-8", errors="ignore")
                        size = len(content_bytes)
                        if size > max_file:
                            print(f"[SKIP] {rel}: supera el máximo por archivo ({size} > {max_file} bytes)")
                            continue
                        if used + size > max_total:
                            print(f"[STOP] Límite total de IA alcanzado ({used + size} > {max_total} bytes). Deteniendo escritura.")
                            break
                        if _is_probably_binary(content):
                            print(f"[SKIP] {rel}: contenido parece binario o no textual")
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
                                fromfile=str(target), tofile=f"new:{rel}", lineterm=""
                            )
                            print("\n--- Diff:")
                            for line in diff:
                                print(line)
                        else:
                            print(f"[SAME] Sin cambios para {rel}")
                        do_write = bool(getattr(args, "yes", False)) and not bool(getattr(args, "ask", False))
                        if not do_write:
                            ans = input(f"¿Escribir {rel}? (y/N): ").strip().lower()
                            do_write = ans in ("y", "s", "yes", "si")
                        if do_write:
                            write_file(target, content)
                            used += size
                            print(f"[OK] Escrito {rel}")
                    print("\n[OK] Revisión AI completada.")
            except Exception as e:
                print(f"[WARN] No se pudieron generar archivos AI: {e}")

        # Preguntar si desea aplicar mejoras y pasos de AI_NOTES.md
        notes_path = dst / "AI_NOTES.md"
        if notes_path.exists():
            proceed = auto_apply
            if not proceed:
                try:
                    apply_ans = input("¿Aplicar ahora las mejoras y pasos de AI_NOTES.md? (y/N): ").strip().lower()
                except EOFError:
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
                            rel = (f.get("path") or "").lstrip("/\\")
                            content = _sanitize_generated_content(f.get("content") or "")
                            target = (dst / rel).resolve()
                            if not str(target).startswith(str(dst.resolve())):
                                print(f"[SKIP] Ruta fuera del proyecto: {rel}")
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
                                print(f"[SKIP] {rel}: supera el máximo por archivo ({size} > {max_file2} bytes)")
                                continue
                            if used + size > max_total2:
                                print(f"[STOP] Límite total de IA alcanzado ({used + size} > {max_total2} bytes). Deteniendo escritura.")
                                break
                            if _is_probably_binary(content):
                                print(f"[SKIP] {rel}: contenido parece binario o no textual")
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
                                    fromfile=str(target), tofile=f"new:{rel}", lineterm=""
                                )
                                print("\n--- Diff:")
                                for line in diff:
                                    print(line)
                            else:
                                print(f"[SAME] Sin cambios para {rel}")
                            # Respetar --ask si se pasó, si no, usar yes por defecto
                            do_write = bool(getattr(args, "yes", True)) and not bool(getattr(args, "ask", False))
                            if not do_write:
                                ans = input(f"¿Escribir {rel}? (y/N): ").strip().lower()
                                do_write = ans in ("y", "s", "yes", "si")
                            if do_write:
                                write_file(target, content)
                                used += size
                                print(f"[OK] Escrito {rel}")
                        print("\n[OK] Aplicación de notas completada.")
    # Verificación rápida post-creación (lint/sintaxis y pruebas básicas si existen)
    try:
        _summary = verify_project(dst, stack)
        print(_summary)
    except Exception as e:
        print(f"[WARN] Verificación post-creación falló: {e}")
    # Smoke run: por defecto en stack 'python' simple, o si --smoke-run está presente; desactivable con --no-smoke-run
    smoke_default_python = (defaults_cfg.get("smoke_python_default") if isinstance(defaults_cfg, dict) else None)
    if smoke_default_python is None:
        smoke_default_python = True
    do_smoke = bool(getattr(args, "smoke_run", False)) or (stack == "python" and bool(smoke_default_python) and not bool(getattr(args, "no_smoke_run", False)))
    if do_smoke:
        try:
            ok, msg = smoke_run(dst, stack, timeout=int(getattr(args, "smoke_timeout", 5) or 5))
            print(msg)
        except Exception as e:
            print(f"[WARN] Smoke run falló: {e}")
    return 0


def cmd_assist(args: argparse.Namespace) -> int:
    # --fast fuerza un modelo ligero por ejecución
    if getattr(args, "fast", False):
        args.model = "phi3:mini"
    model = _ensure_model_available(_resolve_model(args.model))
    system = {
        "role": "system",
        "content": (
            "Eres un asistente que ayuda a clarificar peticiones ambiguas. "
            "Si la petición requiere más detalles, formula UNA pregunta específica y útil. "
            "Si ya hay suficiente contexto, responde claramente. "
            "Responde SIEMPRE en este formato JSON, sin texto adicional: "
            "{\"type\":\"question\",\"text\":\"...\"} o {\"type\":\"answer\",\"text\":\"...\"}."
        ),
    }
    messages: List[Dict[str, Any]] = [system, {"role": "user", "content": args.prompt}]
    while True:
        out = _ollama_chat(messages, model)
        # Intentar parsear JSON
        try:
            data = json.loads(out)
        except Exception:
            print(out)
            if not args.no_tts:
                speak(out)
            return 0
        t = (data or {}).get("type")
        text = (data or {}).get("text") or ""
        if t == "question":
            print(text)
            try:
                answer = input("> ").strip()
            except EOFError:
                return 0
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": answer})
            continue
        elif t == "answer":
            print(text)
            if not args.no_tts:
                speak(text)
            return 0
        else:
            print(out)
            return 0


def cmd_say(args: argparse.Namespace) -> int:
    said = speak(args.text)
    return 0 if said else 1


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
        rel = (f.get("path") or "").lstrip("/\\")
        content = _sanitize_generated_content(f.get("content") or "")
        target = (proj_dir / rel).resolve()
        if not str(target).startswith(str(proj_dir.resolve())):
            print(f"[SKIP] Ruta fuera del proyecto: {rel}")
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
                fromfile=str(target), tofile=f"new:{rel}", lineterm=""
            )
            print("\n--- Diff:")
            for line in diff:
                print(line)
        else:
            print(f"[SAME] Sin cambios para {rel}")
        do_write = getattr(args, "yes", False)
        if not do_write:
            ans = input(f"¿Escribir {rel}? (y/N): ").strip().lower()
            do_write = ans in ("y", "s", "yes", "si")
        if do_write:
            write_file(target, content)
            print(f"[OK] Escrito {rel}")
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
    # Por defecto: AI activado, archivos IA activados, escritura sin preguntar y aplicar notas automáticamente; sin límite de archivos
    p_project.set_defaults(func=cmd_project, ai=True, ai_files=True, yes=True, auto_apply_notes=True, max_files=0)

    p_say = sub.add_parser("say", help="Decir un texto con Piper TTS")
    p_say.add_argument("text")
    p_say.set_defaults(func=cmd_say)

    # Aplicar propuestas desde AI_NOTES.md al proyecto
    p_apply = sub.add_parser("apply-notes", help="Genera y aplica archivos desde AI_NOTES.md con revisión")
    p_apply.add_argument("--dir", default=str(Path.cwd()), help="Directorio del proyecto (por defecto: cwd)")
    p_apply.add_argument("--model", help="Modelo Ollama (por defecto PIPER_OLLAMA_MODEL o mistral:7b-instruct)")
    p_apply.add_argument("--fast", action="store_true", help="Usar modelo rápido (phi3:mini) en esta ejecución")
    p_apply.add_argument("-y", "--yes", action="store_true", help="Escribir sin preguntar por fichero")
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

    # Comando por defecto: project
    p.add_argument("default_prompt", nargs="?", help=argparse.SUPPRESS)
    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv[1:])
    if not getattr(args, "cmd", None):
        # Sin subcomando explícito -> asistente (para uso rápido tipo: piper "haz X")
        default_prompt = args.default_prompt or (argv[1] if len(argv) > 1 else None)
        if not default_prompt:
            parser.print_help(sys.stderr)
            return 2
        ns = argparse.Namespace(prompt=default_prompt, model=None, no_tts=False)
        return cmd_assist(ns)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
