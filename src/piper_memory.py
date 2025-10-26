#!/usr/bin/env python3
"""
Persistencia ligera para Piper (configuración por usuario).
Archivo: ~/.local/share/piper/config.json (o $PIPER_STATE_DIR/config.json si está definido).
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict


def _state_dir() -> Path:
    base = os.environ.get("PIPER_STATE_DIR")
    if base:
        return Path(base).expanduser()
    # XDG-like por defecto
    return Path.home() / ".local" / "share" / "piper"


def _config_path() -> Path:
    d = _state_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "config.json"


def get_config() -> Dict[str, Any]:
    p = _config_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(cfg: Dict[str, Any]) -> None:
    p = _config_path()
    tmp = p.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)
    except Exception:
        # Intento simple en caso de filesystems sin atomic replace
        p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
