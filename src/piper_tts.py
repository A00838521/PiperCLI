#!/usr/bin/env python3
"""
Mínimo backend TTS para Piper en Linux.
Preferencias:
- spd-say (Speech Dispatcher)
- espeak-ng
- espeak
Si no hay TTS disponible, retorna False sin lanzar excepciones.
"""
from __future__ import annotations
import shutil
import subprocess
import sys


def _run(cmd: list[str], timeout: int = 15) -> bool:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0
    except Exception:
        return False


def speak(text: str, lang: str = "es") -> bool:
    if not text:
        return False
    # Limitar longitud para TTS de línea de comandos
    text = text.strip().replace("\n", " ")
    if len(text) > 300:
        text = text[:297] + "..."

    # 1) spd-say (Speech Dispatcher)
    if shutil.which("spd-say"):
        # -l es para español; --wait para bloquear hasta terminar (opcional)
        if _run(["spd-say", "-l", lang, text]):
            return True
    # 2) espeak-ng
    if shutil.which("espeak-ng"):
        if _run(["espeak-ng", "-v", lang, text]):
            return True
    # 3) espeak clásico
    if shutil.which("espeak"):
        if _run(["espeak", "-v", lang, text]):
            return True
    return False
