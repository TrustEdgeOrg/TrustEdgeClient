from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ForegroundApp:
    bundle_id: str
    name: str


def get_foreground_app() -> ForegroundApp | None:
    if sys.platform != "darwin":
        return None

    script = (
        'tell application "System Events" to get {bundle identifier, name} '
        "of first application process whose frontmost is true"
    )
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None

    text = (proc.stdout or "").strip()
    if not text or text == "missing value":
        return None

    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        parts = [p.strip() for p in inner.split(",") if p.strip()]
        if len(parts) >= 2:
            return ForegroundApp(bundle_id=parts[0], name=parts[1])

    return ForegroundApp(bundle_id="", name=text)
