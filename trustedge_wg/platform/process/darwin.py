from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ForegroundApp:
    bundle_id: str
    name: str


_FOREGROUND_SCRIPT = (
    'tell application "System Events" to get {bundle identifier, name} '
    "of first application process whose frontmost is true"
)


def _console_user() -> str | None:
    try:
        proc = subprocess.run(
            ["stat", "-f", "%Su", "/dev/console"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    user = (proc.stdout or "").strip()
    if not user or user == "root":
        return None
    return user


def _run_osascript(script: str) -> subprocess.CompletedProcess[str]:
    """Run AppleScript; when root (GUI tunnel), run as the logged-in console user."""
    if os.geteuid() == 0:
        user = _console_user()
        if user:
            cmd = f"/usr/bin/osascript -e {shlex.quote(script)}"
            return subprocess.run(
                ["su", user, "-c", cmd],
                capture_output=True,
                text=True,
                timeout=8,
            )
    return subprocess.run(
        ["/usr/bin/osascript", "-e", script],
        capture_output=True,
        text=True,
        timeout=5,
    )


def get_foreground_app() -> ForegroundApp | None:
    if sys.platform != "darwin":
        return None

    try:
        proc = _run_osascript(_FOREGROUND_SCRIPT)
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
