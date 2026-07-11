from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass

log = logging.getLogger("trustedge-wg")

_LSAPPINFO = "/usr/bin/lsappinfo"
_OSASCRIPT = "/usr/bin/osascript"

_INVALID_BUNDLE_IDS = frozenset(
    {
        "com.apple.loginwindow",
        "com.apple.WindowManager",
    }
)
_INVALID_NAMES = frozenset({"loginwindow", "windowmanager", "login window"})

_KV_RE = re.compile(r'"([^"]+)"="([^"]*)"')


@dataclass(frozen=True)
class ForegroundApp:
    bundle_id: str
    name: str


_FOREGROUND_SCRIPT = (
    'tell application "System Events" to get {bundle identifier, name} '
    "of first application process whose frontmost is true"
)

_foreground_failure_logged = False


def _console_uid() -> int | None:
    try:
        proc = subprocess.run(
            ["stat", "-f", "%u", "/dev/console"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        uid = int((proc.stdout or "").strip())
    except ValueError:
        return None
    if uid <= 0:
        return None
    return uid


def _run_as_console_user(argv: list[str], *, timeout: float = 5) -> subprocess.CompletedProcess[str]:
    """Run a command in the logged-in GUI session (required when tunnel runs as root)."""
    if os.geteuid() == 0:
        uid = _console_uid()
        if uid:
            return subprocess.run(
                ["launchctl", "asuser", str(uid), *argv],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _parse_lsappinfo_kv(text: str) -> dict[str, str]:
    return {key: value for key, value in _KV_RE.findall(text or "")}


def _is_valid_foreground(bundle_id: str, name: str) -> bool:
    bundle = bundle_id.strip().lower()
    display = name.strip().lower()
    if not bundle and not display:
        return False
    if bundle in _INVALID_BUNDLE_IDS:
        return False
    if display in _INVALID_NAMES:
        return False
    return True


def _from_lsappinfo() -> ForegroundApp | None:
    front = _run_as_console_user([_LSAPPINFO, "front"], timeout=3)
    if front.returncode != 0:
        return None

    asn = (front.stdout or "").strip().splitlines()[0].strip()
    if not asn.startswith("ASN:"):
        return None

    info = _run_as_console_user(
        [_LSAPPINFO, "info", "-only", "bundleID,LSDisplayName", asn],
        timeout=3,
    )
    if info.returncode != 0:
        return None

    fields = _parse_lsappinfo_kv(info.stdout or "")
    bundle_id = (fields.get("CFBundleIdentifier") or fields.get("bundleID") or "").strip()
    name = (fields.get("LSDisplayName") or fields.get("name") or "").strip()
    if not _is_valid_foreground(bundle_id, name):
        return None
    return ForegroundApp(bundle_id=bundle_id, name=name)


def _from_osascript() -> ForegroundApp | None:
    proc = _run_as_console_user([_OSASCRIPT, "-e", _FOREGROUND_SCRIPT], timeout=8)
    if proc.returncode != 0:
        return None

    text = (proc.stdout or "").strip()
    if not text or text == "missing value":
        return None

    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        parts = [p.strip() for p in inner.split(",") if p.strip()]
        if len(parts) >= 2:
            app = ForegroundApp(bundle_id=parts[0], name=parts[1])
            if _is_valid_foreground(app.bundle_id, app.name):
                return app
            return None

    app = ForegroundApp(bundle_id="", name=text)
    if _is_valid_foreground(app.bundle_id, app.name):
        return app
    return None


def _log_foreground_failure() -> None:
    global _foreground_failure_logged
    if _foreground_failure_logged:
        return
    _foreground_failure_logged = True
    log.warning(
        "foreground app detection failed (tried lsappinfo + osascript in console session); "
        "network attribution needs a normal frontmost app while connected"
    )


def get_foreground_app() -> ForegroundApp | None:
    if sys.platform != "darwin":
        return None

    try:
        app = _from_lsappinfo()
        if app is not None:
            return app
        app = _from_osascript()
        if app is not None:
            return app
    except (OSError, subprocess.TimeoutExpired):
        _log_foreground_failure()
        return None

    _log_foreground_failure()
    return None
