from __future__ import annotations

import os
from pathlib import Path

from trustedge_wg.constants import ENV_API_TOKEN, ENV_API_URL

_loaded = False


def _load_dotenv_file(path: Path, *, override: bool = False) -> None:
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value


def load_dotenv() -> None:
    global _loaded
    if _loaded:
        return
    try:
        from trustedge_wg.paths import user_data_dir

        _load_dotenv_file(user_data_dir() / ".env", override=True)
    except OSError:
        pass
    _loaded = True


def api_url() -> str:
    load_dotenv()
    return os.environ.get(ENV_API_URL, "").strip()


def api_token() -> str:
    load_dotenv()
    return os.environ.get(ENV_API_TOKEN, "").strip()
