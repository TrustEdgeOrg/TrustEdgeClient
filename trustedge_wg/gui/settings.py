from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from trustedge_wg import env
from trustedge_wg.paths import user_data_dir
from trustedge_wg.server_config import ServerConfig, fetch_server_config


def settings_path() -> Path:
    return user_data_dir() / "gui-settings.json"


def tunnel_runtime_dir(uid: int | None = None) -> Path:
    """Per-user runtime files; tunnel (root) and GUI (user) must use the same path."""
    user_id = os.getuid() if uid is None else uid
    return Path(f"/tmp/trustedge-wg-{user_id}")


def pid_file(uid: int | None = None) -> Path:
    return tunnel_runtime_dir(uid) / "tunnel.pid"


def log_file(uid: int | None = None) -> Path:
    return tunnel_runtime_dir(uid) / "tunnel.log"


@dataclass
class GuiSettings:
    api_url: str = ""
    api_token: str = ""
    install_policy_ca: bool = False

    @classmethod
    def from_env(cls) -> GuiSettings:
        return cls(api_url=env.api_url())

    def fetch_server_config(self) -> ServerConfig | None:
        api_url = self.api_url.strip()
        if not api_url:
            return None
        try:
            return fetch_server_config(api_url)
        except RuntimeError:
            return None

    @classmethod
    def load(cls, path: Path | None = None) -> GuiSettings:
        target = path or settings_path()
        saved = cls()
        try:
            if target.is_file():
                data = json.loads(target.read_text(encoding="utf-8"))
                saved = cls(
                    api_url=str(data.get("api_url", "")).strip(),
                    install_policy_ca=bool(data.get("install_policy_ca", False)),
                )
        except (OSError, PermissionError, json.JSONDecodeError):
            pass
        return saved.with_defaults()

    def with_defaults(self) -> GuiSettings:
        """Saved settings, then .env API URL override, then server bootstrap config."""
        from_env = self.from_env()
        merged = GuiSettings(
            api_url=self.api_url or from_env.api_url,
            install_policy_ca=self.install_policy_ca,
        )
        server = merged.fetch_server_config()
        if server is None:
            return merged
        return GuiSettings(
            api_url=merged.api_url,
            api_token=server.enroll_bootstrap_token,
            install_policy_ca=merged.install_policy_ca or server.install_policy_ca_default,
        )

    def missing_api_url_message(self) -> str:
        env_path = user_data_dir() / ".env"
        return (
            "No API URL configured.\n\n"
            f"Create {env_path} with:\n"
            "TRUSTEDGE_API_URL=https://your-api.example.com"
        )
