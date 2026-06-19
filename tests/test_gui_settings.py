from __future__ import annotations

import json
from pathlib import Path

from trustedge_wg.constants import ENV_API_URL
from trustedge_wg.gui.settings import GuiSettings
from trustedge_wg.server_config import ServerConfig


def test_gui_settings_load_merges_saved_and_env(tmp_path: Path, monkeypatch) -> None:
    settings_file = tmp_path / "gui-settings.json"
    settings_file.write_text(
        json.dumps({"api_url": "https://saved.example.com"}),
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_API_URL, "https://env.example.com")
    server = ServerConfig(enroll_bootstrap_token="server-token")
    with monkeypatch.context() as m:
        m.setattr(GuiSettings, "fetch_server_config", lambda self: server)
        loaded = GuiSettings.load(settings_file)
    assert loaded.api_url == "https://saved.example.com"
    assert loaded.api_token == "server-token"


def test_gui_settings_from_env_only(monkeypatch) -> None:
    monkeypatch.setenv(ENV_API_URL, "https://env.example.com")
    settings = GuiSettings.from_env()
    assert settings.api_url == "https://env.example.com"
    assert settings.api_token == ""


def test_gui_settings_with_defaults_prefers_saved_over_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(ENV_API_URL, "https://env.example.com")
    saved = GuiSettings(api_url="https://saved.example.com")
    server = ServerConfig(enroll_bootstrap_token="server-token")
    with monkeypatch.context() as m:
        m.setattr(GuiSettings, "fetch_server_config", lambda self: server)
        merged = saved.with_defaults()
    assert merged.api_url == "https://saved.example.com"
    assert merged.api_token == "server-token"
