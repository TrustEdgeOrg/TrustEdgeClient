from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from trustedge_wg.cli import CliConfig
from trustedge_wg.gui.privileged import (
    _log_shows_tunnel_up,
    _log_tail,
    _pid_alive,
    _read_tunnel_pid,
    _tunnel_pgrep_patterns,
    build_tunnel_argv,
)


def test_build_tunnel_argv_api_mode(tmp_user_data, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "trustedge_wg.gui.privileged._python_command",
        lambda: ["/Applications/TrustEdge.app/Contents/MacOS/trustedge-wg"],
    )
    monkeypatch.setattr(
        "trustedge_wg.gui.privileged.agent_state_path",
        lambda: tmp_user_data / "agent-state.json",
    )
    opts = CliConfig(
        api_url="https://api.example.com",
        api_token="bootstrap",
        stats_interval=5.0,
        install_policy_ca=True,
    )
    argv = build_tunnel_argv(opts)
    assert argv[0] == "/Applications/TrustEdge.app/Contents/MacOS/trustedge-wg"
    assert "--api-url" in argv
    assert "https://api.example.com" in argv
    assert "--api-token" in argv
    assert "--stats-interval" in argv
    assert "--install-policy-ca" in argv
    assert "--state" in argv
    assert str(tmp_user_data / "agent-state.json") in argv


def test_build_tunnel_argv_offline_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("trustedge_wg.gui.privileged._python_command", lambda: ["trustedge-wg"])
    opts = CliConfig(config_path="/tmp/client.conf", no_routing=True)
    argv = build_tunnel_argv(opts)
    assert "--config" in argv
    assert "/tmp/client.conf" in argv
    assert "--no-routing" in argv


def test_build_tunnel_argv_darwin_dns_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("trustedge_wg.gui.privileged._python_command", lambda: ["trustedge-wg"])
    assert "--no-apply-dns" in build_tunnel_argv(CliConfig(api_url="https://api.example.com", apply_dns=False))
    assert "--apply-dns" in build_tunnel_argv(CliConfig(api_url="https://api.example.com", apply_dns=True))


def test_log_shows_tunnel_up() -> None:
    lines = ["trustedge-wg: interface utun7 up"]
    assert _log_shows_tunnel_up(lines) is True
    assert _log_shows_tunnel_up(["noise", "other"]) is False


def test_log_tail(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "tunnel.log"
    log_path.write_text("\n".join(f"line {i}" for i in range(10)) + "\n", encoding="utf-8")
    monkeypatch.setattr("trustedge_wg.gui.log_reader.log_file", lambda uid=None: log_path)
    tail = _log_tail(max_lines=3)
    assert tail == "line 7\nline 8\nline 9"


def test_read_tunnel_pid(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    pid_path = tmp_path / "tunnel.pid"
    pid_path.write_text("4242\n", encoding="utf-8")
    monkeypatch.setattr("trustedge_wg.gui.privileged.pid_file", lambda uid=None: pid_path)
    assert _read_tunnel_pid() == 4242


def test_pid_alive_current_process() -> None:
    import os

    assert _pid_alive(os.getpid()) is True
    assert _pid_alive(2_000_000_000) is False


def test_tunnel_pgrep_patterns() -> None:
    assert _tunnel_pgrep_patterns() == [
        "TrustEdge.app/Contents/MacOS/trustedge-wg",
        "TrustEdge.app/Contents/MacOS/wireguard-go",
    ]
