from __future__ import annotations

import json
import stat
from unittest.mock import patch

import pytest

from trustedge_wg.agent.state import AgentState
from trustedge_wg.app.main import main, resolve_wireguard_config, run
from trustedge_wg.cli import CliConfig
from trustedge_wg.constants import CACHED_WG_CONF_PERM
from trustedge_wg.server_config import ServerConfig
from trustedge_wg.wireguard.config import parse_wireguard_config, render_wireguard_conf
from tests.helpers import mock_urlopen_response


def test_resolve_wireguard_config_rejects_config_and_api() -> None:
    opts = CliConfig(config_path="/tmp/x.conf", api_url="https://api.example.com")
    with pytest.raises(RuntimeError, match="choose one"):
        resolve_wireguard_config(opts)


def test_resolve_wireguard_config_missing_offline_file() -> None:
    opts = CliConfig(config_path="/nonexistent/client.conf")
    with pytest.raises(RuntimeError, match="config file not found"):
        resolve_wireguard_config(opts)


def test_resolve_wireguard_config_offline_file(
    tmp_path,
    sample_wireguard_ini: str,
    private_key: str,
    public_key: str,
) -> None:
    conf = tmp_path / "client.conf"
    conf.write_text(sample_wireguard_ini, encoding="utf-8")
    opts = CliConfig(config_path=str(conf))
    cfg = resolve_wireguard_config(opts)
    assert cfg.private_key == private_key
    assert cfg.public_key == public_key


def test_resolve_wireguard_config_enroll_integration(
    tmp_path,
    private_key: str,
    public_key: str,
) -> None:
    state_path = tmp_path / "agent-state.json"
    AgentState(device_id="device-abc", private_key=private_key).save(str(state_path))
    config_out = tmp_path / "cached.conf"

    enroll_body = {
        "server_public_key": public_key,
        "endpoint": "gw.example.com:51820",
        "address": "10.0.0.3/32",
        "dns": ["10.0.0.1"],
        "allowed_ips": ["0.0.0.0/0"],
        "device_token": "device-token-123",
        "persistent_keepalive": 25,
    }

    opts = CliConfig(
        api_url="https://api.example.com",
        api_token="bootstrap-token",
        state_path=str(state_path),
        config_out=str(config_out),
    )

    server_cfg = ServerConfig(enroll_bootstrap_token="bootstrap-token")

    with (
        patch("trustedge_wg.app.main.fetch_server_config", return_value=server_cfg),
        patch("trustedge_wg.app.main.apply_server_config", side_effect=lambda o, _s: o),
        patch("trustedge_wg.enroll.api.urlopen", return_value=mock_urlopen_response(enroll_body)),
        patch("trustedge_wg.app.main.fetch_public_ipv4", return_value="203.0.113.10"),
    ):
        cfg = resolve_wireguard_config(opts)

    assert cfg.private_key == private_key
    assert cfg.public_key == public_key
    assert cfg.endpoint == "gw.example.com:51820"
    assert cfg.address == ["10.0.0.3/32"]

    assert config_out.is_file()
    reparsed = parse_wireguard_config(config_out.open(encoding="utf-8"))
    assert reparsed.private_key == private_key
    assert reparsed.endpoint == cfg.endpoint
    assert stat.S_IMODE(config_out.stat().st_mode) == CACHED_WG_CONF_PERM

    saved_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved_state["device_token"] == "device-token-123"

    rendered = render_wireguard_conf(cfg)
    assert "Endpoint = gw.example.com:51820" in rendered


def test_resolve_wireguard_config_requires_api_or_config() -> None:
    opts = CliConfig()
    with pytest.raises(RuntimeError, match="usage:"):
        resolve_wireguard_config(opts)


def test_main_help_exits_zero() -> None:
    assert main(["--help"]) == 0


def test_main_missing_config_returns_one() -> None:
    assert main(["--config", "/nonexistent/client.conf"]) == 1


def test_run_invokes_tunnel_lifecycle(
    tmp_path,
    sample_wireguard_ini: str,
    monkeypatch,
) -> None:
    conf = tmp_path / "client.conf"
    conf.write_text(sample_wireguard_ini, encoding="utf-8")
    opts = CliConfig(config_path=str(conf))
    called: dict[str, bool] = {}

    def fake_run_tunnel(*_args, **_kwargs) -> None:
        called["tunnel"] = True

    monkeypatch.setattr("trustedge_wg.app.main.run_tunnel", fake_run_tunnel)
    monkeypatch.setattr("trustedge_wg.app.main.install_policy_ca_if_requested", lambda *_a, **_k: None)
    run(opts)
    assert called["tunnel"] is True
