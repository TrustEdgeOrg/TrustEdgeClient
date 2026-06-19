from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from urllib.error import HTTPError, URLError

from trustedge_wg.cli import CliConfig
from trustedge_wg.constants import DEFAULT_ENROLL_PATH, DEFAULT_STATS_INTERVAL, DEFAULT_USAGE_PATH
from trustedge_wg.server_config import ServerConfig, apply_server_config, fetch_server_config
from tests.helpers import mock_urlopen_response


def test_fetch_server_config_parses_response() -> None:
    body = {
        "enroll_bootstrap_token": "bootstrap-secret",
        "enroll_path": "/v1/enroll",
        "usage_path": "/v1/usage",
        "policy_ca_path": "/policy/block-page-ca",
        "stats_interval_sec": 8.0,
        "install_policy_ca_default": True,
        "service_name": "My TrustEdge",
        "policy_profile_slugs": ["teen", "kids"],
    }
    with patch("trustedge_wg.server_config.urlopen", return_value=mock_urlopen_response(body)):
        cfg = fetch_server_config("https://api.example.com/")

    assert cfg.enroll_bootstrap_token == "bootstrap-secret"
    assert cfg.stats_interval_sec == 8.0
    assert cfg.install_policy_ca_default is True
    assert cfg.service_name == "My TrustEdge"
    assert cfg.policy_profile_slugs == ["teen", "kids"]


def test_fetch_server_config_http_error() -> None:
    err = HTTPError(
        "https://api.example.com/v1/client-config",
        503,
        "Unavailable",
        hdrs=None,
        fp=None,
    )
    with patch("trustedge_wg.server_config.urlopen", side_effect=err):
        with pytest.raises(RuntimeError, match="returned 503"):
            fetch_server_config("https://api.example.com")


def test_fetch_server_config_network_error() -> None:
    with patch("trustedge_wg.server_config.urlopen", side_effect=URLError("timeout")):
        with pytest.raises(RuntimeError, match="client-config download"):
            fetch_server_config("https://api.example.com")


def test_apply_server_config_uses_server_defaults() -> None:
    opts = CliConfig(api_url="https://api.example.com", stats_interval=DEFAULT_STATS_INTERVAL)
    server = ServerConfig(
        enroll_bootstrap_token="from-server",
        stats_interval_sec=12.0,
        install_policy_ca_default=True,
    )
    merged = apply_server_config(opts, server)
    assert merged.api_token == "from-server"
    assert merged.api_enroll_path == DEFAULT_ENROLL_PATH
    assert merged.api_usage_path == DEFAULT_USAGE_PATH
    assert merged.stats_interval == 12.0
    assert merged.install_policy_ca is True


def test_apply_server_config_keeps_cli_overrides() -> None:
    opts = CliConfig(
        api_url="https://api.example.com",
        api_token="cli-token",
        stats_interval=3.0,
        install_policy_ca=False,
    )
    server = ServerConfig(
        enroll_bootstrap_token="from-server",
        stats_interval_sec=12.0,
        install_policy_ca_default=True,
    )
    merged = apply_server_config(opts, server)
    assert merged.api_token == "cli-token"
    assert merged.stats_interval == 3.0
    assert merged.install_policy_ca is False
