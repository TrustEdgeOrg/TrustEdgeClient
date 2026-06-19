from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from trustedge_wg.constants import (
    DEFAULT_ENROLL_PATH,
    DEFAULT_POLICY_CA_PATH,
    DEFAULT_STATS_INTERVAL,
    DEFAULT_USAGE_PATH,
    HTTP_CLIENT_TIMEOUT,
    MAX_ENROLL_RESPONSE_BYTES,
)

DEFAULT_CLIENT_CONFIG_PATH = "/v1/client-config"


@dataclass
class ServerConfig:
    enroll_bootstrap_token: str = ""
    enroll_path: str = DEFAULT_ENROLL_PATH
    usage_path: str = DEFAULT_USAGE_PATH
    policy_ca_path: str = DEFAULT_POLICY_CA_PATH
    stats_interval_sec: float = DEFAULT_STATS_INTERVAL
    install_policy_ca_default: bool = False
    service_name: str = "TrustEdge"
    policy_profile_slugs: list[str] = field(default_factory=list)


def fetch_server_config(
    base_url: str,
    *,
    config_path: str = DEFAULT_CLIENT_CONFIG_PATH,
) -> ServerConfig:
    base_url = base_url.strip().rstrip("/")
    if not base_url:
        raise ValueError("trustedge api: empty base URL")
    if not config_path:
        config_path = DEFAULT_CLIENT_CONFIG_PATH
    if not config_path.startswith("/"):
        config_path = "/" + config_path

    req = Request(base_url + config_path, method="GET")
    try:
        with urlopen(req, timeout=HTTP_CLIENT_TIMEOUT) as resp:
            raw = resp.read(MAX_ENROLL_RESPONSE_BYTES)
            status = resp.status
    except HTTPError as e:
        err_body = e.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace").strip()
        raise RuntimeError(
            f"trustedge api: client-config {config_path} returned {e.code}: {err_body}"
        ) from e
    except URLError as e:
        raise RuntimeError(f"trustedge api: client-config download: {e}") from e

    if status < 200 or status >= 300:
        raise RuntimeError(
            f"trustedge api: client-config {config_path} returned {status}: "
            f"{raw.decode(errors='replace')}"
        )

    obj: dict[str, Any] = json.loads(raw.decode())
    return ServerConfig(
        enroll_bootstrap_token=str(obj.get("enroll_bootstrap_token") or "").strip(),
        enroll_path=str(obj.get("enroll_path") or DEFAULT_ENROLL_PATH).strip() or DEFAULT_ENROLL_PATH,
        usage_path=str(obj.get("usage_path") or DEFAULT_USAGE_PATH).strip() or DEFAULT_USAGE_PATH,
        policy_ca_path=str(obj.get("policy_ca_path") or DEFAULT_POLICY_CA_PATH).strip()
        or DEFAULT_POLICY_CA_PATH,
        stats_interval_sec=max(0.0, float(obj.get("stats_interval_sec") or DEFAULT_STATS_INTERVAL)),
        install_policy_ca_default=bool(obj.get("install_policy_ca_default", False)),
        service_name=str(obj.get("service_name") or "TrustEdge").strip() or "TrustEdge",
        policy_profile_slugs=[
            str(slug).strip() for slug in (obj.get("policy_profile_slugs") or []) if str(slug).strip()
        ],
    )


def apply_server_config(opts, server: ServerConfig):
    """Merge server-provided defaults into CliConfig (CLI flags keep precedence)."""
    from trustedge_wg.cli import CliConfig

    stats_interval = opts.stats_interval
    if stats_interval in (0.0, DEFAULT_STATS_INTERVAL):
        stats_interval = server.stats_interval_sec

    return replace(
        opts,
        api_token=opts.api_token or server.enroll_bootstrap_token,
        api_enroll_path=server.enroll_path,
        api_usage_path=server.usage_path,
        api_policy_ca_path=server.policy_ca_path,
        stats_interval=stats_interval,
        install_policy_ca=opts.install_policy_ca or server.install_policy_ca_default,
    )
