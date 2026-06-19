from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from trustedge_wg import env
from trustedge_wg.constants import (
    DEFAULT_ENROLL_PATH,
    DEFAULT_POLICY_CA_PATH,
    DEFAULT_STATS_INTERVAL,
    DEFAULT_USAGE_PATH,
    DEFAULT_WINTUN_NAME,
    ENV_API_TOKEN,
    ENV_API_URL,
)
from trustedge_wg.paths import agent_state_path


@dataclass
class CliConfig:
    config_path: str = ""
    api_url: str = ""
    api_token: str = ""
    api_enroll_path: str = DEFAULT_ENROLL_PATH
    state_path: str = ""
    config_out: str = ""
    interface: str = "wg0"
    no_routing: bool = False
    apply_dns: bool = False
    dns_service: str = ""
    stats_interval: float = 0.0
    stats_file: str = ""
    api_usage_path: str = DEFAULT_USAGE_PATH
    api_policy_ca_path: str = DEFAULT_POLICY_CA_PATH
    install_policy_ca: bool = False

    def resolve_state_path(self) -> str:
        if self.state_path.strip():
            return self.state_path.strip()
        return str(agent_state_path())

    def wintun_adapter_name(self) -> str:
        if sys.platform == "win32" and self.interface == "wg0":
            return DEFAULT_WINTUN_NAME
        return self.interface


def usage_text() -> str:
    api_default = env.api_url() or f"(set {ENV_API_URL} in Application Support/.env)"
    return f"""usage:
  Offline:  trustedge-wg --config /path/to/client.conf [--no-routing]
  API:      trustedge-wg [--api-url URL] [--api-token TOKEN] [--state PATH] [--config-out PATH]

  Default API URL: {api_default}
  Override via --api-url, {ENV_API_URL} in Application Support/.env, or GUI Settings
"""


def parse_cli(argv: list[str] | None = None) -> CliConfig:
    p = argparse.ArgumentParser(
        prog="trustedge-wg",
        description="TrustEdge userspace WireGuard client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_text(),
    )
    p.add_argument("--config", default="", help="WireGuard .conf (offline; ignores --api-url)")
    p.add_argument("--api-url", default=env.api_url(), help="TrustEdge API base URL")
    p.add_argument("--api-token", default=env.api_token(), help="Bearer token (enroll bootstrap)")
    p.add_argument("--api-enroll-path", default=DEFAULT_ENROLL_PATH, help="Enroll path")
    p.add_argument("--state", default="", help="Agent state JSON path")
    p.add_argument("--config-out", default="", help="Write merged .conf after enroll")
    p.add_argument(
        "-interface",
        "--interface",
        dest="interface",
        default="wg0",
        help="Linux TUN name; Windows Wintun name (wg0→TrustEdge); macOS uses utun",
    )
    p.add_argument("--no-routing", action="store_true", help="WireGuard only, no system routes")
    if sys.platform == "darwin":
        p.add_argument(
            "--apply-dns",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Apply DNS from config on macOS (default: on; use --no-apply-dns to disable)",
        )
    else:
        p.add_argument(
            "--apply-dns",
            action="store_true",
            help="Apply DNS from config while tunnel is up (macOS only)",
        )
    p.add_argument("--dns-service", default="", help='macOS network service (e.g. "Wi-Fi")')
    p.add_argument(
        "--stats-interval",
        type=float,
        default=0.0,
        metavar="SEC",
        help=(
            f"Report tunnel traffic every SEC seconds to {DEFAULT_USAGE_PATH} when using "
            f"--api-url (default {DEFAULT_STATS_INTERVAL:g}s; use 0 to disable)"
        ),
    )
    p.add_argument(
        "--stats-file",
        default="",
        help="Append JSON lines of traffic samples to this file",
    )
    p.add_argument(
        "--api-usage-path",
        default=DEFAULT_USAGE_PATH,
        help="With --api-url and --stats-interval: POST usage to this path",
    )
    p.add_argument(
        "--install-policy-ca",
        action="store_true",
        help="macOS: download TrustEdge Policy CA from API and trust it (sudo) for HTTPS block page",
    )
    p.add_argument(
        "--api-policy-ca-path",
        default=DEFAULT_POLICY_CA_PATH,
        help="Path for block-page CA PEM (default: /policy/block-page-ca)",
    )

    args = p.parse_args(argv)
    stats_interval = max(0.0, float(args.stats_interval))
    if stats_interval == 0.0 and args.api_url.strip() and not args.config.strip():
        stats_interval = DEFAULT_STATS_INTERVAL
    return CliConfig(
        config_path=args.config,
        api_url=args.api_url,
        api_token=args.api_token,
        api_enroll_path=args.api_enroll_path,
        state_path=args.state,
        config_out=args.config_out,
        interface=args.interface,
        no_routing=args.no_routing,
        apply_dns=args.apply_dns,
        dns_service=args.dns_service,
        stats_interval=stats_interval,
        stats_file=args.stats_file,
        api_usage_path=args.api_usage_path,
        api_policy_ca_path=args.api_policy_ca_path,
        install_policy_ca=args.install_policy_ca,
    )
