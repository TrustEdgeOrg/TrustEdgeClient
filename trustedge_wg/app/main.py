from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import threading

from trustedge_wg.agent.state import ensure_agent_state
from trustedge_wg.cli import CliConfig, parse_cli, usage_text
from trustedge_wg.constants import CACHED_WG_CONF_PERM
from trustedge_wg.enroll.api import Client, EnrollRequest, wireguard_from_enroll
from trustedge_wg.enroll.public_ip import fetch_public_ipv4
from trustedge_wg.wireguard.config import load_config, render_wireguard_conf
from trustedge_wg.platform.trust_ca import install_policy_ca_if_requested
from trustedge_wg.wireguard.tunnel import normalize_endpoint, run_tunnel

log = logging.getLogger("trustedge-wg")


def resolve_wireguard_config(opts: CliConfig):
    has_file = bool(opts.config_path.strip())
    has_api = bool(opts.api_url.strip())

    if has_file and has_api:
        raise RuntimeError("choose one of --config or --api-url, not both")
    if has_file:
        if not os.path.isfile(opts.config_path):
            raise RuntimeError(
                f"config file not found: {opts.config_path}\n\n"
                "Create one from the example, then edit keys and Endpoint:\n"
                "  cp client.example.conf my.conf\n"
                "  sudo trustedge-wg --config ./my.conf"
            )
        return load_config(opts.config_path)
    if has_api:
        st = ensure_agent_state(opts.resolve_state_path())
        pub = st.public_key()
        client = Client(
            opts.api_url,
            opts.api_token,
            enroll_path=opts.api_enroll_path,
        )
        host = socket.gethostname()
        public_ip = fetch_public_ipv4()
        resp = client.enroll(
            EnrollRequest(
                device_id=st.device_id,
                public_key=pub,
                hostname=host.strip(),
                client_public_ip=public_ip,
            )
        )
        if resp.device_token.strip():
            st.device_token = resp.device_token.strip()
            st.save(opts.resolve_state_path())
        cfg = wireguard_from_enroll(st.private_key, resp)
        log.info(
            "enroll ok endpoint=%s address=%s dns=%s",
            cfg.endpoint,
            ",".join(cfg.address) or resp.address,
            ",".join(cfg.dns) or ",".join(resp.dns),
        )
        if opts.config_out.strip():
            with open(opts.config_out, "w", encoding="utf-8") as f:
                f.write(render_wireguard_conf(cfg))
            os.chmod(opts.config_out, CACHED_WG_CONF_PERM)
        return cfg
    raise RuntimeError(usage_text().strip())


def _shutdown_event():
    ev = threading.Event()
    signals = [signal.SIGINT]
    if sys.platform != "win32":
        signals.append(signal.SIGTERM)

    def handler(_signum, _frame):
        ev.set()

    for sig in signals:
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass
    return ev


def run(opts: CliConfig) -> None:
    cfg = resolve_wireguard_config(opts)
    _ = normalize_endpoint(cfg.endpoint)
    device_id = ""
    api_client = None
    if opts.api_url.strip():
        st = ensure_agent_state(opts.resolve_state_path())
        device_id = st.device_id
        api_client = Client(
            opts.api_url,
            opts.api_token,
            device_token=st.device_token,
            enroll_path=opts.api_enroll_path,
            usage_path=opts.api_usage_path,
            attribution_path=opts.api_attribution_path,
            policy_ca_path=opts.api_policy_ca_path,
        )
        if opts.stats_interval > 0 and not st.device_token.strip():
            log.warning(
                "usage reporting disabled: no device_token in state (enroll first); "
                "dashboard live bandwidth will stay empty"
            )
        elif opts.stats_interval > 0:
            log.info(
                "usage reports every %.0fs to %s%s",
                opts.stats_interval,
                opts.api_url.rstrip("/"),
                opts.api_usage_path,
            )
    install_policy_ca_if_requested(opts, api_client)
    run_tunnel(
        cfg,
        opts,
        _shutdown_event(),
        device_id=device_id,
        api_client=api_client,
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="trustedge-wg: %(message)s")
    try:
        opts = parse_cli(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        run(opts)
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        log.error("%s", e)
        return 1
    return 0
