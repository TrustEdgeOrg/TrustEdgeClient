from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from trustedge_wg.platform.process import get_foreground_app

if TYPE_CHECKING:
    from trustedge_wg.cli import CliConfig
    from trustedge_wg.enroll.api import Client

log = logging.getLogger("trustedge-wg")


def start_network_attribution_monitor(
    opts: CliConfig,
    shutdown_event: threading.Event,
    *,
    device_id: str = "",
    api_client: Client | None = None,
) -> threading.Thread | None:
    if not opts.network_attribution_enabled:
        return None
    if not api_client or not device_id or not api_client.device_token:
        if api_client and device_id and not api_client.device_token:
            log.warning(
                "network attribution skipped: missing device_token; reconnect so enroll can save one"
            )
        return None

    poll_sec = float(opts.network_attribution_poll_sec)
    report_sec = float(opts.network_attribution_report_sec)
    if poll_sec <= 0 or report_sec <= 0:
        return None

    def _loop() -> None:
        pending: list[dict] = []
        last_report = time.monotonic()
        usage_warned = False

        while not shutdown_event.wait(poll_sec):
            app = get_foreground_app()
            if app is None:
                continue

            started_at = datetime.now(timezone.utc)
            pending.append(
                {
                    "started_at": started_at.isoformat(),
                    "duration_sec": poll_sec,
                    "bundle_id": app.bundle_id,
                    "app_name": app.name,
                }
            )

            if time.monotonic() - last_report < report_sec:
                continue

            batch = pending
            pending = []
            last_report = time.monotonic()
            if not batch:
                continue

            try:
                api_client.report_network_attribution(
                    device_id=device_id,
                    intervals=batch,
                )
            except Exception as exc:
                log.warning("network attribution report: %s", exc)
                if not usage_warned:
                    log.warning(
                        "network attribution report failed (dashboard app usage will stay empty)"
                    )
                    usage_warned = True

    thread = threading.Thread(target=_loop, name="trustedge-attribution", daemon=True)
    thread.start()
    log.info(
        "network attribution every %.0fs poll / %.0fs report -> %s%s",
        poll_sec,
        report_sec,
        api_client.base_url,
        api_client.attribution_path,
    )
    return thread
