import threading
from unittest.mock import MagicMock, patch

from trustedge_wg.cli import CliConfig
from trustedge_wg.network_attribution.monitor import start_network_attribution_monitor
from trustedge_wg.platform.process.darwin import ForegroundApp


def test_start_network_attribution_monitor_disabled():
    opts = CliConfig(network_attribution_enabled=False)
    assert start_network_attribution_monitor(opts, threading.Event(), device_id="d1", api_client=MagicMock()) is None


@patch("trustedge_wg.network_attribution.monitor.get_foreground_app")
def test_network_attribution_reports_batch(mock_fg):
    mock_fg.return_value = ForegroundApp(bundle_id="us.zoom.xos", name="zoom.us")
    api = MagicMock()
    shutdown = threading.Event()
    opts = CliConfig(
        api_url="https://api.example.com",
        network_attribution_enabled=True,
        network_attribution_poll_sec=0.05,
        network_attribution_report_sec=0.05,
    )
    api.device_token = "token"

    thread = start_network_attribution_monitor(
        opts,
        shutdown,
        device_id="dev-1",
        api_client=api,
    )
    assert thread is not None
    threading.Event().wait(0.2)
    shutdown.set()
    thread.join(timeout=1)

    assert api.report_network_attribution.called
    payload = api.report_network_attribution.call_args.kwargs
    assert payload["device_id"] == "dev-1"
    assert payload["intervals"]
    assert payload["intervals"][0]["bundle_id"] == "us.zoom.xos"
