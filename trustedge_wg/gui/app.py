from __future__ import annotations

import sys

from trustedge_wg import env

env.load_dotenv()

import rumps
from rumps import events

from trustedge_wg.cli import CliConfig
from trustedge_wg.constants import DEFAULT_STATS_INTERVAL
from trustedge_wg.server_config import apply_server_config
from trustedge_wg.gui.connection_panel import refresh_connection_panel, show_connection_panel
from trustedge_wg.gui.connection_view import (
    ConnectionSnapshot,
    build_connection_snapshot,
    menu_detail_lines,
)
from trustedge_wg.gui.icons import status_icon_path
from trustedge_wg.gui.privileged import (
    cleanup_orphan_tunnel,
    is_gui_tunnel_connected,
    start_tunnel,
    stop_tunnel,
)
from trustedge_wg.gui.settings import GuiSettings
from trustedge_wg.gui.tunnel_session import clear_tunnel_session, mark_tunnel_session

_STATUS_CONNECTED = "Connected"
_STATUS_DISCONNECTED = "Disconnected"


class TrustEdgeMenuBarApp(rumps.App):
    def __init__(self) -> None:
        super().__init__(
            "TrustEdge",
            title=None,
            icon=status_icon_path(connected=False),
            quit_button="Quit TrustEdge",
            template=True,
        )
        self.settings = GuiSettings.load()
        self.status_item = rumps.MenuItem(_STATUS_DISCONNECTED, callback=None)
        self.detail_heading = rumps.MenuItem("Connection", callback=None)
        self.detail_line1 = rumps.MenuItem("", callback=None)
        self.detail_line2 = rumps.MenuItem("", callback=None)
        self.detail_line3 = rumps.MenuItem("", callback=None)
        self.connect_item = rumps.MenuItem("Connect", callback=None)
        self.disconnect_item = rumps.MenuItem("Disconnect", callback=None)
        events.before_quit.register(self._disconnect_on_quit)
        cleanup_orphan_tunnel()
        self.menu = [
            self.status_item,
            None,
            self.detail_heading,
            self.detail_line1,
            self.detail_line2,
            self.detail_line3,
            None,
            "Connection Details…",
            self.connect_item,
            self.disconnect_item,
        ]
        self._refresh_status()

    def _snapshot(self, *, include_public_ip: bool = False) -> ConnectionSnapshot:
        self.settings = self.settings.with_defaults()
        return build_connection_snapshot(
            connected=is_gui_tunnel_connected(),
            api_url=self.settings.api_url,
            include_public_ip=include_public_ip,
        )

    def _refresh_status(self) -> None:
        snapshot = self._snapshot()
        connected = snapshot.connected

        self.status_item.title = _STATUS_CONNECTED if connected else _STATUS_DISCONNECTED
        self.icon = status_icon_path(connected=connected)

        line1, line2, line3 = menu_detail_lines(snapshot)
        self.detail_line1.title = line1
        self.detail_line2.title = line2
        self.detail_line3.title = line3

        if connected:
            self.connect_item.set_callback(None)
            self.disconnect_item.set_callback(self.disconnect)
        else:
            self.connect_item.set_callback(self.connect)
            self.disconnect_item.set_callback(None)

        refresh_connection_panel(snapshot)

    def _cli_config(self) -> CliConfig:
        base = CliConfig(
            api_url=self.settings.api_url,
            api_token=self.settings.api_token,
            apply_dns=True,
            install_policy_ca=self.settings.install_policy_ca,
            stats_interval=DEFAULT_STATS_INTERVAL,
        )
        server = self.settings.fetch_server_config()
        if server is None:
            return base
        return apply_server_config(base, server)

    @rumps.timer(2)
    def poll_status(self, _: rumps.Timer) -> None:
        self._refresh_status()

    def connect(self, _: rumps.MenuItem) -> None:
        self.settings = self.settings.with_defaults()
        if not self.settings.api_url.strip():
            rumps.alert("TrustEdge", self.settings.missing_api_url_message())
            return
        ok, message = start_tunnel(self._cli_config())
        if ok:
            mark_tunnel_session()
        self._refresh_status()
        if ok:
            rumps.notification("TrustEdge", "Connected", message)
        else:
            rumps.alert("Connect failed", message)

    def disconnect(self, _: rumps.MenuItem) -> None:
        ok, message = stop_tunnel()
        clear_tunnel_session()
        self._refresh_status()
        if not ok:
            rumps.alert("Disconnect failed", message)
        elif message != "Already disconnected.":
            rumps.notification("TrustEdge", "Disconnected", message)

    def _disconnect_on_quit(self) -> None:
        if is_gui_tunnel_connected():
            stop_tunnel()
        clear_tunnel_session()

    @rumps.clicked("Connection Details…")
    def connection_details(self, _: rumps.MenuItem) -> None:
        snapshot = self._snapshot(include_public_ip=True)
        show_connection_panel(
            snapshot,
            on_connect=lambda: self.connect(None),
            on_disconnect=lambda: self.disconnect(None),
        )

def main() -> int:
    if sys.platform != "darwin":
        print("trustedge-wg-gui is macOS only.", file=sys.stderr)
        return 1
    TrustEdgeMenuBarApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
