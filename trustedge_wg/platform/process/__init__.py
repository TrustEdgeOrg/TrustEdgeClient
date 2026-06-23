from __future__ import annotations

import sys

from trustedge_wg.platform.process.darwin import get_foreground_app

__all__ = ["get_foreground_app"]

if not sys.platform.startswith("darwin"):
    def get_foreground_app():  # type: ignore[misc]
        return None
