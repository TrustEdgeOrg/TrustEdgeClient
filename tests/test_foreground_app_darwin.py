import os
from unittest.mock import MagicMock, patch

from trustedge_wg.platform.process.darwin import ForegroundApp, get_foreground_app


@patch("trustedge_wg.platform.process.darwin._run_osascript")
def test_get_foreground_app_parses_braced_output(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="{com.apple.Safari, Safari}",
        stderr="",
    )
    app = get_foreground_app()
    assert app == ForegroundApp(bundle_id="com.apple.Safari", name="Safari")


@patch("trustedge_wg.platform.process.darwin._run_osascript")
def test_get_foreground_app_returns_none_on_failure(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not allowed")
    assert get_foreground_app() is None


@patch("trustedge_wg.platform.process.darwin.subprocess.run")
def test_run_osascript_as_console_user_when_root(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

    with patch("trustedge_wg.platform.process.darwin.os.geteuid", return_value=0):
        with patch("trustedge_wg.platform.process.darwin._console_user", return_value="eladmines"):
            from trustedge_wg.platform.process.darwin import _run_osascript

            _run_osascript("tell application \"Finder\" to activate")

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[0] == "su"
    assert args[1] == "eladmines"
    assert "osascript" in args[2]
