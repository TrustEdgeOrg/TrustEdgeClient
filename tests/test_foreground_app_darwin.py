from unittest.mock import MagicMock, patch

from trustedge_wg.platform.process.darwin import ForegroundApp, _from_lsappinfo, _from_osascript, get_foreground_app


def _lsappinfo_side_effect(argv, **_kwargs):
    if argv[-1] == "front":
        return MagicMock(returncode=0, stdout="ASN:0x0-0x1:\n", stderr="")
    if argv[0].endswith("lsappinfo") and argv[1] == "info":
        return MagicMock(
            returncode=0,
            stdout='"CFBundleIdentifier"="com.google.Chrome"\n"LSDisplayName"="Google Chrome"\n',
            stderr="",
        )
    return MagicMock(returncode=1, stdout="", stderr="fail")


@patch("trustedge_wg.platform.process.darwin._run_as_console_user", side_effect=_lsappinfo_side_effect)
def test_get_foreground_app_uses_lsappinfo(mock_run):
    app = get_foreground_app()
    assert app == ForegroundApp(bundle_id="com.google.Chrome", name="Google Chrome")
    assert mock_run.call_count == 2


@patch("trustedge_wg.platform.process.darwin._from_lsappinfo", return_value=None)
@patch("trustedge_wg.platform.process.darwin._run_as_console_user")
def test_get_foreground_app_osascript_fallback(mock_run, _mock_lsappinfo):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="{com.apple.Safari, Safari}",
        stderr="",
    )
    app = get_foreground_app()
    assert app == ForegroundApp(bundle_id="com.apple.Safari", name="Safari")


@patch("trustedge_wg.platform.process.darwin._run_as_console_user")
def test_get_foreground_app_returns_none_on_failure(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not allowed")
    assert _from_lsappinfo() is None
    assert _from_osascript() is None


@patch("trustedge_wg.platform.process.darwin._run_as_console_user")
def test_get_foreground_app_ignores_loginwindow(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='"CFBundleIdentifier"="com.apple.loginwindow"\n"LSDisplayName"="loginwindow"\n',
        stderr="",
    )
    with patch(
        "trustedge_wg.platform.process.darwin._run_as_console_user",
        side_effect=[
            MagicMock(returncode=0, stdout="ASN:0x0-0x1:\n", stderr=""),
            mock_run.return_value,
        ],
    ):
        assert _from_lsappinfo() is None


@patch("trustedge_wg.platform.process.darwin.subprocess.run")
def test_run_as_console_user_uses_launchctl_when_root(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

    with patch("trustedge_wg.platform.process.darwin.os.geteuid", return_value=0):
        with patch("trustedge_wg.platform.process.darwin._console_uid", return_value=501):
            from trustedge_wg.platform.process.darwin import _run_as_console_user

            _run_as_console_user(["/usr/bin/lsappinfo", "front"])

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[:3] == ["launchctl", "asuser", "501"]
    assert args[3].endswith("lsappinfo")
