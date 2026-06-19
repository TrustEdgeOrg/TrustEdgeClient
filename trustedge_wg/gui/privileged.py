from __future__ import annotations

import errno
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from trustedge_wg.cli import CliConfig
from trustedge_wg.gui.log_reader import read_log_lines
from trustedge_wg.gui.settings import log_file, pid_file
from trustedge_wg.gui.tunnel_session import clear_tunnel_session, tunnel_session_valid
from trustedge_wg.paths import agent_state_path


def _python_command() -> list[str]:
    from trustedge_wg.platform.bundled import find_sibling_binary

    cli = find_sibling_binary("trustedge-wg")
    if cli:
        return [cli]
    return [sys.executable]


def build_tunnel_argv(opts: CliConfig) -> list[str]:
    cmd = list(_python_command())
    if opts.config_path.strip():
        cmd.extend(["--config", opts.config_path.strip()])
    if opts.api_url.strip():
        cmd.extend(["--api-url", opts.api_url.strip()])
    if opts.api_token.strip():
        cmd.extend(["--api-token", opts.api_token.strip()])
    if opts.no_routing:
        cmd.append("--no-routing")
    if sys.platform == "darwin":
        if opts.apply_dns:
            cmd.append("--apply-dns")
        else:
            cmd.append("--no-apply-dns")
    elif opts.apply_dns:
        cmd.append("--apply-dns")
    if opts.dns_service.strip():
        cmd.extend(["--dns-service", opts.dns_service.strip()])
    if opts.stats_interval > 0:
        cmd.extend(["--stats-interval", str(opts.stats_interval)])
    if opts.install_policy_ca:
        cmd.append("--install-policy-ca")
    cmd.extend(["--state", str(agent_state_path())])
    return cmd


def _applescript_run_bash_script(script_path: Path) -> subprocess.CompletedProcess[str]:
    """Run a shell script with admin rights via osascript (AppleScript-safe quoting)."""
    posix_path = str(script_path.resolve())
    escaped = posix_path.replace("\\", "\\\\").replace('"', '\\"')
    applescript = (
        'do shell script "/bin/bash " & quoted form of POSIX path of POSIX file '
        f'"{escaped}" with administrator privileges'
    )
    return subprocess.run(
        ["osascript", "-e", applescript],
        capture_output=True,
        text=True,
    )


def _run_admin_shell(script_body: str, *, strict: bool = True) -> subprocess.CompletedProcess[str]:
    fd, script_path = tempfile.mkstemp(prefix="trustedge-wg-", suffix=".sh")
    os.close(fd)
    path = Path(script_path)
    try:
        header = "#!/bin/bash\nset -euo pipefail\n" if strict else "#!/bin/bash\nset +e\n"
        path.write_text(header + script_body + "\n", encoding="utf-8")
        path.chmod(0o700)
        return _applescript_run_bash_script(path)
    finally:
        path.unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    """Return True if pid exists. Root-owned tunnels are visible via ps, not kill(0)."""
    try:
        os.kill(pid, 0)
        return True
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            return False
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "pid="],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and str(pid) in result.stdout


def _log_shows_tunnel_up(lines: list[str] | None = None) -> bool:
    for line in lines or read_log_lines():
        if "interface utun" in line and " up" in line:
            return True
        if line.startswith("trustedge-wg: interface ") and line.endswith(" up"):
            return True
    return False


def _tunnel_pgrep_patterns() -> list[str]:
    return [
        "TrustEdge.app/Contents/MacOS/trustedge-wg",
        "TrustEdge.app/Contents/MacOS/wireguard-go",
    ]


def _pgrep_pids(*extra: str) -> list[int]:
    pids: set[int] = set()
    for token in extra:
        try:
            pids.add(int(token))
        except ValueError:
            continue
    for pattern in _tunnel_pgrep_patterns():
        result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.add(int(line))
    return sorted(p for p in pids if _pid_alive(p))


def _read_tunnel_pid() -> int | None:
    path = pid_file()
    if not path.is_file():
        return None
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return pid if pid > 0 else None


def _list_tunnel_pids() -> list[int]:
    pid = _read_tunnel_pid()
    return _pgrep_pids(str(pid) if pid else "")


def is_tunnel_running() -> bool:
    return bool(_list_tunnel_pids())


def is_gui_tunnel_connected() -> bool:
    """True only when a tunnel is running for this GUI session (not a leftover process)."""
    return is_tunnel_running() and tunnel_session_valid()


def cleanup_orphan_tunnel() -> None:
    """Stop tunnel processes left over from a previous app run."""
    if is_tunnel_running() and not tunnel_session_valid():
        stop_tunnel()
        clear_tunnel_session()
    elif not is_tunnel_running():
        clear_tunnel_session()


def start_tunnel(opts: CliConfig) -> tuple[bool, str]:
    if is_tunnel_running():
        return False, "Already connected."

    argv = build_tunnel_argv(opts)
    tunnel_cmd = " ".join(shlex.quote(part) for part in argv)
    runtime = shlex.quote(str(pid_file().parent))
    pid_path = shlex.quote(str(pid_file()))
    log_path = shlex.quote(str(log_file()))
    state_path = shlex.quote(str(agent_state_path()))
    state_dir = shlex.quote(str(agent_state_path().parent))
    script = (
        f"RUNTIME_DIR={runtime}\n"
        f'STATE_DIR={state_dir}\n'
        f'STATE_FILE={state_path}\n'
        f'mkdir -p "$RUNTIME_DIR" "$STATE_DIR"\n'
        f'chmod 755 "$RUNTIME_DIR" "$STATE_DIR"\n'
        f"CONSOLE_USER=$(stat -f '%Su' /dev/console)\n"
        f'chown "$CONSOLE_USER" "$RUNTIME_DIR" "$STATE_DIR" 2>/dev/null || true\n'
        f"PID_FILE={pid_path}\n"
        f"LOG_FILE={log_path}\n"
        f': > "$LOG_FILE"\n'
        f"{tunnel_cmd} >> \"$LOG_FILE\" 2>&1 &\n"
        f"echo $! > \"$PID_FILE\"\n"
        f'chmod 644 "$PID_FILE" "$LOG_FILE" 2>/dev/null || true\n'
        f"( for _ in $(seq 1 15); do\n"
        f'    if [ -f "$STATE_FILE" ]; then\n'
        f'      chown "$CONSOLE_USER" "$STATE_FILE" 2>/dev/null || true\n'
        f'      chmod 600 "$STATE_FILE" 2>/dev/null || true\n'
        f"      break\n"
        f"    fi\n"
        f"    sleep 1\n"
        f"  done ) &\n"
    )
    result = _run_admin_shell(script)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "admin command failed").strip()
        return False, detail
    for _ in range(60):
        if is_tunnel_running():
            return True, "Connected."
        time.sleep(0.5)
    if _log_shows_tunnel_up():
        return True, "Connected."
    tail = _log_tail()
    return False, tail or f"Tunnel did not start. See {log_file()}."


def stop_tunnel() -> tuple[bool, str]:
    if not is_tunnel_running():
        _clear_tunnel_runtime_files()
        return True, "Already disconnected."

    pid_path = shlex.quote(str(pid_file()))
    log_path = shlex.quote(str(log_file()))
    match_block = """
for _PATTERN in TrustEdge.app/Contents/MacOS/trustedge-wg TrustEdge.app/Contents/MacOS/wireguard-go; do
  for _PID in $(pgrep -f "$_PATTERN" 2>/dev/null); do
    kill -TERM "$_PID" 2>/dev/null
    pkill -TERM -P "$_PID" 2>/dev/null
  done
done
for _ in $(seq 1 40); do
  pgrep -f TrustEdge.app/Contents/MacOS/trustedge-wg >/dev/null 2>&1 && sleep 0.5 && continue
  pgrep -f TrustEdge.app/Contents/MacOS/wireguard-go >/dev/null 2>&1 && sleep 0.5 && continue
  break
done
for _PATTERN in TrustEdge.app/Contents/MacOS/trustedge-wg TrustEdge.app/Contents/MacOS/wireguard-go; do
  for _PID in $(pgrep -f "$_PATTERN" 2>/dev/null); do
    kill -KILL "$_PID" 2>/dev/null
    pkill -KILL -P "$_PID" 2>/dev/null
  done
done
"""
    script = f"""
if [ -f {pid_path} ]; then
  _FILEPID=$(cat {pid_path} 2>/dev/null || true)
  if [ -n "$_FILEPID" ] && kill -0 "$_FILEPID" 2>/dev/null; then
    kill -TERM "$_FILEPID" 2>/dev/null
    pkill -TERM -P "$_FILEPID" 2>/dev/null
  fi
fi
{match_block}
rm -f {pid_path}
: > {log_path}
"""
    result = _run_admin_shell(script, strict=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "could not stop tunnel").strip()
        return False, detail
    for _ in range(40):
        if not is_tunnel_running():
            return True, "Disconnected."
        time.sleep(0.5)
    return False, "Tunnel process is still running."


def _clear_tunnel_runtime_files() -> None:
    for path in (pid_file(), log_file()):
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            pass


def _log_tail(max_lines: int = 8) -> str:
    lines = read_log_lines()
    if not lines:
        return ""
    return "\n".join(lines[-max_lines:]).strip()
