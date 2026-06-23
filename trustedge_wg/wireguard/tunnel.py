from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from trustedge_wg.cli import CliConfig
from trustedge_wg.constants import DEFAULT_MTU, DEFAULT_WIREGUARD_PORT
from trustedge_wg.platform.bundled import find_sibling_binary
from trustedge_wg.platform.dns import apply_dns
from trustedge_wg.platform.routing import apply_full_tunnel_routes
from trustedge_wg.wireguard.config import WireGuardConfig, render_wireguard_conf
from trustedge_wg.wireguard.linux_kernel import WG_SOCKET_DIR, linux_kernel_available
from trustedge_wg.wireguard.monitor import start_traffic_monitor
from trustedge_wg.network_attribution.monitor import start_network_attribution_monitor
from trustedge_wg.wireguard.uapi import build_uapi

log = logging.getLogger("trustedge-wg")


def normalize_endpoint(ep: str) -> str:
    ep = ep.strip()
    if "]:" in ep:
        return ep
    if ep.count(":") == 1:
        _, port = ep.rsplit(":", 1)
        if port.isdigit():
            return ep
    return f"{ep}:{DEFAULT_WIREGUARD_PORT}"


def resolve_endpoint_v4(host: str) -> list[ipaddress.IPv4Address]:
    host = host.strip("[]")
    try:
        ip = ipaddress.IPv4Address(host)
        return [ip]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    out: list[ipaddress.IPv4Address] = []
    for info in infos:
        out.append(ipaddress.IPv4Address(info[4][0]))
    if not out:
        raise RuntimeError(f"endpoint has no IPv4 address for {host!r}")
    return out


@contextmanager
def wireguard_tunnel(cfg: WireGuardConfig, opts: CliConfig) -> Iterator[str]:
    """Bring up WireGuard; yield TUN interface name; tear down on exit."""
    mtu = cfg.mtu if cfg.mtu > 0 else DEFAULT_MTU
    if sys.platform.startswith("linux") and linux_kernel_available():
        tun_name = opts.interface
        with _linux_kernel_tunnel(tun_name, cfg, mtu):
            yield tun_name
        return

    hint = _userspace_iface_hint(opts)
    proc, tun_name = _start_wireguard_go(hint, mtu)
    uapi = build_uapi(cfg)
    sock_path: Path | None = None
    try:
        if sys.platform == "win32":
            _ipc_set_windows(tun_name, uapi)
        else:
            sock_path = _wait_for_uapi_socket(tun_name)
            _ipc_set_unix(sock_path, uapi)
        _configure_interface_addrs(tun_name, cfg.address, mtu)
        yield tun_name
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if sock_path is not None and sock_path.exists():
            try:
                sock_path.unlink()
            except OSError:
                pass


def _userspace_iface_hint(opts: CliConfig) -> str:
    if sys.platform == "darwin":
        return "utun"
    if sys.platform == "win32":
        return opts.wintun_adapter_name()
    return opts.interface


def _find_wireguard_go() -> str:
    bundled = find_sibling_binary("wireguard-go", "wireguard_go")
    if bundled:
        return bundled
    for name in ("wireguard-go", "wireguard_go"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(
        "wireguard-go not found in PATH or next to trustedge-wg. "
        "Install it (https://git.zx2c4.com/wireguard-go/) or place wireguard-go "
        "in the same directory as this program. "
        "On Linux you can use the wireguard kernel module and `wg` instead."
    )


def _start_wireguard_go(iface_hint: str, mtu: int) -> tuple[subprocess.Popen[bytes], str]:
    wg_go = _find_wireguard_go()
    env = os.environ.copy()
    env["WG_PROCESS_FOREGROUND"] = "1"
    env["LOG_LEVEL"] = "error"
    before = _list_tun_interfaces() if sys.platform == "darwin" else set()
    proc = subprocess.Popen(
        [wg_go, "-f", iface_hint],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    tun_name = ""
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace").strip()
            raise RuntimeError(f"wireguard-go exited: {out or f'exit code {proc.returncode}'}")
        if sys.platform == "darwin":
            after = _list_tun_interfaces()
            new = after - before
            if new:
                tun_name = sorted(new)[0]
                break
        else:
            # Linux/Windows: interface name usually matches hint (wg0 / TrustEdge)
            if _interface_exists(iface_hint):
                tun_name = iface_hint
                break
        time.sleep(0.2)
    if not tun_name:
        proc.terminate()
        raise RuntimeError("timed out waiting for wireguard-go to create TUN interface")
    return proc, tun_name


def _list_tun_interfaces() -> set[str]:
    try:
        out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return set()
    names = set()
    for line in out.splitlines():
        if line and not line[0].isspace():
            name = line.split(":")[0]
            if name.startswith("utun"):
                names.add(name)
    return names


def _interface_exists(name: str) -> bool:
    if sys.platform == "win32":
        try:
            from trustedge_wg.platform.routing.windows import _windows_interface_index

            _windows_interface_index(name)
            return True
        except RuntimeError:
            return False
    r = subprocess.run(["ip", "link", "show", name], capture_output=True)
    return r.returncode == 0


def _wait_for_uapi_socket(tun_name: str, timeout: float = 15) -> Path:
    """wireguard-go names the UAPI socket after the real TUN (e.g. utun7.sock)."""
    if WG_SOCKET_DIR is None:
        raise RuntimeError("UAPI socket directory is not configured for this platform")
    candidates = [WG_SOCKET_DIR / f"{tun_name}.sock"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in candidates:
            if path.exists():
                return path
        if WG_SOCKET_DIR.is_dir():
            for path in sorted(WG_SOCKET_DIR.glob("*.sock"), key=lambda p: p.stat().st_mtime):
                if path.stem == tun_name:
                    return path
        time.sleep(0.1)
    raise RuntimeError(
        f"wireguard UAPI socket not found for {tun_name!r} under {WG_SOCKET_DIR} "
        f"(expected {candidates[0]})"
    )


def _ipc_set_windows(iface: str, uapi_body: str) -> None:
    import ctypes

    payload = ("set=1\n" + uapi_body).encode()
    pipe = rf"\\.\pipe\WireGuard\{iface}"
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        pipe,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise RuntimeError(f"could not open WireGuard pipe {pipe!r} (is wireguard-go running?)")
    try:
        written = ctypes.c_ulong(0)
        ok = kernel32.WriteFile(handle, payload, len(payload), ctypes.byref(written), None)
        if not ok:
            raise RuntimeError("WriteFile to WireGuard pipe failed")
        buf = ctypes.create_string_buffer(4096)
        read = ctypes.c_ulong(0)
        kernel32.ReadFile(handle, buf, 4096, ctypes.byref(read), None)
        resp = buf.raw[: read.value].decode(errors="replace")
        if "errno=" in resp and "errno=0" not in resp:
            raise RuntimeError(f"wireguard ipc set failed: {resp.strip()}")
    finally:
        kernel32.CloseHandle(handle)


def _ipc_set_unix(sock_path: Path, uapi_body: str) -> None:
    payload = "set=1\n" + uapi_body
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(sock_path))
        sock.sendall(payload.encode())
        sock.shutdown(socket.SHUT_WR)
        resp = sock.recv(4096).decode(errors="replace")
        if "errno=0" not in resp and resp.strip():
            if "errno=" in resp and "errno=0" not in resp:
                raise RuntimeError(f"wireguard ipc set failed: {resp.strip()}")
    finally:
        sock.close()


@contextmanager
def _linux_kernel_tunnel(tun_name: str, cfg: WireGuardConfig, mtu: int) -> Iterator[None]:
    subprocess.run(["ip", "link", "del", "dev", tun_name], capture_output=True)
    r = subprocess.run(["ip", "link", "add", "dev", tun_name, "type", "wireguard"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"ip link add wireguard: {r.stderr or r.stdout}")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf:
        tf.write(render_wireguard_conf(cfg))
        conf_path = tf.name
    try:
        r = subprocess.run(["wg", "setconf", tun_name, conf_path], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"wg setconf: {r.stderr or r.stdout}")
        subprocess.run(["ip", "link", "set", "dev", tun_name, "mtu", str(mtu), "up"], capture_output=True)
        for cidr in cfg.address:
            subprocess.run(["ip", "addr", "add", cidr, "dev", tun_name], capture_output=True)
        yield
    finally:
        subprocess.run(["ip", "link", "del", "dev", tun_name], capture_output=True)
        try:
            os.unlink(conf_path)
        except OSError:
            pass


def _configure_interface_addrs(tun_name: str, addrs: list[str], mtu: int) -> None:
    if sys.platform == "darwin":
        for cidr in addrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                raise RuntimeError(f"parse {cidr!r}: {e}") from e
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            ip_s = str(net.network_address)
            r = subprocess.run(
                [
                    "ifconfig",
                    tun_name,
                    "inet",
                    ip_s,
                    ip_s,
                    "netmask",
                    "255.255.255.255",
                    "mtu",
                    str(mtu),
                    "up",
                ],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(f"ifconfig: {r.stderr or r.stdout}")
    elif sys.platform.startswith("linux"):
        subprocess.run(["ip", "link", "set", "dev", tun_name, "mtu", str(mtu), "up"], capture_output=True)
        for cidr in addrs:
            r = subprocess.run(["ip", "addr", "add", cidr, "dev", tun_name], capture_output=True, text=True)
            if r.returncode != 0 and "File exists" not in (r.stderr or r.stdout):
                raise RuntimeError(f"ip addr add: {r.stderr or r.stdout}")
    elif sys.platform == "win32":
        v4_count = 0
        for cidr in addrs:
            try:
                iface = ipaddress.ip_interface(cidr)
            except ValueError as e:
                raise RuntimeError(f"parse {cidr!r}: {e}") from e
            if not isinstance(iface, ipaddress.IPv4Interface):
                continue
            ip4 = str(iface.ip)
            mask = str(iface.netmask)
            if v4_count == 0:
                cmd = [
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    f"name={tun_name}",
                    "source=static",
                    f"address={ip4}",
                    f"mask={mask}",
                    "gateway=none",
                ]
            else:
                cmd = [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "address",
                    f"name={tun_name}",
                    f"address={ip4}",
                    f"mask={mask}",
                ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f"netsh address: {r.stderr or r.stdout}")
            v4_count += 1
        if v4_count > 0:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "subinterface", tun_name, f"mtu={mtu}", "store=active"],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(f"netsh set mtu: {r.stderr or r.stdout}")


def run_tunnel(
    cfg: WireGuardConfig,
    opts: CliConfig,
    shutdown_event,
    *,
    device_id: str = "",
    api_client=None,
) -> None:
    host, _ = normalize_endpoint(cfg.endpoint).rsplit(":", 1)
    host = host.strip("[]")

    with wireguard_tunnel(cfg, opts) as tun_name:
        log.info("interface %s up", tun_name)

        v4 = resolve_endpoint_v4(host)
        stop_route = None
        if not opts.no_routing:
            stop_route = apply_full_tunnel_routes(tun_name, v4)

        restore_dns = None
        if opts.apply_dns and cfg.dns:
            try:
                restore_dns = apply_dns(cfg.dns, opts.dns_service)
                log.info("DNS applied: %s", ", ".join(cfg.dns))
            except RuntimeError as e:
                log.warning(
                    "%s — tunnel stays up; retry with --dns-service \"Wi-Fi\"",
                    e,
                )
        elif cfg.dns:
            log.warning(
                "DNS in config (%s) is not applied on this OS (macOS: use --apply-dns)",
                ", ".join(cfg.dns),
            )

        if opts.stats_interval > 0 and opts.api_url.strip() and api_client is None:
            from trustedge_wg.agent.state import ensure_agent_state
            from trustedge_wg.enroll.api import Client

            st = ensure_agent_state(opts.resolve_state_path())
            device_id = st.device_id
            api_client = Client(
                opts.api_url,
                opts.api_token,
                device_token=st.device_token,
                enroll_path=opts.api_enroll_path,
                usage_path=opts.api_usage_path,
                attribution_path=opts.api_attribution_path,
            )

        start_traffic_monitor(
            cfg,
            tun_name,
            opts,
            shutdown_event,
            device_id=device_id,
            api_client=api_client,
        )

        start_network_attribution_monitor(
            opts,
            shutdown_event,
            device_id=device_id,
            api_client=api_client,
        )

        shutdown_event.wait()
        log.info("shutting down…")
        if restore_dns:
            restore_dns()
        if stop_route:
            stop_route()
