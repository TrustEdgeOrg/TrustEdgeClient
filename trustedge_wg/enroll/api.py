from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from trustedge_wg.wireguard.config import (
    WireGuardConfig,
    finalize_wireguard_config,
    parse_wireguard_config,
    render_wireguard_conf,
)
from trustedge_wg.constants import (
    DEFAULT_ATTRIBUTION_PATH,
    DEFAULT_ENROLL_PATH,
    DEFAULT_POLICY_CA_PATH,
    DEFAULT_USAGE_PATH,
    HTTP_CLIENT_TIMEOUT,
    MAX_ENROLL_RESPONSE_BYTES,
)


@dataclass
class EnrollRequest:
    device_id: str
    public_key: str
    hostname: str = ""
    mac_address: str = ""
    client_public_ip: str = ""


@dataclass
class EnrollResponse:
    wireguard_conf: str = ""
    address: str = ""
    addresses: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mtu: int = 0
    server_public_key: str = ""
    endpoint: str = ""
    allowed_ips: list[str] = field(default_factory=list)
    preshared_key: str = ""
    persistent_keepalive: int = 0
    device_token: str = ""


class Client:
    def __init__(
        self,
        base_url: str,
        enroll_token: str = "",
        *,
        device_token: str = "",
        enroll_path: str = DEFAULT_ENROLL_PATH,
        usage_path: str = DEFAULT_USAGE_PATH,
        attribution_path: str = DEFAULT_ATTRIBUTION_PATH,
        policy_ca_path: str = DEFAULT_POLICY_CA_PATH,
    ) -> None:
        base_url = base_url.strip().rstrip("/")
        if not base_url:
            raise ValueError("trustedge api: empty base URL")
        if not enroll_path:
            enroll_path = DEFAULT_ENROLL_PATH
        if not enroll_path.startswith("/"):
            enroll_path = "/" + enroll_path
        if not usage_path:
            usage_path = DEFAULT_USAGE_PATH
        if not usage_path.startswith("/"):
            usage_path = "/" + usage_path
        if not attribution_path:
            attribution_path = DEFAULT_ATTRIBUTION_PATH
        if not attribution_path.startswith("/"):
            attribution_path = "/" + attribution_path
        if not policy_ca_path.startswith("/"):
            policy_ca_path = "/" + policy_ca_path
        self.base_url = base_url
        self.enroll_token = enroll_token.strip()
        self.device_token = device_token.strip()
        self.enroll_path = enroll_path
        self.usage_path = usage_path
        self.attribution_path = attribution_path
        self.policy_ca_path = policy_ca_path

    def fetch_block_page_ca(self) -> bytes:
        req = Request(self.base_url + self.policy_ca_path, method="GET")
        try:
            with urlopen(req, timeout=HTTP_CLIENT_TIMEOUT) as resp:
                if resp.status < 200 or resp.status >= 300:
                    body = resp.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace")
                    raise RuntimeError(f"policy CA returned {resp.status}: {body}")
                return resp.read(MAX_ENROLL_RESPONSE_BYTES)
        except HTTPError as e:
            err_body = e.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace").strip()
            raise RuntimeError(f"trustedge api: policy CA returned {e.code}: {err_body}") from e
        except URLError as e:
            raise RuntimeError(f"trustedge api: policy CA download: {e}") from e

    def _auth_header(self, *, for_usage: bool) -> dict[str, str]:
        if for_usage and self.device_token:
            return {"Authorization": f"Bearer {self.device_token}"}
        if self.enroll_token:
            return {"Authorization": f"Bearer {self.enroll_token}"}
        return {}

    def report_usage(
        self,
        *,
        device_id: str,
        rx_bytes: int,
        tx_bytes: int,
        delta_rx: int,
        delta_tx: int,
        interval_sec: float,
    ) -> None:
        payload = {
            "device_id": device_id,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "delta_rx_bytes": delta_rx,
            "delta_tx_bytes": delta_tx,
            "interval_sec": interval_sec,
        }
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", **self._auth_header(for_usage=True)}
        req = Request(
            self.base_url + self.usage_path,
            data=data,
            method="POST",
            headers=headers,
        )
        try:
            with urlopen(req, timeout=HTTP_CLIENT_TIMEOUT) as resp:
                if resp.status < 200 or resp.status >= 300:
                    body = resp.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace")
                    raise RuntimeError(f"usage {self.usage_path} returned {resp.status}: {body}")
        except HTTPError as e:
            err_body = e.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace").strip()
            raise RuntimeError(
                f"trustedge api: usage {self.usage_path} returned {e.code}: {err_body}"
            ) from e
        except URLError as e:
            raise RuntimeError(f"trustedge api: usage round trip: {e}") from e

    def report_network_attribution(
        self,
        *,
        device_id: str,
        intervals: list[dict],
    ) -> None:
        payload = {
            "device_id": device_id,
            "intervals": intervals,
        }
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", **self._auth_header(for_usage=True)}
        req = Request(
            self.base_url + self.attribution_path,
            data=data,
            method="POST",
            headers=headers,
        )
        try:
            with urlopen(req, timeout=HTTP_CLIENT_TIMEOUT) as resp:
                if resp.status < 200 or resp.status >= 300:
                    body = resp.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace")
                    raise RuntimeError(
                        f"network attribution {self.attribution_path} returned {resp.status}: {body}"
                    )
        except HTTPError as e:
            err_body = e.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace").strip()
            raise RuntimeError(
                f"trustedge api: network attribution {self.attribution_path} returned {e.code}: {err_body}"
            ) from e
        except URLError as e:
            raise RuntimeError(f"trustedge api: network attribution round trip: {e}") from e

    def enroll(self, body: EnrollRequest) -> EnrollResponse:
        payload: dict[str, Any] = {
            "device_id": body.device_id,
            "public_key": body.public_key,
        }
        if body.hostname.strip():
            payload["hostname"] = body.hostname.strip()
        if body.mac_address.strip():
            payload["mac_address"] = body.mac_address.strip()
        if body.client_public_ip.strip():
            payload["client_public_ip"] = body.client_public_ip.strip()

        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", **self._auth_header(for_usage=False)}
        req = Request(
            self.base_url + self.enroll_path,
            data=data,
            method="POST",
            headers=headers,
        )

        try:
            with urlopen(req, timeout=HTTP_CLIENT_TIMEOUT) as resp:
                raw = resp.read(MAX_ENROLL_RESPONSE_BYTES)
                status = resp.status
        except HTTPError as e:
            err_body = e.read(MAX_ENROLL_RESPONSE_BYTES).decode(errors="replace").strip()
            raise RuntimeError(
                f"trustedge api: enroll {self.enroll_path} returned {e.code}: {err_body}"
            ) from e
        except URLError as e:
            raise RuntimeError(f"trustedge api: round trip: {e}") from e

        if status < 200 or status >= 300:
            raise RuntimeError(
                f"trustedge api: enroll {self.enroll_path} returned {status}: {raw.decode(errors='replace')}"
            )

        obj = json.loads(raw.decode())
        return EnrollResponse(
            wireguard_conf=str(obj.get("wireguard_conf") or ""),
            address=str(obj.get("address") or ""),
            addresses=list(obj.get("addresses") or []),
            dns=list(obj.get("dns") or []),
            mtu=int(obj.get("mtu") or 0),
            server_public_key=str(obj.get("server_public_key") or ""),
            endpoint=str(obj.get("endpoint") or ""),
            allowed_ips=list(obj.get("allowed_ips") or []),
            preshared_key=str(obj.get("preshared_key") or ""),
            persistent_keepalive=int(obj.get("persistent_keepalive") or 0),
            device_token=str(obj.get("device_token") or ""),
        )


def inject_local_private_key_into_ini(ini: str, private_key: str) -> str:
    if "privatekey" in ini.lower():
        return ini
    s = ini.replace("\r\n", "\n")
    parts = s.split("\n", 1)
    if parts and parts[0].strip().lower() == "[interface]":
        rest = parts[1] if len(parts) > 1 else ""
        return parts[0] + "\nPrivateKey = " + private_key + "\n" + rest
    return f"[Interface]\nPrivateKey = {private_key}\n\n" + ini


def wireguard_from_enroll(private_key: str, resp: EnrollResponse) -> WireGuardConfig:
    private_key = private_key.strip()
    if not private_key:
        raise ValueError("enroll: local private key is required")
    if resp.wireguard_conf.strip():
        ini = inject_local_private_key_into_ini(resp.wireguard_conf, private_key)
        cfg = parse_wireguard_config(io.StringIO(ini))
        if cfg.private_key and cfg.private_key != private_key:
            raise ValueError("enroll: server PrivateKey does not match local key")
        cfg.private_key = private_key
        return finalize_wireguard_config(cfg)
    else:
        cfg = WireGuardConfig(
            private_key=private_key,
            public_key=resp.server_public_key.strip(),
            endpoint=resp.endpoint.strip(),
            preshared_key=resp.preshared_key.strip(),
            persistent_keepalive=resp.persistent_keepalive,
            mtu=resp.mtu,
        )
        cfg.dns = [d.strip() for d in resp.dns if d.strip()]
        if resp.address.strip():
            cfg.address.append(resp.address.strip())
        for a in resp.addresses:
            if a.strip():
                cfg.address.append(a.strip())
        for cidr in resp.allowed_ips:
            if cidr.strip():
                cfg.allowed_ips.append(cidr.strip())
        return finalize_wireguard_config(cfg)
