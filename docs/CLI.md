# trustedge-wg CLI

The **trustedge-wg** command-line client is for power users, Linux/Windows, automation, and debugging. Most Mac users should use **TrustEdge.app** instead — see the [README](../README.md).

---

## Install

Use the binary shipped with `TrustEdge.app` (`Contents/MacOS/trustedge-wg`) or from a release build (`dist/trustedge-wg`).

---

## API enroll (recommended)

No WireGuard config file needed. Set your server in the production `.env` file or pass flags:

```bash
# macOS: ~/Library/Application Support/TrustEdgeClient/.env
sudo trustedge-wg --api-url https://your-api.example.com
```

Or with environment variables:

```bash
export TRUSTEDGE_API_URL=https://your-api.example.com
export TRUSTEDGE_API_TOKEN=your-token   # optional
sudo trustedge-wg
```

The client registers the device, receives tunnel settings from the server, and connects.

---

## Offline mode (WireGuard file)

If you already have a `.conf` from your admin:

```bash
cp client.example.conf my.conf
# edit placeholders — never commit my.conf

sudo trustedge-wg --config ./my.conf
```

Template fields:

| Field | Meaning |
|-------|---------|
| `PrivateKey` | Your device secret key |
| `Address` | VPN IP assigned to you |
| `DNS` | TrustEdge DNS gateway |
| `PublicKey` | Server public key |
| `Endpoint` | Server host:port |

---

## Common flags

| Flag | Purpose |
|------|---------|
| `--api-url` | TrustEdge API base URL |
| `--api-token` | Bearer token for bootstrap enroll |
| `--config` | Local WireGuard `.conf` (offline mode) |
| `--state PATH` | Agent state JSON path |
| `--no-routing` | Tunnel only, skip system routes |
| `--apply-dns` / `--no-apply-dns` | macOS DNS from config (on by default) |
| `--stats-interval SEC` | Report traffic every N seconds |
| `--install-policy-ca` | macOS: trust HTTPS block-page CA (one-time) |

```bash
trustedge-wg --help
```

---

## macOS policy CA (block page)

One-time setup so HTTPS block pages work:

```bash
sudo trustedge-wg --api-url https://your-api.example.com --install-policy-ca
```

---

## Enroll API

- `POST {api-url}/v1/enroll`
- Body: `device_id`, `public_key`, optional `hostname`, `client_public_ip`
- Response: WireGuard fields or `wireguard_conf` INI, plus `device_token` for usage reporting

---

## Related docs

- [README](../README.md) — TrustEdge.app for Mac users
