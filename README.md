# Cloud VM Onekey Manager

One-click deployment script for VLESS Reality and Hysteria2 proxy services on cloud VMs.

## Features

- **Interactive Menu**: Choose to install VLESS Reality, Hysteria2, or both
- **Custom Ports**: User-specified ports during installation
- **Docker-based**: All services run in Docker containers for easy management
- **Auto-generated Credentials**: Secure random passwords and keys
- **QR Code Support**: Text-based QR codes for easy mobile import
- **Unified Management**: Status, logs, restart, and uninstall commands
- **Kernel Optimization**: Auto-enable BBR, TCP Fast Open, and MPTCP
- **New v2rayN Compatible**: Uses `pinSHA256` instead of deprecated `insecure` for Hysteria2

## Quick Start

```bash
# Download and run
curl -fsSL https://raw.githubusercontent.com/realDuang/cloud-vm-onekey-manager/main/xray_vless_reality_and_hysteria2.sh -o proxy.sh
chmod +x proxy.sh
./proxy.sh
```

## Usage

### Interactive Mode

```bash
./xray_vless_reality_and_hysteria2.sh
```

Displays menu:
```
1) Install VLESS Reality
2) Install Hysteria2
3) Install All (VLESS + Hysteria2)
4) View Service Status
5) View Connection Info
6) View Logs
7) Restart Services
8) Uninstall
9) Optimize System Kernel (BBR/TCP)
0) Exit
```

### Command Line Mode

| Command | Description |
|---------|-------------|
| `./proxy.sh status` | Show running status of all services |
| `./proxy.sh info` | Display connection configuration |
| `./proxy.sh logs [service] [lines]` | View logs (service: vless/hy2/all) |
| `./proxy.sh restart [service]` | Restart services (service: vless/hy2/all) |
| `./proxy.sh uninstall [service]` | Remove services and configs (service: vless/hy2/all) |
| `./proxy.sh help` | Show help message |

### Examples

```bash
# Check if services are running
./proxy.sh status

# View connection info and QR codes
./proxy.sh info

# View last 100 lines of Hysteria2 logs
./proxy.sh logs hy2 100

# Restart VLESS Reality only
./proxy.sh restart vless

# Restart all services
./proxy.sh restart

# Uninstall only Hysteria2
./proxy.sh uninstall hy2

# Uninstall only VLESS Reality
./proxy.sh uninstall vless
```

## Saved Files

After installation, connection info is saved to `~/proxy_info/`:

| File | Description |
|------|-------------|
| `vless_info.txt` | VLESS Reality full configuration |
| `vless_uri.txt` | VLESS share link |
| `vless_qr.txt` | VLESS QR code (text) |
| `hy2_info.txt` | Hysteria2 full configuration |
| `hy2_uri.txt` | Hysteria2 share link |
| `hy2_qr.txt` | Hysteria2 QR code (text) |

## Requirements

- Linux server (Ubuntu/Debian/CentOS/Fedora/Arch/Alpine)
- Root or sudo access
- Ports accessible (firewall configured)

Docker, openssl, curl, and qrencode will be installed automatically if not present.

## Kernel Optimization

The script automatically applies the following optimizations:

- **BBR**: Google's TCP congestion control algorithm
- **TCP Fast Open**: Reduces connection latency
- **MPTCP**: Multi-path TCP support (kernel 5.6+)
- **Increased TCP buffers**: Better throughput
- **Connection queue optimization**: Higher concurrency

## Default Ports

| Service | Default Port | Protocol |
|---------|--------------|----------|
| VLESS Reality | 443 | TCP |
| Hysteria2 | 8443 | UDP |

Ports can be customized during installation.

## Docker Containers

| Container Name | Image |
|----------------|-------|
| `xray_reality` | ghcr.io/xtls/xray-core:latest |
| `hysteria2` | tobyxdd/hysteria:v2 |

## Client Configuration Notes

### Hysteria2 (v2rayN 6.x+)

New versions of v2rayN/Xray have removed `allowInsecure` option. The script now generates share links with `pinSHA256` (certificate fingerprint pinning) instead:

```
hysteria2://password@host:port?sni=xxx&pinSHA256=<cert_hash>#name
```

If you have an existing deployment, get the certificate hash manually:

```bash
openssl x509 -in ~/hysteria2/server.crt -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | base64
```

## License

MIT
