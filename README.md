# TINC-QUIC: DPI-Evasion VPN

Tinc VPN fork with QUIC transport and DPI (Deep Packet Inspection) evasion, designed to bypass censorship in restrictive networks.

## Features

- **QUIC transport** with TLS 1.3 encryption
- **HTTP/3 masquerading** - traffic looks like web browsing
- **SNI domain rotation** - connections appear as CDN traffic
- **Timing jitter** - breaks timing-based fingerprinting
- **Packet padding** - hides packet size patterns
- **Real TLS certificates** - supports Let's Encrypt for legitimate appearance
- **Multi-stream connections** - mimics browser behavior

## Quick Start

```bash
cd docker
docker compose build
docker compose up -d

# Test connectivity
docker exec tinc-node1 ping -c 3 10.0.0.2
docker exec tinc-node2 ping -c 3 10.0.0.3
```

## Network Topology

```
node2 (10.0.0.2) ──┐
                   ├── node1 (10.0.0.1) ── node3 (10.0.0.3)
node4 (10.0.0.4) ──┘
```

- **networkA** (10.2.2.0/24): node1, node2, node4
- **networkB** (10.2.3.0/24): node1, node3
- Node2/Node3/Node4 communicate through node1 via VPN

## Configuration

### Minimal tinc.conf

```conf
Name = mynode
TransportMode = quic
Port = 443
DeviceType = tun
Interface = tinc0
Mode = router
VPNAddress = 10.0.0.1/24
ConnectTo = peer1
```

### Full Configuration Reference

```conf
# ===== Basic =====
Name = node1
Port = 443
DeviceType = tun
Interface = tinc0
Mode = router
TransportMode = quic
VPNAddress = 10.0.0.1/24
ConnectTo = node2
AutoConnect = yes
MTU = 1400

# ===== DPI Evasion =====

# HTTP/3 Masquerading - wrap traffic in HTTP/3 frames
# Makes VPN traffic look like web browsing
QUICHTTP3Masquerading = yes

# Timing Jitter - random delay per packet (microseconds)
# 0=disabled, 1000=1ms (default), 5000=5ms (max evasion)
QUICJitterMaxUs = 1000

# SNI Domain Pool - rotate through CDN domains
# Default: 12 built-in domains (cloudflare, google, aws, etc.)
# QUICSNIDomains = cdn.example.com, api.example.com

# Packet Padding - obscure packet sizes
# off (default), random, buckets
QUICPaddingMode = off
QUICPaddingMin = 0
QUICPaddingMax = 128

# Stream Multiplexing - parallel streams like browsers
QUICStreamCount = 6

# Keepalives - maintain connection through NAT
QUICKeepaliveMin = 5
QUICKeepaliveMax = 15
QUICKeepaliveSize = 64

# ===== TLS Certificates =====

# Use real certificates (Let's Encrypt) for maximum stealth
QUICCertFile = /etc/tinc/certs/fullchain.pem
QUICKeyFile = /etc/tinc/certs/privkey.pem
QUICTrustPublicCerts = yes

# ===== Debug =====
QUICDebugLevel = 0   # 0-5
PingInterval = 10
PingTimeout = 5
```

## Docker Commands

```bash
# Build and start
docker compose build
docker compose up -d

# View logs
docker logs -f tinc-node1

# Shell access
docker exec -it tinc-node1 bash

# Stop
docker compose down

# Rebuild after code changes
docker compose down && docker compose build --no-cache && docker compose up -d
```

## Testing

### Connectivity Test
```bash
docker exec tinc-node1 ping -c 3 10.0.0.2
docker exec tinc-node2 ping -c 3 10.0.0.3
```

### Performance Test
```bash
# Start iperf server on node3
docker exec -d tinc-node3 iperf3 -s

# Run throughput test from node2
docker exec tinc-node2 iperf3 -c 10.0.0.3 -t 10
```

### Monitor VPN Status
```bash
./scripts/monitor-vpn.sh --mode simple
./scripts/stress-test.sh
```

## DPI Evasion Techniques

| Technique | Detection Method | Countermeasure |
|-----------|-----------------|----------------|
| Protocol fingerprint | Magic bytes | HTTP/3 frames, random SNI |
| Statistical analysis | Packet sizes | Padding (random/buckets) |
| Timing analysis | Regular patterns | Timing jitter |
| Certificate inspection | Self-signed certs | Real TLS certs |
| Flow analysis | Single connection | Multi-stream |

### Recommended Profiles

**Balanced (default):**
```conf
QUICHTTP3Masquerading = yes
QUICJitterMaxUs = 1000
QUICPaddingMode = off
```

**Maximum Stealth:**
```conf
QUICHTTP3Masquerading = yes
QUICJitterMaxUs = 5000
QUICPaddingMode = buckets
QUICStreamCount = 8
```

**Maximum Performance:**
```conf
QUICHTTP3Masquerading = yes
QUICJitterMaxUs = 0
QUICPaddingMode = off
```

## Troubleshooting

### Low Throughput
```bash
# Check MTU
docker exec tinc-node1 ip link show tinc0

# Disable jitter for testing
QUICJitterMaxUs = 0
```

### Connection Issues
```bash
# Check logs for QUIC errors
docker logs tinc-node1 | grep -E "QUIC|error|ERROR"

# Verify network connectivity
docker exec tinc-node2 ping 10.2.2.10  # Docker network
```

### Debug Mode
```bash
# Enable verbose logging in tinc.conf
QUICDebugLevel = 5
```

## Project Structure

```
tinc-quic/
├── src/
│   ├── quic.c/.h      # QUIC transport implementation
│   ├── padding.c/.h   # Packet padding
│   └── ...
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── node{1..4}/tinc/   # Node configs
│   └── scripts/
│       ├── stress-test.sh
│       └── monitor-vpn.sh
└── msquic/            # MsQuic library (submodule)
```

## Security Notes

**Protects against:**
- Protocol fingerprinting
- Statistical traffic analysis
- Certificate inspection
- Timing pattern detection

**Does NOT protect against:**
- Traffic correlation attacks
- Active probing
- Endpoint compromise
- DNS leaks (configure separately)

## License

GPL-2.0-or-later (same as Tinc VPN)

## References

- [Tinc VPN](https://tinc-vpn.org/)
- [MsQuic](https://github.com/microsoft/msquic)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
