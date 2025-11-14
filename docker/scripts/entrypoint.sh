#!/bin/bash
set -e

NETWORK=${TINC_NETWORK:-testvpn}
NODE=${NODE_NAME:-node1}

echo "================================================"
echo "Starting Tinc Node: $NODE"
echo "Network: $NETWORK"
echo "VLESS Mode: ${VLESS_MODE:-no}"
echo "Reality Mode: ${REALITY_MODE:-no}"
echo "================================================"

# Check if tinc configuration exists
if [ ! -f "/etc/tinc/$NETWORK/tinc.conf" ]; then
    echo "ERROR: Configuration not found at /etc/tinc/$NETWORK/tinc.conf"
    echo "Please ensure configuration is mounted correctly"
    exit 1
fi

# Show configuration
echo ""
echo "=== Tinc Configuration ==="
cat "/etc/tinc/$NETWORK/tinc.conf"
echo "=========================="
echo ""

# Check if host files exist
if [ -d "/etc/tinc/$NETWORK/hosts" ]; then
    echo "=== Available Host Files ==="
    ls -la "/etc/tinc/$NETWORK/hosts/"
    echo "============================"
    echo ""
fi

# Create TUN device if not exists
if [ ! -e /dev/net/tun ]; then
    echo "Creating /dev/net/tun"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Generate TLS certificate for QUIC if not exists
CERT_FILE="/etc/tinc/$NETWORK/quic-cert.pem"
KEY_FILE="/etc/tinc/$NETWORK/quic-key.pem"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed TLS certificate for QUIC..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 \
        -subj "/C=US/ST=State/L=City/O=TincVPN/CN=localhost" \
        2>/dev/null
    echo "TLS certificate generated: $CERT_FILE"
    echo "TLS private key generated: $KEY_FILE"
else
    echo "TLS certificate already exists: $CERT_FILE"
fi

# Execute tincd with all arguments and network name
echo "Starting tincd with network: $NETWORK"
exec tincd -n "$NETWORK" -D -d5
