#!/bin/bash
set -e

NETWORK=${TINC_NETWORK:-testvpn}
NODE=${NODE_NAME:-node1}
QUIC_ENABLED=${QUIC_ENABLED:-yes}

echo "================================================"
echo "Starting Tinc Node: $NODE"
echo "Network: $NETWORK"
echo "QUIC Support: $QUIC_ENABLED"
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

# Generate TLS certificates for QUIC if not exist and QUIC is enabled
if [ "$QUIC_ENABLED" = "yes" ]; then
    CERT_FILE="/etc/tinc/$NETWORK/quic-cert.pem"
    KEY_FILE="/etc/tinc/$NETWORK/quic-key.pem"

    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
        echo "Generating self-signed TLS certificate for QUIC..."
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 3650 \
            -subj "/C=US/ST=State/L=City/O=TincVPN/CN=$NODE" \
            2>/dev/null
        echo "TLS certificate generated: $CERT_FILE"
        echo "TLS private key generated: $KEY_FILE"
    else
        echo "TLS certificate already exists: $CERT_FILE"
    fi

    echo ""
    echo "=== QUIC Configuration ==="
    echo "Certificate: $CERT_FILE"
    echo "Private Key: $KEY_FILE"
    echo "=========================="
    echo ""
fi

# Display MsQuic library information
echo "=== MsQuic Library Info ==="
if ldconfig -p | grep -q libmsquic; then
    ldconfig -p | grep libmsquic
    echo "MsQuic library loaded successfully"
else
    echo "WARNING: MsQuic library not found in ldconfig cache"
    echo "Attempting to locate manually..."
    find /usr -name "libmsquic.so*" 2>/dev/null || echo "Not found"
fi
echo "============================"
echo ""

# Execute tincd with all arguments and network name
echo "Starting tincd with network: $NETWORK"
echo "Debug level: 5 (maximum verbosity for QUIC debugging)"
echo ""
exec tincd -n "$NETWORK" -D -d5
