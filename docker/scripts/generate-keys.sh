#!/bin/bash

set -e


# Generate UUID for VLESS
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Generate hex random bytes
generate_hex() {
    local bytes=$1
    openssl rand -hex "$bytes"
}

# Generate keys for a node
generate_node_keys() {
    local node_name=$1

    echo "Generating keys for $node_name..."
    echo ""

    # VLESS UUID
    local uuid=$(generate_uuid)
    echo "  VLESS UUID: $uuid"

    # Reality Keys (X25519 - 32 bytes)
    local private_key=$(generate_hex 32)
    local public_key=$(generate_hex 32)
    local short_id=$(generate_hex 8)

    echo "  Reality Private Key: $private_key"
    echo "  Reality Public Key:  $public_key"
    echo "  Reality ShortID:     $short_id"
    echo ""

    # Save to file
    cat > "docker/${node_name}/keys.txt" <<EOF
# VLESS + Reality Keys for $node_name
# Generated: $(date)

VLESSUUID=$uuid
VLESSRealityPrivateKey=$private_key
VLESSRealityPublicKey=$public_key
VLESSRealityShortID=$short_id
EOF

    echo "  Keys saved to docker/${node_name}/keys.txt"
    echo ""
}

# Main
cd /opt/gitrepo/vpn-experiments/tinc-vless

echo "Generating keys for all nodes..."
echo ""

generate_node_keys "node1"
generate_node_keys "node2"
generate_node_keys "node3"

echo "==============================================="
echo "  All keys generated successfully!"
echo "  Check docker/node*/keys.txt for details"
echo "==============================================="
