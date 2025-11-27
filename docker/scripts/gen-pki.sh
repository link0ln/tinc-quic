#!/bin/bash
set -e

# Directory setup
BASE_DIR="$(dirname "$0")/.."
CA_DIR="$BASE_DIR/ca"
NODES_DIR="$BASE_DIR"

mkdir -p "$CA_DIR"

echo "=== Generating Private Root CA ==="

# 1. Generate Root CA Key
if [ ! -f "$CA_DIR/ca.key" ]; then
    openssl genrsa -out "$CA_DIR/ca.key" 4096
fi

# 2. Generate Root CA Certificate (Self-Signed)
if [ ! -f "$CA_DIR/ca.crt" ]; then
    openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 3650 \
        -out "$CA_DIR/ca.crt" \
        -subj "/C=US/ST=VPN/L=Internet/O=TincVPN/CN=TincRootCA"
    echo "Created Root CA: $CA_DIR/ca.crt"
fi

# Function to generate and sign node certificate
generate_node_cert() {
    NODE_NAME=$1
    NODE_DIR="$NODES_DIR/$NODE_NAME/tinc"
    
    echo "--- Processing $NODE_NAME ---"
    mkdir -p "$NODE_DIR"

    # Generate Node Key
    openssl genrsa -out "$NODE_DIR/quic-key.pem" 2048

    # Generate CSR
    openssl req -new -key "$NODE_DIR/quic-key.pem" \
        -out "$NODE_DIR/node.csr" \
        -subj "/C=US/ST=VPN/L=Internet/O=TincVPN/CN=$NODE_NAME"

    # Sign Certificate with Root CA
    openssl x509 -req -in "$NODE_DIR/node.csr" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$NODE_DIR/quic-cert.pem" \
        -days 365 -sha256

    # Copy CA cert to node directory (so node can verify others)
    cp "$CA_DIR/ca.crt" "$NODE_DIR/ca.crt"

    # Cleanup CSR
    rm "$NODE_DIR/node.csr"
    
    echo "Generated signed cert for $NODE_NAME"
}

# Generate certs for all nodes
generate_node_cert "node1"
generate_node_cert "node2"
generate_node_cert "node3"

echo "=== PKI Generation Complete ==="
echo "CA Certificate: $CA_DIR/ca.crt"
echo "Node Certificates: $NODES_DIR/node*/tinc/quic-cert.pem"
