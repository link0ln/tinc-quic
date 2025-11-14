#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==========================================="
echo "TINC QUIC TEST - $(date)"
echo "==========================================="

# Build and deploy
echo ""
echo "=== Building Docker images ==="
docker compose -f docker-compose.optimized.yml build --no-cache

echo ""
echo "=== Restarting containers ==="
docker compose -f docker-compose.optimized.yml up -d --force-recreate --no-deps

echo ""
echo "=== Container status ==="
docker ps --filter "name=tinc-node"

# Wait for containers to start
echo ""
echo "=== Waiting 3 seconds for containers to initialize ==="
sleep 3

# Show container network information
echo ""
echo "=========================================="
echo "NETWORK INFORMATION"
echo "=========================================="
echo ""
echo "--- node1 network ---"
docker exec tinc-node1 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' || true
echo ""
echo "--- node2 network ---"
docker exec tinc-node2 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' || true
echo ""
echo "--- node3 network ---"
docker exec tinc-node3 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' || true

# Connectivity tests
echo ""
echo "=========================================="
echo "CONNECTIVITY TESTS"
echo "=========================================="
echo ""
echo "--- node1 -> node2 (10.0.0.2) ---"
docker exec tinc-node1 ping -c 2 -W 2 10.0.0.2 || echo "FAILED"
echo ""
echo "--- node1 -> node3 (10.0.0.3) ---"
docker exec tinc-node1 ping -c 2 -W 2 10.0.0.3 || echo "FAILED"
echo ""
echo "--- node2 -> node1 (10.0.0.1) ---"
docker exec tinc-node2 ping -c 2 -W 2 10.0.0.1 || echo "FAILED"
echo ""
echo "--- node2 -> node3 (10.0.0.3) ---"
docker exec tinc-node2 ping -c 2 -W 2 10.0.0.3 || echo "FAILED"
echo ""
echo "--- node3 -> node1 (10.0.0.1) ---"
docker exec tinc-node3 ping -c 2 -W 2 10.0.0.1 || echo "FAILED"
echo ""
echo "--- node3 -> node2 (10.0.0.2) ---"
docker exec tinc-node3 ping -c 2 -W 2 10.0.0.2 || echo "FAILED"

# Tinc state dumps
echo ""
echo "=========================================="
echo "TINC STATE DUMPS"
echo "=========================================="
echo ""
echo "--- node1 tinc dump ---"
docker exec tinc-node1 sh -c 'echo "=== Nodes ==="; tinc -n testvpn dump nodes 2>&1 || true; echo "=== Connections ==="; tinc -n testvpn dump connections 2>&1 || true; echo "=== Edges ==="; tinc -n testvpn dump edges 2>&1 || true'
echo ""
echo "--- node2 tinc dump ---"
docker exec tinc-node2 sh -c 'echo "=== Nodes ==="; tinc -n testvpn dump nodes 2>&1 || true; echo "=== Connections ==="; tinc -n testvpn dump connections 2>&1 || true; echo "=== Edges ==="; tinc -n testvpn dump edges 2>&1 || true'
echo ""
echo "--- node3 tinc dump ---"
docker exec tinc-node3 sh -c 'echo "=== Nodes ==="; tinc -n testvpn dump nodes 2>&1 || true; echo "=== Connections ==="; tinc -n testvpn dump connections 2>&1 || true; echo "=== Edges ==="; tinc -n testvpn dump edges 2>&1 || true'

# Show logs with QUIC-specific filtering
echo ""
echo "=========================================="
echo "DETAILED LOGS (QUIC HANDSHAKE FOCUS)"
echo "=========================================="

echo ""
echo "=== NODE1 LOGS ==="
echo "--- QUIC Initialization ---"
docker logs tinc-node1 2>&1 | grep -E "(QUIC|quiche|Initial|Handshake|established|Connection ID|CID|SCID|DCID|dropped)" | tail -n 50
echo ""
echo "--- Errors & Warnings ---"
docker logs tinc-node1 2>&1 | grep -E "(ERR|WARNING|Failed|failed|Error|error)" | tail -n 20 || echo "No errors found"

echo ""
echo "=== NODE2 LOGS ==="
echo "--- QUIC Initialization ---"
docker logs tinc-node2 2>&1 | grep -E "(QUIC|quiche|Initial|Handshake|established|Connection ID|CID|SCID|DCID|dropped)" | tail -n 50
echo ""
echo "--- Errors & Warnings ---"
docker logs tinc-node2 2>&1 | grep -E "(ERR|WARNING|Failed|failed|Error|error)" | tail -n 20 || echo "No errors found"

echo ""
echo "=== NODE3 LOGS ==="
echo "--- QUIC Initialization ---"
docker logs tinc-node3 2>&1 | grep -E "(QUIC|quiche|Initial|Handshake|established|Connection ID|CID|SCID|DCID|dropped)" | tail -n 50
echo ""
echo "--- Errors & Warnings ---"
docker logs tinc-node3 2>&1 | grep -E "(ERR|WARNING|Failed|failed|Error|error)" | tail -n 20 || echo "No errors found"

# Full logs for deep debugging
echo ""
echo "=========================================="
echo "FULL LOGS (LAST 100 LINES EACH)"
echo "=========================================="
echo ""
echo "=== NODE1 FULL LOG ==="
docker logs tinc-node1 --tail 100
echo ""
echo "=== NODE2 FULL LOG ==="
docker logs tinc-node2 --tail 100
echo ""
echo "=== NODE3 FULL LOG ==="
docker logs tinc-node3 --tail 100

echo ""
echo "==========================================="
echo "TEST COMPLETED - $(date)"
echo "==========================================="
