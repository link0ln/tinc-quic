#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create logs directory
LOGS_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOGS_DIR"

# Define log files
BUILD_LOG="$LOGS_DIR/build.log"
DEPLOY_LOG="$LOGS_DIR/deployment.log"
NETWORK_LOG="$LOGS_DIR/network-info.log"
CONNECTIVITY_LOG="$LOGS_DIR/connectivity-tests.log"
TINC_STATE_LOG="$LOGS_DIR/tinc-state.log"
NODE1_QUIC_LOG="$LOGS_DIR/node1-quic.log"
NODE2_QUIC_LOG="$LOGS_DIR/node2-quic.log"
NODE3_QUIC_LOG="$LOGS_DIR/node3-quic.log"
NODE1_FULL_LOG="$LOGS_DIR/node1-full.log"
NODE2_FULL_LOG="$LOGS_DIR/node2-full.log"
NODE3_FULL_LOG="$LOGS_DIR/node3-full.log"
ERRORS_LOG="$LOGS_DIR/errors.log"
SUMMARY_LOG="$LOGS_DIR/summary.log"

# Clear previous logs
rm -f "$LOGS_DIR"/*.log

# Logging helper functions
log_section() {
    local title="$1"
    local separator="=========================================="
    echo ""
    echo "$separator"
    echo "$title"
    echo "$separator"
    echo ""
}

log_to_file() {
    local logfile="$1"
    local title="$2"
    echo "==========================================" >> "$logfile"
    echo "$title - $(date)" >> "$logfile"
    echo "==========================================" >> "$logfile"
    echo "" >> "$logfile"
}

# Start test
START_TIME=$(date +%s)
log_section "TINC-QUIC TEST - $(date)"

# Initialize summary
{
    echo "TINC-QUIC Test Summary"
    echo "======================"
    echo "Started: $(date)"
    echo ""
} > "$SUMMARY_LOG"

# Build Docker images
log_section "Building Docker images"
log_to_file "$BUILD_LOG" "Docker Build"
{
    echo "Building tinc-quic Docker images with MsQuic support..."
    docker compose build --no-cache 2>&1
    BUILD_STATUS=$?
    echo ""
    echo "Build exit code: $BUILD_STATUS"
} | tee -a "$BUILD_LOG"

if [ $BUILD_STATUS -ne 0 ]; then
    echo "ERROR: Build failed!" | tee -a "$BUILD_LOG" "$ERRORS_LOG" "$SUMMARY_LOG"
    exit 1
fi
echo "✓ Build successful" >> "$SUMMARY_LOG"

# Deploy containers
log_section "Restarting containers"
log_to_file "$DEPLOY_LOG" "Container Deployment"
{
    echo "Stopping old containers..."
    docker compose down 2>&1
    echo ""
    echo "Starting new containers..."
    docker compose up -d --force-recreate --no-deps 2>&1
    echo ""
    echo "Container status:"
    docker ps --filter "name=tinc-node" 2>&1
} | tee -a "$DEPLOY_LOG"

# Wait for containers to initialize
log_section "Waiting for containers to initialize"
echo "Waiting 5 seconds..." | tee -a "$DEPLOY_LOG"
sleep 5

# Collect network information
log_section "Collecting network information"
log_to_file "$NETWORK_LOG" "Network Information"
{
    echo "=== Node1 Network Configuration ==="
    docker exec tinc-node1 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' 2>&1 || echo "Node1 not accessible"
    echo ""

    echo "=== Node2 Network Configuration ==="
    docker exec tinc-node2 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' 2>&1 || echo "Node2 not accessible"
    echo ""

    echo "=== Node3 Network Configuration ==="
    docker exec tinc-node3 sh -c 'ip a show dev tinc0 2>/dev/null || echo "tinc0 not ready"; ip r' 2>&1 || echo "Node3 not accessible"
} | tee -a "$NETWORK_LOG"

# Connectivity tests
log_section "Running connectivity tests"
log_to_file "$CONNECTIVITY_LOG" "Connectivity Tests"

CONNECTIVITY_PASSED=0
CONNECTIVITY_FAILED=0

{
    echo "Test 1: node1 -> node2 (10.0.0.2)"
    if docker exec tinc-node1 ping -c 2 -W 2 10.0.0.2 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Test 2: node1 -> node3 (10.0.0.3)"
    if docker exec tinc-node1 ping -c 2 -W 2 10.0.0.3 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Test 3: node2 -> node1 (10.0.0.1)"
    if docker exec tinc-node2 ping -c 2 -W 2 10.0.0.1 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Test 4: node2 -> node3 (10.0.0.3)"
    if docker exec tinc-node2 ping -c 2 -W 2 10.0.0.3 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Test 5: node3 -> node1 (10.0.0.1)"
    if docker exec tinc-node3 ping -c 2 -W 2 10.0.0.1 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Test 6: node3 -> node2 (10.0.0.2)"
    if docker exec tinc-node3 ping -c 2 -W 2 10.0.0.2 2>&1; then
        echo "✓ PASSED"
        ((CONNECTIVITY_PASSED++))
    else
        echo "✗ FAILED"
        ((CONNECTIVITY_FAILED++))
    fi
    echo ""

    echo "Connectivity Summary: $CONNECTIVITY_PASSED passed, $CONNECTIVITY_FAILED failed"
} | tee -a "$CONNECTIVITY_LOG"

# Update summary
{
    echo ""
    echo "Connectivity Tests: $CONNECTIVITY_PASSED/6 passed"
} >> "$SUMMARY_LOG"

# Tinc state dumps
log_section "Collecting Tinc state information"
log_to_file "$TINC_STATE_LOG" "Tinc State Dumps"
{
    echo "=== Node1 Tinc State ==="
    docker exec tinc-node1 sh -c '
        echo "=== Nodes ===";
        tinc -n testvpn dump nodes 2>&1 || true;
        echo "";
        echo "=== Connections ===";
        tinc -n testvpn dump connections 2>&1 || true;
        echo "";
        echo "=== Edges ===";
        tinc -n testvpn dump edges 2>&1 || true
    ' 2>&1
    echo ""

    echo "=== Node2 Tinc State ==="
    docker exec tinc-node2 sh -c '
        echo "=== Nodes ===";
        tinc -n testvpn dump nodes 2>&1 || true;
        echo "";
        echo "=== Connections ===";
        tinc -n testvpn dump connections 2>&1 || true;
        echo "";
        echo "=== Edges ===";
        tinc -n testvpn dump edges 2>&1 || true
    ' 2>&1
    echo ""

    echo "=== Node3 Tinc State ==="
    docker exec tinc-node3 sh -c '
        echo "=== Nodes ===";
        tinc -n testvpn dump nodes 2>&1 || true;
        echo "";
        echo "=== Connections ===";
        tinc -n testvpn dump connections 2>&1 || true;
        echo "";
        echo "=== Edges ===";
        tinc -n testvpn dump edges 2>&1 || true
    ' 2>&1
} | tee -a "$TINC_STATE_LOG"

# Collect QUIC-specific logs
log_section "Collecting QUIC-specific logs"

echo "Extracting Node1 QUIC logs..." | tee -a "$NODE1_QUIC_LOG"
log_to_file "$NODE1_QUIC_LOG" "Node1 QUIC Logs"
{
    echo "=== QUIC Initialization & Handshake ==="
    docker logs tinc-node1 2>&1 | grep -E "(QUIC|MsQuic|msquic|quic_|Handshake|Connection ID|CID|SCID|DCID)" || echo "No QUIC logs found"
} >> "$NODE1_QUIC_LOG"

echo "Extracting Node2 QUIC logs..." | tee -a "$NODE2_QUIC_LOG"
log_to_file "$NODE2_QUIC_LOG" "Node2 QUIC Logs"
{
    echo "=== QUIC Initialization & Handshake ==="
    docker logs tinc-node2 2>&1 | grep -E "(QUIC|MsQuic|msquic|quic_|Handshake|Connection ID|CID|SCID|DCID)" || echo "No QUIC logs found"
} >> "$NODE2_QUIC_LOG"

echo "Extracting Node3 QUIC logs..." | tee -a "$NODE3_QUIC_LOG"
log_to_file "$NODE3_QUIC_LOG" "Node3 QUIC Logs"
{
    echo "=== QUIC Initialization & Handshake ==="
    docker logs tinc-node3 2>&1 | grep -E "(QUIC|MsQuic|msquic|quic_|Handshake|Connection ID|CID|SCID|DCID)" || echo "No QUIC logs found"
} >> "$NODE3_QUIC_LOG"

# Collect full container logs
log_section "Collecting full container logs"

echo "Saving Node1 full logs..." | tee -a "$NODE1_FULL_LOG"
log_to_file "$NODE1_FULL_LOG" "Node1 Full Logs"
docker logs tinc-node1 2>&1 >> "$NODE1_FULL_LOG"

echo "Saving Node2 full logs..." | tee -a "$NODE2_FULL_LOG"
log_to_file "$NODE2_FULL_LOG" "Node2 Full Logs"
docker logs tinc-node2 2>&1 >> "$NODE2_FULL_LOG"

echo "Saving Node3 full logs..." | tee -a "$NODE3_FULL_LOG"
log_to_file "$NODE3_FULL_LOG" "Node3 Full Logs"
docker logs tinc-node3 2>&1 >> "$NODE3_FULL_LOG"

# Collect all errors
log_section "Collecting errors and warnings"
log_to_file "$ERRORS_LOG" "Errors and Warnings"
{
    echo "=== Node1 Errors ==="
    docker logs tinc-node1 2>&1 | grep -E "(ERROR|ERR|WARNING|Failed|failed|Error|error)" || echo "No errors found"
    echo ""

    echo "=== Node2 Errors ==="
    docker logs tinc-node2 2>&1 | grep -E "(ERROR|ERR|WARNING|Failed|failed|Error|error)" || echo "No errors found"
    echo ""

    echo "=== Node3 Errors ==="
    docker logs tinc-node3 2>&1 | grep -E "(ERROR|ERR|WARNING|Failed|failed|Error|error)" || echo "No errors found"
} | tee -a "$ERRORS_LOG"

# Calculate test duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Finalize summary
{
    echo ""
    echo "Test Duration: ${DURATION}s"
    echo "Finished: $(date)"
    echo ""
    echo "Log Files:"
    echo "  - Build:         $BUILD_LOG"
    echo "  - Deployment:    $DEPLOY_LOG"
    echo "  - Network Info:  $NETWORK_LOG"
    echo "  - Connectivity:  $CONNECTIVITY_LOG"
    echo "  - Tinc State:    $TINC_STATE_LOG"
    echo "  - QUIC Logs:     $NODE1_QUIC_LOG, $NODE2_QUIC_LOG, $NODE3_QUIC_LOG"
    echo "  - Full Logs:     $NODE1_FULL_LOG, $NODE2_FULL_LOG, $NODE3_FULL_LOG"
    echo "  - Errors:        $ERRORS_LOG"
    echo ""
    if [ $CONNECTIVITY_FAILED -eq 0 ]; then
        echo "Status: ✓ ALL TESTS PASSED"
    else
        echo "Status: ✗ SOME TESTS FAILED ($CONNECTIVITY_FAILED failures)"
    fi
} >> "$SUMMARY_LOG"

# Display summary
log_section "TEST COMPLETED"
cat "$SUMMARY_LOG"

echo ""
echo "All logs saved to: $LOGS_DIR"
echo ""

# Return exit code based on connectivity tests
if [ $CONNECTIVITY_FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
