#!/bin/bash
# Quick VPN test script - validates connectivity and basic performance
# Enhanced with CPU monitoring
# Usage: ./quick-test.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test parameters
TEST_DURATION=10
IPERF_PORT=5201

# Logging functions
log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Report storage
declare -A REPORT

# Helper: Monitor CPU usage
monitor_cpu() {
    local container=$1
    local duration=$2
    local output_file="/tmp/cpu_${container}.log"
    
    # Monitor CPU in background
    (
        for i in $(seq 1 $duration); do
            docker stats --no-stream --format "{{.CPUPerc}}" $container 2>/dev/null | tr -d '%' >> $output_file
            sleep 1
        done
    ) &
    echo $!
}

# Helper: Calculate average CPU
calculate_avg_cpu() {
    local output_file=$1
    if [ -f "$output_file" ]; then
        awk '{sum+=$1; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}' $output_file
    else
        echo "0"
    fi
}

# Step 1: Check containers
check_containers() {
    header "STEP 1: Container Status Check"

    local all_running=true
    for node in node1 node2 node3; do
        log "Checking tinc-$node..."

        if docker ps --format '{{.Names}} {{.Status}}' | grep -q "tinc-$node.*Up"; then
            local uptime=$(docker ps --format '{{.Names}} {{.Status}}' | grep "tinc-$node" | awk '{print $2" "$3}')
            success "tinc-$node is running ($uptime)"
            REPORT["container_$node"]="UP ($uptime)"
        else
            error "tinc-$node is NOT running!"
            REPORT["container_$node"]="DOWN"
            all_running=false
        fi
    done

    if [ "$all_running" = false ]; then
        error "Some containers are not running. Aborting tests."
#         print_report
        exit 1
    fi

    success "All containers are running"
    echo ""
}

# Step 2: Check connectivity with ping
check_connectivity() {
    header "STEP 2: VPN Connectivity Check"

    # Test node1 -> node2
    log "Waiting 5s for mesh to settle..."
    sleep 5
    log "Testing node1 (10.0.0.1) -> node2 (10.0.0.2)..."
    if docker exec tinc-node1 ping -c 3 -W 2 10.0.0.2 >/dev/null 2>&1; then
        local ping_result=$(docker exec tinc-node1 ping -c 3 10.0.0.2 2>&1 | grep 'rtt min/avg/max' | awk -F'/' '{print $5}')
        success "node1 -> node2 OK (avg: ${ping_result}ms)"
        REPORT["ping_1_2"]="OK (${ping_result}ms)"
    else
        error "node1 -> node2 FAILED - No connectivity!"
        REPORT["ping_1_2"]="FAILED"
#         print_report
        exit 1
    fi

    # Test node2 -> node3
    log "Testing node2 (10.0.0.2) -> node3 (10.0.0.3)..."
    if docker exec tinc-node2 ping -c 3 -W 2 10.0.0.3 >/dev/null 2>&1; then
        local ping_result=$(docker exec tinc-node2 ping -c 3 10.0.0.3 2>&1 | grep 'rtt min/avg/max' | awk -F'/' '{print $5}')
        success "node2 -> node3 OK (avg: ${ping_result}ms)"
        REPORT["ping_2_3"]="OK (${ping_result}ms)"
    else
        error "node2 -> node3 FAILED - No connectivity!"
        REPORT["ping_2_3"]="FAILED"
#         print_report
        exit 1
    fi

    success "All ping tests passed"
    echo ""
}

# Helper: Start iperf3 server
start_iperf_server() {
    local node=$1
    docker exec -d $node iperf3 -s -p $IPERF_PORT >/dev/null 2>&1
    sleep 1
}

# Helper: Stop iperf3 server
stop_iperf_server() {
    local node=$1
    docker exec $node pkill -9 iperf3 >/dev/null 2>&1 || true
}

# Helper: Run iperf3 test WITH CPU monitoring
run_iperf_with_cpu() {
    local client=$1
    local server=$2
    local server_ip=$3
    local test_type=$4
    
    # Run iperf3 test
    local output
    if [ "$test_type" = "UDP" ]; then
        docker exec $client iperf3 -c $server_ip -p $IPERF_PORT -t $TEST_DURATION -u -b 1000M 2>&1
    else
        docker exec $client iperf3 -c $server_ip -p $IPERF_PORT -t $TEST_DURATION 2>&1
    fi
}

# Step 3: iperf tests between nodes 1 and 2
test_nodes_1_2() {
    header "STEP 3: Performance Tests node1 <-> node2"

    # Start server on node2
    log "Starting iperf3 server on node2..."
    start_iperf_server tinc-node2

    # UDP test
    log "Running UDP test (node1 -> node2, ${TEST_DURATION}s, 100Mbps)..."
    run_iperf_with_cpu tinc-node1 tinc-node2 10.0.0.2 "UDP"

    # TCP test
    log "Running TCP test (node1 -> node2, ${TEST_DURATION}s)..."
    run_iperf_with_cpu tinc-node1 tinc-node2 10.0.0.2 "TCP"

    # Stop server
    stop_iperf_server tinc-node2
    echo ""
}

# Step 4: iperf tests between nodes 2 and 3 (Transit test)
test_nodes_2_3() {
    header "STEP 4: Performance Tests node2 <-> node3 (via node1 transit)"

    # Start server on node3
    log "Starting iperf3 server on node3..."
    start_iperf_server tinc-node3

    # UDP test
    log "Running UDP test (node2 -> node3, ${TEST_DURATION}s, 100Mbps)..."
    run_iperf_with_cpu tinc-node2 tinc-node3 10.0.0.3 "UDP"

    # TCP test with CPU monitoring
    log "Running TCP test (node2 -> node3, ${TEST_DURATION}s)..."
    run_iperf_with_cpu tinc-node2 tinc-node3 10.0.0.3 "TCP"

    # Stop server
    stop_iperf_server tinc-node3
    echo ""
}

# Cleanup on exit
cleanup() {
    log "Cleaning up..."
    stop_iperf_server tinc-node1
    stop_iperf_server tinc-node2
    stop_iperf_server tinc-node3
    rm -f /tmp/cpu_*.log
}

trap cleanup EXIT

# Main execution
main() {
    header "QUICK VPN TEST SUITE WITH CPU MONITORING"
    log "Test duration: ${TEST_DURATION}s per test"
    log "Start time: $(date)"
    echo ""

    check_containers
    check_connectivity
    test_nodes_1_2
    test_nodes_2_3
}

main
