#!/bin/bash
# Stress testing script for tinc-quic VPN
# Tests network performance and stability under load

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test duration in seconds
TEST_DURATION=${TEST_DURATION:-30}
IPERF_PORT=5201

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if containers are running
check_containers() {
    log "Checking container status..."

    for node in node1 node2 node3; do
        if ! docker compose ps | grep -q "tinc-$node.*Up"; then
            error "Container tinc-$node is not running!"
            exit 1
        fi
    done

    success "All containers are running"
}

# Check VPN connectivity
check_vpn() {
    log "Checking VPN connectivity..."

    # Test node1 -> node2
    if ! docker exec tinc-node1 ping -c 3 -W 2 10.0.0.2 >/dev/null 2>&1; then
        error "VPN connectivity node1->node2 failed!"
        return 1
    fi

    # Test node2 -> node3
    if ! docker exec tinc-node2 ping -c 3 -W 2 10.0.0.3 >/dev/null 2>&1; then
        error "VPN connectivity node2->node3 failed!"
        return 1
    fi

    success "VPN connectivity OK"
    return 0
}

# Start iperf3 server on a node
start_iperf_server() {
    local node=$1
    log "Starting iperf3 server on $node..."
    docker exec -d $node iperf3 -s -p $IPERF_PORT >/dev/null 2>&1
    sleep 2
    success "iperf3 server started on $node"
}

# Stop iperf3 server
stop_iperf_server() {
    local node=$1
    docker exec $node pkill -9 iperf3 >/dev/null 2>&1 || true
}

# Run iperf3 test
run_iperf_test() {
    local server_node=$1
    local client_node=$2
    local server_ip=$3
    local test_name=$4
    local extra_args=$5

    log "Running: $test_name"
    log "  Server: $server_node ($server_ip)"
    log "  Client: $client_node"
    log "  Duration: ${TEST_DURATION}s"

    # Run test and capture output
    local output=$(docker exec $client_node iperf3 -c $server_ip -p $IPERF_PORT -t $TEST_DURATION $extra_args 2>&1)

    # Parse results
    if echo "$output" | grep -q "iperf Done"; then
        # Extract bandwidth
        local bandwidth=$(echo "$output" | grep -E "receiver|sender" | tail -1 | awk '{for(i=1;i<=NF;i++){if($i~/bits\/sec/){print $(i-1)" "$i; break}}}')
        local retrans=$(echo "$output" | grep -oP 'Retr\s+\K\d+' | tail -1 || echo "N/A")

        success "Test completed: $bandwidth (Retransmits: $retrans)"
        echo "$output" > /tmp/iperf_${test_name// /_}.log

        # Check for packet loss if UDP test
        if [[ "$extra_args" == *"-u"* ]]; then
            local loss=$(echo "$output" | grep -oP '\(\K[0-9.]+(?=%\))' | tail -1 || echo "0")
            if (( $(echo "$loss > 5" | bc -l) )); then
                warning "High packet loss: ${loss}%"
            fi
        fi
    else
        error "Test failed!"
        echo "$output"
        return 1
    fi
}

# TCP bandwidth test
test_tcp_bandwidth() {
    local server_node=$1
    local client_node=$2
    local server_ip=$3
    local direction=$4

    header "TCP Bandwidth Test: $direction"

    start_iperf_server $server_node
    sleep 2

    # Single stream
    run_iperf_test $server_node $client_node $server_ip \
        "TCP single stream" ""

    # Parallel streams
    run_iperf_test $server_node $client_node $server_ip \
        "TCP 4 parallel streams" "-P 4"

    # Bidirectional
    run_iperf_test $server_node $client_node $server_ip \
        "TCP bidirectional" "--bidir"

    stop_iperf_server $server_node
}

# UDP bandwidth test with different packet sizes
test_udp_bandwidth() {
    local server_node=$1
    local client_node=$2
    local server_ip=$3
    local direction=$4

    header "UDP Bandwidth Test: $direction"

    start_iperf_server $server_node
    sleep 2

    # Small packets (VoIP-like)
    run_iperf_test $server_node $client_node $server_ip \
        "UDP 160 byte packets (VoIP)" "-u -b 1M -l 160"

    # Medium packets
    run_iperf_test $server_node $client_node $server_ip \
        "UDP 512 byte packets" "-u -b 10M -l 512"

    # Large packets
    run_iperf_test $server_node $client_node $server_ip \
        "UDP 1400 byte packets (near MTU)" "-u -b 50M -l 1400"

    # Stress test - high bandwidth
    run_iperf_test $server_node $client_node $server_ip \
        "UDP stress test (100Mbps)" "-u -b 100M"

    stop_iperf_server $server_node
}

# Latency test under load
test_latency_under_load() {
    local server_node=$1
    local client_node=$2
    local server_ip=$3

    header "Latency Test Under Load"

    # Start background traffic
    log "Starting background TCP traffic..."
    start_iperf_server $server_node
    docker exec -d $client_node iperf3 -c $server_ip -p $IPERF_PORT -t 60 >/dev/null 2>&1

    sleep 3

    # Measure latency with ping
    log "Measuring latency under load (10 pings)..."
    local ping_output=$(docker exec $client_node ping -c 10 $server_ip 2>&1)

    local avg_latency=$(echo "$ping_output" | grep -oP 'avg = [0-9.]+' | awk '{print $3}')
    local packet_loss=$(echo "$ping_output" | grep -oP '[0-9]+(?=% packet loss)')

    success "Average latency under load: ${avg_latency}ms (loss: ${packet_loss}%)"

    # Stop background traffic
    docker exec $client_node pkill -9 iperf3 >/dev/null 2>&1 || true
    stop_iperf_server $server_node
}

# Monitor system during stress
monitor_system() {
    local duration=$1
    log "Monitoring system for ${duration}s..."

    for i in $(seq 1 $duration); do
        # Check if containers are still running
        if ! docker compose ps | grep -q "tinc-.*Up.*Up.*Up"; then
            error "Container crashed during test!"
            docker compose ps
            return 1
        fi
        sleep 1
    done

    success "System stable during stress test"
}

# Main test runner
run_all_tests() {
    header "TINC-QUIC VPN STRESS TEST SUITE"

    log "Test configuration:"
    log "  Duration per test: ${TEST_DURATION}s"
    log "  iperf3 port: $IPERF_PORT"
    echo ""

    check_containers
    check_vpn || {
        error "VPN not working, aborting tests"
        exit 1
    }

    # Test node1 <-> node2
    test_tcp_bandwidth tinc-node2 tinc-node1 10.0.0.2 "node1 -> node2"
    check_vpn || exit 1

    test_tcp_bandwidth tinc-node1 tinc-node2 10.0.0.1 "node2 -> node1"
    check_vpn || exit 1

    test_udp_bandwidth tinc-node2 tinc-node1 10.0.0.2 "node1 -> node2"
    check_vpn || exit 1

    # Test node2 <-> node3
    test_tcp_bandwidth tinc-node3 tinc-node2 10.0.0.3 "node2 -> node3"
    check_vpn || exit 1

    test_tcp_bandwidth tinc-node2 tinc-node3 10.0.0.2 "node3 -> node2"
    check_vpn || exit 1

    test_udp_bandwidth tinc-node3 tinc-node2 10.0.0.3 "node2 -> node3"
    check_vpn || exit 1

    # Latency tests
    test_latency_under_load tinc-node2 tinc-node1 10.0.0.2
    check_vpn || exit 1

    test_latency_under_load tinc-node3 tinc-node2 10.0.0.3
    check_vpn || exit 1

    header "TEST SUMMARY"

    success "All stress tests completed successfully!"

    # Check final system state
    log "Final system check..."
    docker compose ps

    log "Test logs saved to /tmp/iperf_*.log"

    # Show quick summary
    echo ""
    log "Quick bandwidth summary:"
    for log in /tmp/iperf_*.log; do
        if [ -f "$log" ]; then
            local testname=$(basename "$log" .log | sed 's/iperf_//' | sed 's/_/ /g')
            local bw=$(grep -E "receiver|sender" "$log" | tail -1 | awk '{for(i=1;i<=NF;i++){if($i~/bits\/sec/){print $(i-1)" "$i; break}}}')
            echo "  $testname: $bw"
        fi
    done
}

# Cleanup function
cleanup() {
    log "Cleaning up..."
    stop_iperf_server tinc-node1
    stop_iperf_server tinc-node2
    stop_iperf_server tinc-node3
}

trap cleanup EXIT

# Parse arguments
case "${1:-all}" in
    all)
        run_all_tests
        ;;
    tcp)
        check_containers
        test_tcp_bandwidth tinc-node2 tinc-node1 10.0.0.2 "node1 -> node2"
        test_tcp_bandwidth tinc-node3 tinc-node2 10.0.0.3 "node2 -> node3"
        ;;
    udp)
        check_containers
        test_udp_bandwidth tinc-node2 tinc-node1 10.0.0.2 "node1 -> node2"
        test_udp_bandwidth tinc-node3 tinc-node2 10.0.0.3 "node2 -> node3"
        ;;
    latency)
        check_containers
        test_latency_under_load tinc-node2 tinc-node1 10.0.0.2
        test_latency_under_load tinc-node3 tinc-node2 10.0.0.3
        ;;
    *)
        echo "Usage: $0 {all|tcp|udp|latency}"
        echo ""
        echo "Options:"
        echo "  all     - Run all tests (default)"
        echo "  tcp     - TCP bandwidth tests only"
        echo "  udp     - UDP bandwidth tests only"
        echo "  latency - Latency under load tests only"
        echo ""
        echo "Environment variables:"
        echo "  TEST_DURATION - Duration of each test in seconds (default: 30)"
        exit 1
        ;;
esac
