#!/bin/bash
# Real-time VPN monitoring script
# Shows traffic stats, connection status, and performance metrics

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INTERVAL=${INTERVAL:-2}

# Clear screen and show header
show_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}              ${CYAN}TINC-QUIC VPN REAL-TIME MONITOR${NC}                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}              $(date '+%Y-%m-%d %H:%M:%S')                               ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Get container stats
get_container_stats() {
    local node=$1
    local stats=$(docker stats --no-stream --format "{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" $node 2>/dev/null || echo "N/A\tN/A\tN/A")
    echo "$stats"
}

# Check if node is reachable via VPN
check_vpn_connectivity() {
    local source=$1
    local target_ip=$2

    if docker exec $source ping -c 1 -W 1 $target_ip >/dev/null 2>&1; then
        echo -e "${GREEN}●${NC} UP"
    else
        echo -e "${RED}●${NC} DOWN"
    fi
}

# Get QUIC connection count
get_quic_connections() {
    local node=$1
    local count=$(docker exec $node sh -c "netstat -tn 2>/dev/null | grep -c ':443.*ESTABLISHED' || echo 0")
    echo "$count"
}

# Monitor tinc logs for errors
check_recent_errors() {
    local node=$1
    local errors=$(docker logs --since 10s $node 2>&1 | grep -iE "error|fail|crash|invalid" | wc -l)
    if [ "$errors" -gt 0 ]; then
        echo -e "${RED}$errors errors${NC}"
    else
        echo -e "${GREEN}OK${NC}"
    fi
}

# Show node status
show_node_status() {
    local node=$1
    local vpn_ip=$2
    local display_name=$3

    echo -e "${YELLOW}┌─ $display_name ($node)${NC}"

    # Container status
    local status=$(docker inspect -f '{{.State.Status}}' $node 2>/dev/null || echo "stopped")
    if [ "$status" == "running" ]; then
        echo -e "│  Status: ${GREEN}Running${NC}"
    else
        echo -e "│  Status: ${RED}$status${NC}"
        echo -e "└────────────────────────────────────────────"
        return
    fi

    # Get stats
    local stats=$(get_container_stats $node)
    local cpu=$(echo "$stats" | cut -f1)
    local mem=$(echo "$stats" | cut -f2)
    local net=$(echo "$stats" | cut -f3)

    echo -e "│  CPU: ${CYAN}$cpu${NC}  |  Memory: ${CYAN}$mem${NC}"
    echo -e "│  Network I/O: ${CYAN}$net${NC}"

    # QUIC connections
    local conn_count=$(get_quic_connections $node)
    echo -e "│  QUIC connections: ${CYAN}$conn_count${NC}"

    # Recent errors
    local error_status=$(check_recent_errors $node)
    echo -e "│  Health: $error_status"

    echo -e "└────────────────────────────────────────────"
    echo ""
}

# Show VPN connectivity matrix
show_connectivity_matrix() {
    echo -e "${YELLOW}VPN Connectivity Matrix:${NC}"
    echo -e "┌─────────┬──────────┬──────────┬──────────┐"
    echo -e "│  From   │  Node1   │  Node2   │  Node3   │"
    echo -e "├─────────┼──────────┼──────────┼──────────┤"

    # Node1 row
    local n1_n2=$(check_vpn_connectivity tinc-node1 10.0.0.2)
    local n1_n3=$(check_vpn_connectivity tinc-node1 10.0.0.3)
    echo -e "│  Node1  │    -     │  $n1_n2    │  $n1_n3    │"

    # Node2 row
    local n2_n1=$(check_vpn_connectivity tinc-node2 10.0.0.1)
    local n2_n3=$(check_vpn_connectivity tinc-node2 10.0.0.3)
    echo -e "│  Node2  │  $n2_n1    │    -     │  $n2_n3    │"

    # Node3 row
    local n3_n1=$(check_vpn_connectivity tinc-node3 10.0.0.1)
    local n3_n2=$(check_vpn_connectivity tinc-node3 10.0.0.2)
    echo -e "│  Node3  │  $n3_n1    │  $n3_n2    │    -     │"

    echo -e "└─────────┴──────────┴──────────┴──────────┘"
    echo ""
}

# Show live traffic stats
show_traffic_stats() {
    echo -e "${YELLOW}Live Traffic Statistics (last ${INTERVAL}s):${NC}"
    echo ""

    for node in tinc-node1 tinc-node2 tinc-node3; do
        # Get interface stats from tinc0
        local stats=$(docker exec $node sh -c "cat /sys/class/net/tinc0/statistics/rx_bytes /sys/class/net/tinc0/statistics/tx_bytes 2>/dev/null || echo '0 0'")
        local rx=$(echo "$stats" | head -1)
        local tx=$(echo "$stats" | tail -1)

        # Convert to human readable
        local rx_mb=$(echo "scale=2; $rx / 1048576" | bc 2>/dev/null || echo "0")
        local tx_mb=$(echo "scale=2; $tx / 1048576" | bc 2>/dev/null || echo "0")

        echo -e "  ${CYAN}$node${NC}: ↓ ${rx_mb} MB  ↑ ${tx_mb} MB"
    done
    echo ""
}

# Show active connections
show_active_connections() {
    echo -e "${YELLOW}Active QUIC Connections:${NC}"
    echo ""

    for node in tinc-node1 tinc-node2 tinc-node3; do
        echo -e "${CYAN}$node:${NC}"
        docker exec $node sh -c "netstat -tn 2>/dev/null | grep ':443.*ESTABLISHED' | awk '{print \$5}' | sed 's/:.*//' | sort -u" 2>/dev/null | while read ip; do
            echo "  → $ip"
        done || echo "  (none)"
        echo ""
    done
}

# Main monitoring loop
monitor_loop() {
    while true; do
        show_header

        # Container and resource status
        show_node_status tinc-node1 10.0.0.1 "Node 1 (Hub)"
        show_node_status tinc-node2 10.0.0.2 "Node 2 (Mid)"
        show_node_status tinc-node3 10.0.0.3 "Node 3 (Edge)"

        # Connectivity matrix
        show_connectivity_matrix

        # Traffic stats
        show_traffic_stats

        # Active connections
        show_active_connections

        echo -e "${BLUE}Press Ctrl+C to exit${NC}"
        echo -e "Refresh interval: ${INTERVAL}s"

        sleep $INTERVAL
    done
}

# Show simple stats (non-interactive)
show_simple_stats() {
    echo "=== TINC-QUIC VPN Status ==="
    echo ""
    echo "Container Status:"
    docker compose ps
    echo ""

    echo "VPN Connectivity:"
    echo -n "  node1 → node2: "
    if docker exec tinc-node1 ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
    fi

    echo -n "  node2 → node3: "
    if docker exec tinc-node2 ping -c 1 -W 1 10.0.0.3 >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
    fi

    echo -n "  node1 → node3: "
    if docker exec tinc-node1 ping -c 1 -W 1 10.0.0.3 >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
    fi

    echo ""
    echo "Recent Errors:"
    for node in tinc-node1 tinc-node2 tinc-node3; do
        errors=$(docker logs --since 60s $node 2>&1 | grep -iE "error|fail|crash" | wc -l)
        echo "  $node: $errors errors in last 60s"
    done
}

# Parse arguments
case "${1:-live}" in
    live)
        monitor_loop
        ;;
    simple)
        show_simple_stats
        ;;
    traffic)
        while true; do
            clear
            show_header
            show_traffic_stats
            show_active_connections
            sleep $INTERVAL
        done
        ;;
    *)
        echo "Usage: $0 {live|simple|traffic}"
        echo ""
        echo "Modes:"
        echo "  live    - Full real-time dashboard (default)"
        echo "  simple  - One-time status check"
        echo "  traffic - Traffic and connection stats only"
        echo ""
        echo "Environment:"
        echo "  INTERVAL - Refresh interval in seconds (default: 2)"
        exit 1
        ;;
esac
