#!/bin/bash
set -e

# Start the environment if not running
# make -C docker up

echo "Starting iperf3 server on node3..."
docker exec -d tinc-node3 iperf3 -s

echo "Waiting for server to start..."
sleep 2

echo "Running iperf3 client on node2 connecting to node3 (10.0.0.3)..."
docker exec tinc-node2 iperf3 -c 10.0.0.3 -t 10

echo "Test complete."
