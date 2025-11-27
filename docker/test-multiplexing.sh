#!/bin/bash
# Test script for QUIC connection multiplexing patterns

echo "======================================================================"
echo "QUIC Connection Multiplexing Test"
echo "======================================================================"
echo ""

echo "1. Checking stream pool initialization..."
echo "----------------------------------------------------------------------"
docker logs tinc-node1 2>&1 | grep -E "Stream pool initialized|Stream [0-9] opened with priority" | tail -20
echo ""

echo "2. Testing VPN connectivity..."
echo "----------------------------------------------------------------------"
echo "Node1 -> Node2 (10.0.0.2):"
docker exec tinc-node1 ping -c 3 -W 2 10.0.0.2 2>&1 | grep "bytes from\|packet loss"
echo ""
echo "Node1 -> Node3 (10.0.0.3):"
docker exec tinc-node1 ping -c 3 -W 2 10.0.0.3 2>&1 | grep "bytes from\|packet loss"
echo ""

echo "3. Checking QUIC stream activity..."
echo "----------------------------------------------------------------------"
echo "Recent stream sends (node1):"
docker logs tinc-node1 2>&1 | grep "stream send complete" | tail -10 | wc -l
echo "Recent datagram activity (node1):"
docker logs tinc-node1 2>&1 | grep "datagram" | tail -10
echo ""

echo "4. Connection multiplexing summary..."
echo "----------------------------------------------------------------------"
echo "Node1:"
docker logs tinc-node1 2>&1 | grep "Stream pool initialized" | tail -2
echo ""
echo "Node2:"
docker logs tinc-node2 2>&1 | grep "Stream pool initialized" | tail -2
echo ""
echo "Node3:"
docker logs tinc-node3 2>&1 | grep "Stream pool initialized" | tail -2
echo ""

echo "======================================================================"
echo "Test completed!"
echo "======================================================================"
