/*
    config_template.c -- Generate default tinc.conf template
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "config_template.h"

/*
 * Default tinc.conf template with all options documented.
 * %s placeholders will be replaced by generate_default_config():
 *   1. Node name
 *   2. Generation timestamp
 */
static const char *config_template =
"# ==============================================================================\n"
"# Tinc QUIC VPN Configuration\n"
"# ==============================================================================\n"
"# Generated: %s\n"
"# Documentation: https://www.tinc-vpn.org/documentation/\n"
"# ==============================================================================\n"
"\n"
"# ==============================================================================\n"
"# BASIC SETTINGS (Required)\n"
"# ==============================================================================\n"
"\n"
"# Name of this node (required, alphanumeric and underscores only)\n"
"Name = %s\n"
"\n"
"# Port to listen on (default: 655, using 443 for DPI evasion)\n"
"Port = 443\n"
"\n"
"# Device type: tun (IP-level) or tap (Ethernet-level)\n"
"# tun is more efficient for routing, tap needed for bridging\n"
"DeviceType = tun\n"
"\n"
"# Network interface name for the VPN tunnel\n"
"Interface = tinc0\n"
"\n"
"# Operating mode:\n"
"#   router - Route packets between subnets (most common)\n"
"#   switch - Act as Ethernet switch (for tap devices)\n"
"#   hub    - Broadcast all packets (legacy)\n"
"Mode = router\n"
"\n"
"# Transport protocol:\n"
"#   quic - QUIC over UDP with TLS 1.3 (recommended for DPI evasion)\n"
"#   tcp  - Legacy TCP transport (not recommended)\n"
"TransportMode = quic\n"
"\n"
"# ==============================================================================\n"
"# VPN ADDRESS CONFIGURATION\n"
"# ==============================================================================\n"
"\n"
"# VPN address for this node (replaces tinc-up script)\n"
"# Format: IP/prefix (e.g., 10.0.0.1/24 for server, 10.0.0.x/24 for clients)\n"
"# Leave commented if using tinc-up script or join command\n"
"#VPNAddress = 10.0.0.1/24\n"
"\n"
"# Additional routes to add when VPN is up\n"
"# Format: network/prefix (multiple Route lines allowed)\n"
"#Route = 192.168.1.0/24\n"
"#Route = 172.16.0.0/12\n"
"\n"
"# Subnet owned by this node (for routing)\n"
"# Automatically derived from VPNAddress if not specified\n"
"#Subnet = 10.0.0.1/32\n"
"\n"
"# ==============================================================================\n"
"# CONNECTION SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Nodes to connect to on startup (multiple ConnectTo lines allowed)\n"
"# Use hostnames or IP addresses of other tinc nodes\n"
"#ConnectTo = server1\n"
"#ConnectTo = server2\n"
"\n"
"# Automatically connect to other nodes when needed\n"
"AutoConnect = yes\n"
"\n"
"# Addresses to bind to (default: all interfaces)\n"
"# Multiple BindToAddress lines allowed\n"
"#BindToAddress = 0.0.0.0\n"
"#BindToAddress = ::\n"
"\n"
"# Alternative: Listen on specific addresses only\n"
"#ListenAddress = 0.0.0.0 443\n"
"#ListenAddress = :: 443\n"
"\n"
"# Bind to specific network interface\n"
"#BindToInterface = eth0\n"
"\n"
"# Address family preference: ipv4, ipv6, or any\n"
"#AddressFamily = any\n"
"\n"
"# ==============================================================================\n"
"# TIMING AND KEEPALIVE\n"
"# ==============================================================================\n"
"\n"
"# Interval between keepalive pings (seconds)\n"
"PingInterval = 10\n"
"\n"
"# Timeout before considering a node unreachable (seconds)\n"
"PingTimeout = 5\n"
"\n"
"# Maximum reconnection timeout (seconds, default: 900)\n"
"#MaxTimeout = 900\n"
"\n"
"# Maximum connection attempts per second (default: 100)\n"
"#MaxConnectionBurst = 100\n"
"\n"
"# ==============================================================================\n"
"# MTU AND PACKET HANDLING\n"
"# ==============================================================================\n"
"\n"
"# Maximum Transmission Unit (bytes)\n"
"# Recommended: 1400 for QUIC (accounts for overhead)\n"
"MTU = 1400\n"
"\n"
"# Enable Path MTU Discovery\n"
"#PMTUDiscovery = yes\n"
"\n"
"# Override PMTU for specific connections\n"
"#PMTU = 1400\n"
"\n"
"# Clamp TCP MSS to avoid fragmentation\n"
"#ClampMSS = yes\n"
"\n"
"# Output buffer size (bytes)\n"
"#MaxOutputBufferSize = 10485760\n"
"\n"
"# UDP buffer sizes (bytes)\n"
"#UDPRcvBuf = 1048576\n"
"#UDPSndBuf = 1048576\n"
"\n"
"# Firewall mark for outgoing packets (Linux only)\n"
"#FWMark = 0\n"
"\n"
"# ==============================================================================\n"
"# SECURITY SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Replay window size for packet deduplication (default: 32)\n"
"#ReplayWindow = 32\n"
"\n"
"# Key expiration time in seconds (default: 3600)\n"
"#KeyExpire = 3600\n"
"\n"
"# Invitation expiration time in seconds (default: 604800 = 1 week)\n"
"#InvitationExpire = 604800\n"
"\n"
"# Only accept connections from nodes with pre-configured subnets\n"
"#StrictSubnets = no\n"
"\n"
"# Act as tunnel server (don't forward between clients)\n"
"#TunnelServer = no\n"
"\n"
"# Decrement TTL on forwarded packets\n"
"#DecrementTTL = no\n"
"\n"
"# Inherit TOS/priority from inner packets\n"
"#PriorityInheritance = no\n"
"\n"
"# ==============================================================================\n"
"# ROUTING AND FORWARDING\n"
"# ==============================================================================\n"
"\n"
"# Forwarding mode:\n"
"#   off      - Only forward packets for directly connected nodes\n"
"#   internal - Forward packets internally (default)\n"
"#   kernel   - Let kernel handle forwarding\n"
"#Forwarding = internal\n"
"\n"
"# Direct-only mode: only connect to nodes we have addresses for\n"
"#DirectOnly = no\n"
"\n"
"# Indirect data: allow data through other nodes (required for mesh)\n"
"#IndirectData = no\n"
"\n"
"# Enable local network discovery\n"
"#LocalDiscovery = yes\n"
"\n"
"# ==============================================================================\n"
"# BROADCAST SETTINGS (for switch/hub mode)\n"
"# ==============================================================================\n"
"\n"
"# Broadcast mode: no, mst (minimum spanning tree), or direct\n"
"#Broadcast = mst\n"
"\n"
"# Subnets to broadcast to\n"
"#BroadcastSubnet = 10.0.0.0/24\n"
"\n"
"# MAC address cache expiration (seconds, for switch mode)\n"
"#MACExpire = 600\n"
"\n"
"# ==============================================================================\n"
"# UDP DISCOVERY\n"
"# ==============================================================================\n"
"\n"
"# Enable UDP hole punching discovery\n"
"#UDPDiscovery = yes\n"
"\n"
"# UDP discovery intervals (seconds)\n"
"#UDPDiscoveryKeepaliveInterval = 9\n"
"#UDPDiscoveryInterval = 2\n"
"#UDPDiscoveryTimeout = 30\n"
"\n"
"# Info intervals for MTU and UDP status (seconds)\n"
"#MTUInfoInterval = 5\n"
"#UDPInfoInterval = 5\n"
"\n"
"# ==============================================================================\n"
"# COMPRESSION\n"
"# ==============================================================================\n"
"\n"
"# Compression level (0 = off, 1-9 = zlib, 10 = LZO, 11 = LZ4)\n"
"# Higher values = more CPU, better compression\n"
"#Compression = 0\n"
"\n"
"# ==============================================================================\n"
"# QUIC DPI EVASION SETTINGS\n"
"# ==============================================================================\n"
"# These settings help hide VPN traffic from Deep Packet Inspection (DPI)\n"
"\n"
"# ----- Timing Jitter -----\n"
"# Adds random delay to packets to hide timing patterns\n"
"# Range: 0 (disabled) to 50000 (50ms)\n"
"# Recommended:\n"
"#   0     - Disabled (lowest latency)\n"
"#   1000  - Default (1ms, balanced)\n"
"#   2000  - Moderate (2ms, good DPI evasion)\n"
"#   5000  - Strong (5ms, maximum evasion)\n"
"QUICJitterMaxUs = 0\n"
"\n"
"# ----- SNI Domain Pool -----\n"
"# Custom domains for TLS SNI field (helps bypass SNI-based blocking)\n"
"# Default: 12 popular CDN/cloud domains if not specified\n"
"# Comma-separated list of domains for your region:\n"
"#QUICSNIDomains = www.cloudflare.com, cdn.jsdelivr.net, api.github.com\n"
"\n"
"# ----- Connection Multiplexing -----\n"
"# Number of parallel QUIC streams (mimics browser behavior)\n"
"# Range: 1-10, Default: 6\n"
"# More streams = better browser imitation, slightly more overhead\n"
"QUICStreamCount = 6\n"
"\n"
"# ----- Keepalive Configuration -----\n"
"# Periodic packets to maintain connection and mimic activity\n"
"# Interval range in seconds (random within range)\n"
"# Set to 0 to disable\n"
"QUICKeepaliveMin = 5\n"
"QUICKeepaliveMax = 15\n"
"\n"
"# Keepalive packet size in bytes (16-512)\n"
"QUICKeepaliveSize = 64\n"
"\n"
"# ----- HTTP/3 Masquerading -----\n"
"# Wrap VPN traffic in HTTP/3 frames to look like web browsing\n"
"# Very effective against DPI: mimics browser behavior with\n"
"# realistic User-Agent, Accept headers, common URL paths\n"
"QUICHTTP3Masquerading = yes\n"
"\n"
"# Interval between fake HTTP requests (seconds, 0 = disabled)\n"
"#HTTP3HeadersInterval = 30\n"
"\n"
"# ----- Packet Padding -----\n"
"# Add random padding to hide packet sizes\n"
"# Modes: off, random, fixed, adaptive\n"
"QUICPaddingMode = off\n"
"\n"
"# Padding size range (bytes, for random/adaptive modes)\n"
"#QUICPaddingMin = 0\n"
"#QUICPaddingMax = 128\n"
"\n"
"# Only pad small packets (reduces overhead)\n"
"#QUICPaddingSmallPacketsOnly = yes\n"
"\n"
"# Threshold below which packets are considered \"small\" (bytes)\n"
"#QUICPaddingThreshold = 128\n"
"\n"
"# ----- Certificate Trust -----\n"
"# Trust system CA store for public certificates (Let's Encrypt, etc.)\n"
"# Required for initial 'join' before CA is received from inviter\n"
"# Safe: security comes from invitation token, not TLS certificate chain\n"
"QUICTrustPublicCerts = yes\n"
"\n"
"# ----- Debug Level -----\n"
"# QUIC-specific debug output (0-5, 0 = off)\n"
"QUICDebugLevel = 0\n"
"\n"
"# ==============================================================================\n"
"# TLS CERTIFICATES FOR QUIC\n"
"# ==============================================================================\n"
"# For maximum DPI evasion, use real certificates (e.g., Let's Encrypt)\n"
"# This makes the server appear as a legitimate HTTPS website\n"
"\n"
"# Path to TLS certificate file (PEM format)\n"
"# Use fullchain.pem for Let's Encrypt certificates\n"
"#QUICCertFile = /etc/tinc/certs/fullchain.pem\n"
"\n"
"# Path to TLS private key file (PEM format)\n"
"#QUICKeyFile = /etc/tinc/certs/privkey.pem\n"
"\n"
"# ==============================================================================\n"
"# SYSTEM SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Process priority: low, normal, high\n"
"#ProcessPriority = normal\n"
"\n"
"# Log level (0-5, higher = more verbose)\n"
"#LogLevel = 0\n"
"\n"
"# Script interpreter (for tinc-up, tinc-down, etc.)\n"
"#ScriptsInterpreter = /bin/sh\n"
"\n"
"# Script file extension\n"
"#ScriptsExtension = \n"
"\n"
"# Proxy for outgoing connections\n"
"# Format: socks4|socks5|http|exec host port [username password]\n"
"#Proxy = socks5 127.0.0.1 1080\n"
"\n"
"# Put device in standby mode when not in use\n"
"#DeviceStandby = no\n"
"\n"
"# Enable UPnP port forwarding\n"
"#UPnP = no\n"
"#UPnPDiscoverWait = 5\n"
"#UPnPRefreshPeriod = 60\n"
"\n"
"# Show hostnames instead of IP addresses in logs\n"
"#Hostnames = no\n"
"\n"
"# Disable connections from buggy peers\n"
"#DisableBuggyPeers = no\n"
"\n"
"# Use TCP only (disable UDP)\n"
"#TCPOnly = no\n"
"\n"
"# ==============================================================================\n"
"# LINUX-SPECIFIC SETTINGS\n"
"# ==============================================================================\n"
"\n"
"# Use single queue mode for TUN device (may improve performance)\n"
"#IffOneQueue = no\n"
"\n"
"# Device path (default: /dev/net/tun)\n"
"#Device = /dev/net/tun\n"
"\n"
"# ==============================================================================\n"
"# END OF CONFIGURATION\n"
"# ==============================================================================\n"
;

bool generate_default_config(const char *filepath, const char *node_name) {
	if(!filepath || !node_name || !node_name[0]) {
		return false;
	}

	FILE *f = fopen(filepath, "w");
	if(!f) {
		return false;
	}

	/* Get current timestamp */
	time_t now = time(NULL);
	char timestamp[64];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

	/* Write template with substitutions */
	fprintf(f, config_template, timestamp, node_name);

	fclose(f);
	return true;
}

bool config_file_exists(const char *confbase) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/tinc.conf", confbase);

	struct stat st;
	return stat(path, &st) == 0;
}

bool ensure_config_dirs(const char *confbase) {
	/* Create confbase directory */
	if(mkdir(confbase, 0755) && errno != EEXIST) {
		return false;
	}

	/* Create hosts directory (legacy, may still be needed) */
	char hosts_dir[PATH_MAX];
	snprintf(hosts_dir, sizeof(hosts_dir), "%s/hosts", confbase);
	if(mkdir(hosts_dir, 0755) && errno != EEXIST) {
		return false;
	}

	/* Create cache directory (not fatal if fails) */
	char cache_dir[PATH_MAX];
	snprintf(cache_dir, sizeof(cache_dir), "%s/cache", confbase);
	mkdir(cache_dir, 0755); /* Ignore errors */

	return true;
}
