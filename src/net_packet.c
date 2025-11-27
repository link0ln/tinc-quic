/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2021 Guus Sliepen <guus@tinc-vpn.org>
                  2010      Timothy Redaelli <timothy@redaelli.eu>
                  2010      Brandon Black <blblack@gmail.com>

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

#ifdef HAVE_ZLIB
#define ZLIB_CONST
#include <zlib.h>
#endif

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#include "address_cache.h"
#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "device.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "quic.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* The minimum size of a probe is 14 bytes, but since we normally use CBC mode
   encryption, we can add a few extra random bytes without increasing the
   resulting packet size. */
#define MIN_PROBE_SIZE 18

int keylifetime = 0;
#ifdef HAVE_LZO
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
#endif

static void send_udppacket(node_t *, vpn_packet_t *);

unsigned replaywin = 32;
bool localdiscovery = true;
bool udp_discovery = true;
int udp_discovery_keepalive_interval = 10;
int udp_discovery_interval = 2;
int udp_discovery_timeout = 30;

#define MAX_SEQNO 1073741824

static void try_fix_mtu(node_t *n) {
	if(n->mtuprobes < 0) {
		return;
	}

	if(n->mtuprobes == 20 || n->minmtu >= n->maxmtu) {
		if(n->minmtu > n->maxmtu) {
			n->minmtu = n->maxmtu;
		} else {
			n->maxmtu = n->minmtu;
		}

		n->mtu = n->minmtu;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = -1;
	}
}

static void udp_probe_timeout_handler(void *data) {
	node_t *n = data;

	if(!n->status.udp_confirmed) {
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Too much time has elapsed since last UDP ping response from %s (%s), stopping UDP communication", n->name, n->hostname);
	n->status.udp_confirmed = false;
	n->udp_ping_rtt = -1;
	n->maxrecentlen = 0;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
}

static void send_udp_probe_reply(node_t *n, vpn_packet_t *packet, length_t len) {
	/* Type 2 probe replies were introduced in protocol 17.3 */
	if((n->options >> 24) >= 3) {
		DATA(packet)[0] = 2;
		uint16_t len16 = htons(len);
		memcpy(DATA(packet) + 1, &len16, 2);
		packet->len = MIN_PROBE_SIZE;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 2 probe reply length %u to %s (%s)", len, n->name, n->hostname);

	} else {
		/* Legacy protocol: n won't understand type 2 probe replies. */
		DATA(packet)[0] = 1;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 1 probe reply length %u to %s (%s)", len, n->name, n->hostname);
	}

	/* Temporarily set udp_confirmed, so that the reply is sent
	   back exactly the way it came in. */

	bool udp_confirmed = n->status.udp_confirmed;
	n->status.udp_confirmed = true;
	send_udppacket(n, packet);
	n->status.udp_confirmed = udp_confirmed;
}

static void udp_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	if(!DATA(packet)[0]) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got UDP probe request %d from %s (%s)", packet->len, n->name, n->hostname);
		send_udp_probe_reply(n, packet, len);
		return;
	}

	if(DATA(packet)[0] == 2) {
		// It's a type 2 probe reply, use the length field inside the packet
		uint16_t len16;
		memcpy(&len16, DATA(packet) + 1, 2);
		len = ntohs(len16);
	}

	if(n->status.ping_sent) {  // a probe in flight
		gettimeofday(&now, NULL);
		struct timeval rtt;
		timersub(&now, &n->udp_ping_sent, &rtt);
		n->udp_ping_rtt = rtt.tv_sec * 1000000 + rtt.tv_usec;
		n->status.ping_sent = false;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d UDP probe reply %d from %s (%s) rtt=%d.%03d", DATA(packet)[0], len, n->name, n->hostname, n->udp_ping_rtt / 1000, n->udp_ping_rtt % 1000);
	} else {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d UDP probe reply %d from %s (%s)", DATA(packet)[0], len, n->name, n->hostname);
	}

	/* It's a valid reply: now we know bidirectional communication
	   is possible using the address and socket that the reply
	   packet used. */
	if(!n->status.udp_confirmed) {
		n->status.udp_confirmed = true;

		if(!n->address_cache) {
			n->address_cache = open_address_cache(n);
		}

		reset_address_cache(n->address_cache, &n->address);
	}

	// Reset the UDP ping timer.

	if(udp_discovery) {
		timeout_del(&n->udp_ping_timeout);
		timeout_add(&n->udp_ping_timeout, &udp_probe_timeout_handler, n, &(struct timeval) {
			udp_discovery_timeout, 0
		});
	}

	if(len > n->maxmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Increase in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->minmtu = len;
		n->maxmtu = MTU;
		/* Set mtuprobes to 1 so that try_mtu() doesn't reset maxmtu */
		n->mtuprobes = 1;
		return;
	} else if(n->mtuprobes < 0 && len == n->maxmtu) {
		/* We got a maxmtu sized packet, confirming the PMTU is still valid. */
		n->mtuprobes = -1;
		n->mtu_ping_sent = now;
	}

	/* If applicable, raise the minimum supported MTU */

	if(n->minmtu < len) {
		n->minmtu = len;
		try_fix_mtu(n);
	}
}

/* compress_packet and uncompress_packet removed - QUIC mode uses native QUIC compression */

/* VPN packet I/O */

void receive_packet(node_t *n, vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received packet of %d bytes from %s (%s)",
	       packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	/* Ethernet type (bytes 12-13) is already set by sender from TUN PI header.
	   In QUIC mode, packets are sent with correct Ethernet type preserved from
	   the TUN device PI header, so no need to re-detect or modify it here. */

	route(n, packet);
}

/* try_mac and receive_udppacket removed - QUIC only mode */

void receive_tcppacket(connection_t *c, const char *buffer, size_t len) {
	vpn_packet_t outpkt;
	outpkt.offset = DEFAULT_PACKET_OFFSET;

	if(len > sizeof(outpkt.data) - outpkt.offset) {
		return;
	}

	outpkt.len = len;

	if(c->options & OPTION_TCPONLY) {
		outpkt.priority = 0;
	} else {
		outpkt.priority = -1;
	}

	memcpy(DATA(&outpkt), buffer, len);

	receive_packet(c->node, &outpkt);
}

/* SPTPS over TCP removed - QUIC only mode */
/* SPTPS over TCP removed - QUIC only mode */

/* Simplified packet send - QUIC only mode */
static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	/* FIX: Store connection pointer locally to prevent race condition
	 * Another thread could set n->connection = NULL between check and use
	 */
	connection_t *c = n->connection;
	if(!c) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Cannot send packet to %s - no connection", n->name);
		return;
	}

#ifdef HAVE_MSQUIC
	/* Use QUIC datagram - use local c pointer throughout */
	void *qc = c->quic_context;
	if(qc) {
		if(quic_send_packet(c, origpkt)) {
			return;
		}
		logger(DEBUG_TRAFFIC, LOG_ERR, "QUIC datagram send failed to %s", n->name);
		return;
	}
#endif

	logger(DEBUG_TRAFFIC, LOG_ERR, "No QUIC context for %s - cannot send packet", n->name);
}

static void adapt_socket(const sockaddr_t *sa, int *sock) {
	/* Make sure we have a suitable socket for the chosen address */
	if(listen_socket[*sock].sa.sa.sa_family != sa->sa.sa_family) {
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				*sock = i;
				break;
			}
		}
	}
}

static void choose_udp_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	/* Latest guess */
	*sa = &n->address;
	*sock = n->sock;

	/* If the UDP address is confirmed, use it. */
	if(n->status.udp_confirmed) {
		return;
	}

	/* Send every third packet to n->address; that could be set
	   to the node's reflexive UDP address discovered during key
	   exchange. */

	static int x = 0;

	if(++x >= 3) {
		x = 0;
		return;
	}

	/* Otherwise, address are found in edges to this node.
	   So we pick a random edge and a random socket. */

	int i = 0;
	int j = rand() % n->edge_tree->count;
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(i++ == j) {
			candidate = e->reverse;
			break;
		}
	}

	if(candidate) {
		*sa = &candidate->address;
		*sock = rand() % listen_sockets;
	}

	adapt_socket(*sa, sock);
}

static void choose_local_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	*sa = NULL;

	/* Pick one of the edges from this node at random, then use its local address. */

	int i = 0;
	int j = rand() % n->edge_tree->count;
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(i++ == j) {
			candidate = e;
			break;
		}
	}

	if(candidate && candidate->local_address.sa.sa_family) {
		*sa = &candidate->local_address;
		*sock = rand() % listen_sockets;
		adapt_socket(*sa, sock);
	}
}

/* Simplified UDP packet send - QUIC only mode */
static void send_udppacket(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

#ifdef HAVE_MSQUIC
	/* Use QUIC datagram */
	if(n->connection && n->connection->quic_context) {
		if(quic_send_packet(n->connection, origpkt)) {
			return;
		}
		logger(DEBUG_TRAFFIC, LOG_ERR, "QUIC datagram send failed to %s", n->name);
		return;
	}
#endif

	logger(DEBUG_TRAFFIC, LOG_ERR, "No QUIC connection to %s - cannot send packet", n->name);
}

/* SPTPS data relay removed - QUIC only mode */
/* SPTPS data relay removed - QUIC only mode */

/* SPTPS record handler removed - QUIC only mode */
/* SPTPS record handler removed - QUIC only mode */

/* SPTPS key exchange removed - QUIC only mode */
/* SPTPS key exchange removed - QUIC only mode */

static void send_udp_probe_packet(node_t *n, int len) {
	vpn_packet_t packet;
	packet.offset = DEFAULT_PACKET_OFFSET;
	memset(DATA(&packet), 0, 14);
	randomize(DATA(&packet) + 14, len - 14);
	packet.len = len;
	packet.priority = 0;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending UDP probe length %d to %s (%s)", len, n->name, n->hostname);

	send_udppacket(n, &packet);
}

// This function tries to establish a UDP tunnel to a node so that packets can be sent.
// If a tunnel is already established, it makes sure it stays up.
// This function makes no guarantees - it is up to the caller to check the node's state to figure out if UDP is usable.
static void try_udp(node_t *n) {
	if(!udp_discovery) {
		return;
	}

	/* Send gratuitous probe replies to 1.1 nodes. */

	if((n->options >> 24) >= 3 && n->status.udp_confirmed) {
		struct timeval ping_tx_elapsed;
		timersub(&now, &n->udp_reply_sent, &ping_tx_elapsed);

		if(ping_tx_elapsed.tv_sec >= udp_discovery_keepalive_interval - 1) {
			n->udp_reply_sent = now;

			if(n->maxrecentlen) {
				vpn_packet_t pkt;
				pkt.len = n->maxrecentlen;
				pkt.offset = DEFAULT_PACKET_OFFSET;
				memset(DATA(&pkt), 0, 14);
				randomize(DATA(&pkt) + 14, MIN_PROBE_SIZE - 14);
				send_udp_probe_reply(n, &pkt, pkt.len);
				n->maxrecentlen = 0;
			}
		}
	}

	/* Probe request */

	struct timeval ping_tx_elapsed;
	timersub(&now, &n->udp_ping_sent, &ping_tx_elapsed);

	int interval = n->status.udp_confirmed ? udp_discovery_keepalive_interval : udp_discovery_interval;

	if(ping_tx_elapsed.tv_sec >= interval) {
		gettimeofday(&now, NULL);
		n->udp_ping_sent = now; // a probe in flight
		n->status.ping_sent = true;
		send_udp_probe_packet(n, MIN_PROBE_SIZE);

		if(localdiscovery && !n->status.udp_confirmed && n->prevedge) {
			n->status.send_locally = true;
			send_udp_probe_packet(n, MIN_PROBE_SIZE);
			n->status.send_locally = false;
		}
	}
}

static length_t choose_initial_maxmtu(node_t *n) {
#ifdef IP_MTU

	int sock = -1;

	const sockaddr_t *sa = NULL;
	int sockindex;
	choose_udp_address(n, &sa, &sockindex);

	if(!sa) {
		return MTU;
	}

	sock = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(sock < 0) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Creating MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		return MTU;
	}

	if(connect(sock, &sa->sa, SALEN(sa->sa))) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Connecting MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		close(sock);
		return MTU;
	}

	int ip_mtu;
	socklen_t ip_mtu_len = sizeof(ip_mtu);

	if(getsockopt(sock, IPPROTO_IP, IP_MTU, &ip_mtu, &ip_mtu_len)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		close(sock);
		return MTU;
	}

	close(sock);

	/* getsockopt(IP_MTU) returns the MTU of the physical interface.
	   We need to remove various overheads to get to the tinc MTU. */
	length_t mtu = ip_mtu;
	mtu -= (sa->sa.sa_family == AF_INET6) ? sizeof(struct ip6_hdr) : sizeof(struct ip);
	mtu -= 8; /* UDP */

	/* In QUIC mode, QUIC handles encryption overhead internally */
	/* No additional overhead calculation needed */

	if(mtu < 512) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) returned absurdly small value: %d", n->name, n->hostname, ip_mtu);
		return MTU;
	}

	if(mtu > MTU) {
		return MTU;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Using system-provided maximum tinc MTU for %s (%s): %hd", n->name, n->hostname, mtu);
	return mtu;

#else
	(void)n;
	return MTU;
#endif
}

/* This function tries to determines the MTU of a node.
   By calling this function repeatedly, n->minmtu will be progressively
   increased, and at some point, n->mtu will be fixed to n->minmtu.  If the MTU
   is already fixed, this function checks if it can be increased.
*/

static void try_mtu(node_t *n) {
	if(!(n->options & OPTION_PMTU_DISCOVERY)) {
		return;
	}

	if(udp_discovery && !n->status.udp_confirmed) {
		n->maxrecentlen = 0;
		n->mtuprobes = 0;
		n->minmtu = 0;
		n->maxmtu = MTU;
		return;
	}

	/* mtuprobes == 0..19: initial discovery, send bursts with 1 second interval, mtuprobes++
	   mtuprobes ==    20: fix MTU, and go to -1
	   mtuprobes ==    -1: send one maxmtu and one maxmtu+1 probe every pinginterval
	   mtuprobes ==-2..-3: send one maxmtu probe every second
	   mtuprobes ==    -4: maxmtu no longer valid, reset minmtu and maxmtu and go to 0 */

	struct timeval elapsed;
	timersub(&now, &n->mtu_ping_sent, &elapsed);

	if(n->mtuprobes >= 0) {
		if(n->mtuprobes != 0 && elapsed.tv_sec == 0 && elapsed.tv_usec < 333333) {
			return;
		}
	} else {
		if(n->mtuprobes < -1) {
			if(elapsed.tv_sec < 1) {
				return;
			}
		} else {
			if(elapsed.tv_sec < pinginterval) {
				return;
			}
		}
	}

	n->mtu_ping_sent = now;

	try_fix_mtu(n);

	if(n->mtuprobes < -3) {
		/* We lost three MTU probes, restart discovery */
		logger(DEBUG_TRAFFIC, LOG_INFO, "Decrease in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->mtuprobes = 0;
		n->minmtu = 0;
	}

	if(n->mtuprobes < 0) {
		/* After the initial discovery, we only send one maxmtu and one
		   maxmtu+1 probe to detect PMTU increases. */
		send_udp_probe_packet(n, n->maxmtu);

		if(n->mtuprobes == -1 && n->maxmtu + 1 < MTU) {
			send_udp_probe_packet(n, n->maxmtu + 1);
		}

		n->mtuprobes--;
	} else {
		/* Before initial discovery begins, set maxmtu to the most likely value.
		   If it's underestimated, we will correct it after initial discovery. */
		if(n->mtuprobes == 0) {
			n->maxmtu = choose_initial_maxmtu(n);
		}

		for(;;) {
			/* Decreasing the number of probes per cycle might make the algorithm react faster to lost packets,
			   but it will typically increase convergence time in the no-loss case. */
			const length_t probes_per_cycle = 8;

			/* This magic value was determined using math simulations.
			   It will result in a 1329-byte first probe, followed (if there was a reply) by a 1407-byte probe.
			   Since 1407 is just below the range of tinc MTUs over typical networks,
			   this fine-tuning allows tinc to cover a lot of ground very quickly.
			   This fine-tuning is only valid for maxmtu = MTU; if maxmtu is smaller,
			   then it's better to use a multiplier of 1. Indeed, this leads to an interesting scenario
			   if choose_initial_maxmtu() returns the actual MTU value - it will get confirmed with one single probe. */
			const float multiplier = (n->maxmtu == MTU) ? 0.97 : 1;

			const float cycle_position = probes_per_cycle - (n->mtuprobes % probes_per_cycle) - 1;
			const length_t minmtu = MAX(n->minmtu, 512);
			const float interval = n->maxmtu - minmtu;

			/* The core of the discovery algorithm is this exponential.
			   It produces very large probes early in the cycle, and then it very quickly decreases the probe size.
			   This reflects the fact that in the most difficult cases, we don't get any feedback for probes that
			   are too large, and therefore we need to concentrate on small offsets so that we can quickly converge
			   on the precise MTU as we are approaching it.
			   The last probe of the cycle is always 1 byte in size - this is to make sure we'll get at least one
			   reply per cycle so that we can make progress. */
			const length_t offset = powf(interval, multiplier * cycle_position / (probes_per_cycle - 1));

			length_t maxmtu = n->maxmtu;
			send_udp_probe_packet(n, minmtu + offset);

			/* If maxmtu changed, it means the probe was rejected by the system because it was too large.
			   In that case, we recalculate with the new maxmtu and try again. */
			if(n->mtuprobes < 0 || maxmtu == n->maxmtu) {
				break;
			}
		}

		if(n->mtuprobes >= 0) {
			n->mtuprobes++;
		}
	}
}

/* These functions try to establish a tunnel to a node (or its relay) so that
   packets can be sent (e.g. exchange keys).
   If a tunnel is already established, it tries to improve it (e.g. by trying
   to establish a UDP tunnel instead of TCP).  This function makes no
   guarantees - it is up to the caller to check the node's state to figure out
   if TCP and/or UDP is usable.  By calling this function repeatedly, the
   tunnel is gradually improved until we hit the wall imposed by the underlying
   network environment.  It is recommended to call this function every time a
   packet is sent (or intended to be sent) to a node, so that the tunnel keeps
   improving as packets flow, and then gracefully downgrades itself as it goes
   idle.
*/

/* Legacy transmission helpers removed - QUIC only mode */
void try_tx(node_t *n, bool mtu) {
	if(!n->status.reachable) {
		return;
	}

	/* In QUIC mode, connections are already established via QUIC handshake */
	/* Just maintain UDP probes for latency monitoring */
	try_udp(n);

	if(mtu) {
		try_mtu(n);
	}
}

void send_packet(node_t *n, vpn_packet_t *packet) {
	// If it's for myself, write it to the tun/tap device.

	if(n == myself) {
		if(overwrite_mac) {
			memcpy(DATA(packet), mymac.x, ETH_ALEN);
			// Use an arbitrary fake source address.
			memcpy(DATA(packet) + ETH_ALEN, DATA(packet), ETH_ALEN);
			DATA(packet)[ETH_ALEN * 2 - 1] ^= 0xFF;
		}

		n->out_packets++;
		n->out_bytes += packet->len;
		devops.write(packet);
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_ERR, "Sending packet of %d bytes to %s (%s)", packet->len, n->name, n->hostname);

	// If the node is not reachable, drop it.

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Node %s (%s) is not reachable", n->name, n->hostname);
		return;
	}

	// Keep track of packet statistics.

	n->out_packets++;
	n->out_bytes += packet->len;

	// In QUIC mode, send via next hop if not directly connected
	// In QUIC, control and data use same connection, so use nexthop instead of via
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "send_packet: dest=%s, n->via=%s, n->nexthop=%s",
	       n->name, n->via ? n->via->name : "NULL", n->nexthop ? n->nexthop->name : "NULL");

	// Use nexthop for QUIC routing (not via, which is for legacy UDP)
	node_t *via = (n->nexthop == myself) ? n : n->nexthop;

	if(via != n) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Routing packet for %s via %s", n->name, via->name);
	}

	send_sptps_packet(via, packet);
	try_tx(via, true);
}

void broadcast_packet(const node_t *from, vpn_packet_t *packet) {
	// Always give ourself a copy of the packet.
	if(from != myself) {
		send_packet(myself, packet);
	}

	// In TunnelServer mode, do not forward broadcast packets.
	// The MST might not be valid and create loops.
	if(tunnelserver || broadcast_mode == BMODE_NONE) {
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Broadcasting packet of %d bytes from %s (%s)",
	       packet->len, from->name, from->hostname);

	switch(broadcast_mode) {
	// In MST mode, broadcast packets travel via the Minimum Spanning Tree.
	// This guarantees all nodes receive the broadcast packet, and
	// usually distributes the sending of broadcast packets over all nodes.
	case BMODE_MST:
		for list_each(connection_t, c, connection_list)
			if(c->edge && c->status.mst && c != from->nexthop->connection) {
				send_packet(c->node, packet);
			}

		break;

	// In direct mode, we send copies to each node we know of.
	// However, this only reaches nodes that can be reached in a single hop.
	// We don't have enough information to forward broadcast packets in this case.
	case BMODE_DIRECT:
		if(from != myself) {
			break;
		}

		for splay_each(node_t, n, node_tree)
			if(n->status.reachable && n != myself && ((n->via == myself && n->nexthop == n) || n->via == n)) {
				send_packet(n, packet);
			}

		break;

	default:
		break;
	}
}

/* Legacy UDP packet handling - stub for io_add callback (QUIC only mode) */
static void handle_incoming_vpn_packet(listen_socket_t *ls, vpn_packet_t *pkt, sockaddr_t *addr) {
	(void)ls;
	(void)pkt;
	char *hostname;

	sockaddrunmap(addr);

	/* In QUIC mode, VPN packets arrive via QUIC datagram callbacks, not UDP */
	if(debug_level >= DEBUG_PROTOCOL) {
		hostname = sockaddr2hostname(addr);
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Received legacy UDP packet from %s - not supported in QUIC mode", hostname);
		free(hostname);
	}
}

void handle_incoming_vpn_data(void *data, int flags) {
	(void)data;
	(void)flags;
	listen_socket_t *ls = data;

#ifdef HAVE_RECVMMSG
#define MAX_MSG 64
	static int num = MAX_MSG;
	static vpn_packet_t pkt[MAX_MSG];
	static sockaddr_t addr[MAX_MSG];
	static struct mmsghdr msg[MAX_MSG];
	static struct iovec iov[MAX_MSG];

	for(int i = 0; i < num; i++) {
		pkt[i].offset = 0;

		iov[i] = (struct iovec) {
			.iov_base = DATA(&pkt[i]),
			.iov_len = MAXSIZE,
		};

		msg[i].msg_hdr = (struct msghdr) {
			.msg_name = &addr[i].sa,
			.msg_namelen = sizeof(addr)[i],
			.msg_iov = &iov[i],
			.msg_iovlen = 1,
		};
	}

	num = recvmmsg(ls->udp.fd, msg, MAX_MSG, MSG_DONTWAIT, NULL);

	if(num < 0) {
		if(!sockwouldblock(sockerrno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	for(int i = 0; i < num; i++) {
		pkt[i].len = msg[i].msg_len;

		if(pkt[i].len <= 0 || pkt[i].len > MAXSIZE) {
			continue;
		}

		handle_incoming_vpn_packet(ls, &pkt[i], &addr[i]);
	}

#else
	vpn_packet_t pkt;
	sockaddr_t addr = {0};
	socklen_t addrlen = sizeof(addr);

	pkt.offset = 0;
	int len = recvfrom(ls->udp.fd, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

	if(len <= 0 || (size_t)len > MAXSIZE) {
		if(!sockwouldblock(sockerrno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	pkt.len = len;

	handle_incoming_vpn_packet(ls, &pkt, &addr);
#endif
}

void handle_device_data(void *data, int flags) {
	(void)data;
	(void)flags;
	vpn_packet_t packet;
	packet.offset = DEFAULT_PACKET_OFFSET;
	packet.priority = 0;
	static int errors = 0;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "handle_device_data called");

	if(devops.read(&packet)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet from device, len=%d", packet.len);
		errors = 0;
		myself->in_packets++;
		myself->in_bytes += packet.len;
		route(myself, &packet);
	} else {
		usleep(errors * 50000);
		errors++;

		if(errors > 10) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many errors from %s, exiting!", device);
			event_exit();
		}
	}
}
