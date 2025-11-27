/*
    protocol_auth.c -- handle the meta-protocol, authentication
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "connection.h"
#include "control.h"
#include "control_common.h"
#include "crypto.h"
#include "device.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "prf.h"
#include "protocol.h"
#include "script.h"
#include "utils.h"
#include "xalloc.h"

/* ed25519/sha512.h removed - QUIC only mode */

int invitation_lifetime;
/* invitation_key removed - QUIC only mode */

static bool send_proxyrequest(connection_t *c) {
	switch(proxytype) {
	case PROXY_HTTP: {
		char *host;
		char *port;

		sockaddr2str(&c->address, &host, &port);
		send_request(c, "CONNECT %s:%s HTTP/1.1\r\n\r", host, port);
		free(host);
		free(port);
		return true;
	}

	case PROXY_SOCKS4: {
		if(c->address.sa.sa_family != AF_INET) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Cannot connect to an IPv6 host through a SOCKS 4 proxy!");
			return false;
		}

		char s4req[9 + (proxyuser ? strlen(proxyuser) : 0)];
		s4req[0] = 4;
		s4req[1] = 1;
		memcpy(s4req + 2, &c->address.in.sin_port, 2);
		memcpy(s4req + 4, &c->address.in.sin_addr, 4);

		if(proxyuser) {
			memcpy(s4req + 8, proxyuser, strlen(proxyuser));
		}

		s4req[sizeof(s4req) - 1] = 0;
		c->tcplen = 8;
		return send_meta(c, s4req, sizeof(s4req));
	}

	case PROXY_SOCKS5: {
		int len = 3 + 6 + (c->address.sa.sa_family == AF_INET ? 4 : 16);
		c->tcplen = 2;

		if(proxypass) {
			len += 3 + strlen(proxyuser) + strlen(proxypass);
		}

		char s5req[len];
		int i = 0;
		s5req[i++] = 5;
		s5req[i++] = 1;

		if(proxypass) {
			s5req[i++] = 2;
			s5req[i++] = 1;
			s5req[i++] = strlen(proxyuser);
			memcpy(s5req + i, proxyuser, strlen(proxyuser));
			i += strlen(proxyuser);
			s5req[i++] = strlen(proxypass);
			memcpy(s5req + i, proxypass, strlen(proxypass));
			i += strlen(proxypass);
			c->tcplen += 2;
		} else {
			s5req[i++] = 0;
		}

		s5req[i++] = 5;
		s5req[i++] = 1;
		s5req[i++] = 0;

		if(c->address.sa.sa_family == AF_INET) {
			s5req[i++] = 1;
			memcpy(s5req + i, &c->address.in.sin_addr, 4);
			i += 4;
			memcpy(s5req + i, &c->address.in.sin_port, 2);
			i += 2;
			c->tcplen += 10;
		} else if(c->address.sa.sa_family == AF_INET6) {
			s5req[i++] = 3;
			memcpy(s5req + i, &c->address.in6.sin6_addr, 16);
			i += 16;
			memcpy(s5req + i, &c->address.in6.sin6_port, 2);
			i += 2;
			c->tcplen += 22;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Address family %x not supported for SOCKS 5 proxies!", c->address.sa.sa_family);
			return false;
		}

		if(i > len) {
			abort();
		}

		return send_meta(c, s5req, sizeof(s5req));
	}

	case PROXY_SOCKS4A:
		logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type not implemented yet");
		return false;

	case PROXY_EXEC:
		return true;

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type");
		return false;
	}
}

bool send_id(connection_t *c) {
	gettimeofday(&c->start, NULL);

	int minor = 0;

	if(experimental) {
		/* In QUIC mode, always use current protocol version */
		minor = myself->connection->protocol_minor;
	}

	if(proxytype && c->outgoing)
		if(!send_proxyrequest(c)) {
			return false;
		}

	return send_request(c, "%d %s %d.%d", ID, myself->connection->name, myself->connection->protocol_major, minor);
}

/* finalize_invitation() removed - QUIC only mode */
/* receive_invitation_sptps() removed - QUIC only mode */

bool id_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %2d.%3d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name,
		       c->hostname);
		return false;
	}

	/* Check if this is a control connection */

	if(name[0] == '^' && !strcmp(name + 1, controlcookie)) {
		c->status.control = true;
		c->allow_request = CONTROL;
		c->last_ping_time = now.tv_sec + 3600;

		free(c->name);
		c->name = xstrdup("<control>");

		if(!c->outgoing) {
			send_id(c);
		}

		return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_CURRENT, getpid());
	}

	/* Invitation handling removed - QUIC only mode */

	/* Check if identity is a valid name */

	if(!check_id(name) || !strcmp(name, myself->name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ID", c->name,
		       c->hostname, "invalid name");
		return false;
	}

	/* If this is an outgoing connection, make sure we are connected to the right host */

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s is %s instead of %s", c->hostname, name,
			       c->name);
			return false;
		}
	} else {
		free(c->name);
		c->name = xstrdup(name);
	}

	/* Check if version matches */

	if(c->protocol_major != myself->connection->protocol_major) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) uses incompatible version %d.%d",
		       c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

#ifdef HAVE_MSQUIC
	/* QUIC only - TLS 1.3 encryption */
	if(c->quic_context) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection to %s - using native QUIC TLS 1.3", c->name);

		if(!c->config_tree) {
			init_configuration(&c->config_tree);
		}

		c->allow_request = ACK;

		if(!c->outgoing) {
			send_id(c);
		}

		return send_ack(c);
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection!");
	return false;
#else
	logger(DEBUG_ALWAYS, LOG_ERR, "QUIC not compiled in!");
	return false;
#endif
}

bool send_ack(connection_t *c) {
	/* Protocol upgrade removed - QUIC only mode */

	/* ACK message contains rest of the information the other end needs
	   to create node_t and edge_t structures. */

	struct timeval now;
	bool choice;

	/* Estimate weight */

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	/* Check some options */

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT) {
		c->options |= OPTION_INDIRECT;
	}

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY) {
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;
	}

	if(myself->options & OPTION_PMTU_DISCOVERY && !(c->options & OPTION_TCPONLY)) {
		c->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = myself->options & OPTION_CLAMP_MSS;
	get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice);

	if(choice) {
		c->options |= OPTION_CLAMP_MSS;
	}

	if(!get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight)) {
		get_config_int(lookup_config(config_tree, "Weight"), &c->estimated_weight);
	}

	return send_request(c, "%d %s %d %x", ACK, myport, c->estimated_weight, (c->options & 0xffffff) | (experimental ? (PROT_MINOR << 24) : 0));
}

static void send_everything(connection_t *c) {
	/* Send all known subnets and edges */

	/* disablebuggypeers workaround removed - QUIC only mode */

	if(tunnelserver) {
		for splay_each(subnet_t, s, myself->subnet_tree) {
			send_add_subnet(c, s);
		}

		return;
	}

	for splay_each(node_t, n, node_tree) {
		for splay_each(subnet_t, s, n->subnet_tree) {
			send_add_subnet(c, s);
		}

		for splay_each(edge_t, e, n->edge_tree) {
			send_add_edge(c, e);
		}
	}
}

/* Legacy ECDSA upgrade removed - QUIC only mode */

bool ack_h(connection_t *c, const char *request) {
	/* Protocol upgrade to ECDSA removed - QUIC uses TLS 1.3 */

	char hisport[MAX_STRING_SIZE];
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name,
		       c->hostname);
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			/* Check if this is actually the same connection */
			if(n->connection == c) {
				/* Same connection, not a second one - just update node pointer */
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "ACK received on existing connection with %s (%s)", c->name, c->hostname);
			} else {
				/* Oh dear, we already have a connection to this node. */
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Established a second connection with %s (%s), closing old connection", n->connection->name, n->connection->hostname);

				/* Tie-breaker: when both sides connect simultaneously, use name comparison */
				/* This ensures both sides make the same decision about which connection to keep */
				bool old_outgoing = n->connection->outgoing != NULL;
				bool new_outgoing = c->outgoing != NULL;

				/* If both are outgoing OR both are incoming, we have a race condition */
				if((old_outgoing && new_outgoing) || (!old_outgoing && !new_outgoing)) {
					logger(DEBUG_CONNECTIONS, LOG_INFO, "Simultaneous connections detected (old=%s, new=%s)",
					       old_outgoing ? "outgoing" : "incoming", new_outgoing ? "outgoing" : "incoming");

					/* Compare names: keep connection FROM node with smaller name */
					if(strcmp(c->name, myself->name) < 0) {
						/* Keep new connection (from node with smaller name) */
						logger(DEBUG_CONNECTIONS, LOG_INFO, "Keeping new connection from %s (smaller name)", c->name);
						if(old_outgoing) {
							c->outgoing = n->connection->outgoing;
							n->connection->outgoing = NULL;
						}
						terminate_connection(n->connection, false);
						graph();
					} else {
						/* Keep old connection (we have smaller name, so we're the source) */
						logger(DEBUG_CONNECTIONS, LOG_INFO, "Keeping old connection to %s (our name %s is smaller)", c->name, myself->name);
						terminate_connection(c, false);
						return true;
					}
				} else if(old_outgoing && !new_outgoing) {
					/* Old is outgoing, new is incoming - this is the simultaneous outgoing case */
					/* Use name comparison to decide which side keeps their outgoing connection */
					if(strcmp(c->name, myself->name) < 0) {
						/* Peer has smaller name, peer should keep their outgoing (which is our incoming) */
						/* Close our outgoing, accept their incoming */
						logger(DEBUG_CONNECTIONS, LOG_INFO, "Peer %s has smaller name, replacing our outgoing with their incoming", c->name);
						c->outgoing = n->connection->outgoing;
						n->connection->outgoing = NULL;
						terminate_connection(n->connection, false);
						graph();
					} else {
						/* We have smaller name, we should keep our outgoing */
						/* Reject their incoming */
						logger(DEBUG_CONNECTIONS, LOG_INFO, "We have smaller name (%s < %s), keeping our outgoing, rejecting incoming", myself->name, c->name);
						terminate_connection(c, false);
						return true;
					}
				} else {
					/* Old is incoming, new is outgoing - replace with new */
					logger(DEBUG_CONNECTIONS, LOG_INFO, "Replacing old incoming with new outgoing connection");
					c->outgoing = n->connection->outgoing;
					terminate_connection(n->connection, false);
					graph();
				}
			}
		}
	}

	n->connection = c;
	c->node = n;

	if(!(c->options & options & OPTION_PMTU_DISCOVERY)) {
		c->options &= ~OPTION_PMTU_DISCOVERY;
		options &= ~OPTION_PMTU_DISCOVERY;
	}

	c->options |= options;

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_int(lookup_config(config_tree, "PMTU"), &mtu) && mtu < n->mtu) {
		n->mtu = mtu;
	}

	if(get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice)) {
		if(choice) {
			c->options |= OPTION_CLAMP_MSS;
		} else {
			c->options &= ~OPTION_CLAMP_MSS;
		}
	}

	/* Activate this connection */

	c->allow_request = ALL;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection with %s (%s) activated", c->name,
	       c->hostname);

	/* Send him everything we know */

	send_everything(c);

	/* Create an edge_t for this connection */

	c->edge = new_edge();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddrcpy(&c->edge->address, &c->address);
	sockaddr_setport(&c->edge->address, hisport);
	sockaddr_t local_sa;
	socklen_t local_salen = sizeof(local_sa);

	/* For QUIC connections, use the stored local_address; for TCP, use getsockname() */
	if(c->quic_context) {
		/* QUIC connection - use stored local address */
		local_sa = c->local_address;
		sockaddr_setport(&local_sa, myport);
		c->edge->local_address = local_sa;
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Using QUIC local address for edge with %s", c->name);
	} else if(getsockname(c->socket, &local_sa.sa, &local_salen) < 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not get local socket address for connection with %s", c->name);
	} else {
		sockaddr_setport(&local_sa, myport);
		c->edge->local_address = local_sa;
	}

	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	/* Notify everyone of the new edge */

	if(tunnelserver) {
		send_add_edge(c, c->edge);
	} else {
		send_add_edge(everyone, c->edge);
	}

	/* Run MST and SSSP algorithms */

	graph();

	return true;
}
