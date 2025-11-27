/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2021 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
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

#include "cert_autogen.h"
#include "conf.h"
#include "connection.h"
#include "control.h"
#include "device.h"
#include "graph.h"
#include "ifconfig_auto.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "quic.h"
#include "padding.h"
#include "route.h"
#include "script.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"
#include "hosts_json.h"

#ifdef HAVE_MINIUPNPC
#include "upnp.h"
#endif

char *myport;
static io_t device_io;
devops_t devops;
bool device_standby = false;

char *proxyhost;
char *proxyport;
char *proxyuser;
char *proxypass;
proxytype_t proxytype;
bool autoconnect;
bool disablebuggypeers;

char *scriptinterpreter;
char *scriptextension;

tmode_t transport_mode = TMODE_LEGACY;

/* Legacy ECDSA/RSA/invitation key reading removed - QUIC only mode */

/* Legacy key expiration removed - QUIC only mode */
void regenerate_key(void) {
	/* In QUIC mode, TLS 1.3 handles key rotation */
	logger(DEBUG_STATUS, LOG_INFO, "regenerate_key called - no-op in QUIC mode");
}

/*
 * Callback for loading nodes from hosts.json
 */
static bool load_node_from_json(host_entry_t *host, void *ctx) {
	(void)ctx;

	if(!host->name[0]) return true;

	node_t *n = lookup_node(host->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(host->name);
		node_add(n);
	}

	/* Add subnet if configured */
	if(host->subnet[0]) {
		subnet_t *s = xzalloc(sizeof(subnet_t));
		if(str2net(s, host->subnet)) {
			subnet_t *s2 = lookup_subnet(n, s);
			if(s2) {
				s2->expires = -1;
				free(s);
			} else {
				subnet_add(n, s);
			}
		} else {
			free(s);
		}
	}

	/* Mark as having address if addresses configured */
	if(host->address_count > 0) {
		n->status.has_address = true;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Loaded node %s from hosts.json (vpn=%s, addrs=%d)",
	       host->name, host->vpn_address, host->address_count);

	return true;
}

void load_all_nodes(void) {
	/* Initialize hosts database if not already done */
	if(!hosts_db) {
		if(!hosts_db_init(confbase)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize hosts database");
			return;
		}
	}

	/* Load all nodes from hosts.json */
	hosts_db_foreach(load_node_from_json, NULL);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Loaded %d nodes from hosts.json", hosts_db_count());
}

char *get_name(void) {
	char *name = NULL;
	char *returned_name;

	get_config_string(lookup_config(config_tree, "Name"), &name);

	if(!name) {
		return NULL;
	}

	returned_name = replace_name(name);
	free(name);
	return returned_name;
}

bool setup_myself_reloadable(void) {
	char *proxy = NULL;
	char *rmode = NULL;
	char *fmode = NULL;
	char *bmode = NULL;
	char *afname = NULL;
	char *space;
	bool choice;

	free(scriptinterpreter);
	scriptinterpreter = NULL;
	get_config_string(lookup_config(config_tree, "ScriptsInterpreter"), &scriptinterpreter);


	free(scriptextension);

	if(!get_config_string(lookup_config(config_tree, "ScriptsExtension"), &scriptextension)) {
		scriptextension = xstrdup("");
	}

	get_config_string(lookup_config(config_tree, "Proxy"), &proxy);

	if(proxy) {
		if((space = strchr(proxy, ' '))) {
			*space++ = 0;
		}

		if(!strcasecmp(proxy, "none")) {
			proxytype = PROXY_NONE;
		} else if(!strcasecmp(proxy, "socks4")) {
			proxytype = PROXY_SOCKS4;
		} else if(!strcasecmp(proxy, "socks4a")) {
			proxytype = PROXY_SOCKS4A;
		} else if(!strcasecmp(proxy, "socks5")) {
			proxytype = PROXY_SOCKS5;
		} else if(!strcasecmp(proxy, "http")) {
			proxytype = PROXY_HTTP;
		} else if(!strcasecmp(proxy, "exec")) {
			proxytype = PROXY_EXEC;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type %s!", proxy);
			return false;
		}

		switch(proxytype) {
		case PROXY_NONE:
		default:
			break;

		case PROXY_EXEC:
			if(!space || !*space) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Argument expected for proxy type exec!");
				return false;
			}

			proxyhost =  xstrdup(space);
			break;

		case PROXY_SOCKS4:
		case PROXY_SOCKS4A:
		case PROXY_SOCKS5:
		case PROXY_HTTP:
			proxyhost = space;

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyport = space;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxyuser = space;
			}

			if(space && (space = strchr(space, ' '))) {
				*space++ = 0, proxypass = space;
			}

			if(!proxyhost || !*proxyhost || !proxyport || !*proxyport) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Host and port argument expected for proxy!");
				return false;
			}

			proxyhost = xstrdup(proxyhost);
			proxyport = xstrdup(proxyport);

			if(proxyuser && *proxyuser) {
				proxyuser = xstrdup(proxyuser);
			}

			if(proxypass && *proxypass) {
				proxypass = xstrdup(proxypass);
			}

			break;
		}

		free(proxy);
	}

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice) {
		myself->options |= OPTION_INDIRECT;
	}

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice) {
		myself->options |= OPTION_TCPONLY;
	}

	if(myself->options & OPTION_TCPONLY) {
		myself->options |= OPTION_INDIRECT;
	}

	get_config_bool(lookup_config(config_tree, "UDPDiscovery"), &udp_discovery);
	get_config_int(lookup_config(config_tree, "UDPDiscoveryKeepaliveInterval"), &udp_discovery_keepalive_interval);
	get_config_int(lookup_config(config_tree, "UDPDiscoveryInterval"), &udp_discovery_interval);
	get_config_int(lookup_config(config_tree, "UDPDiscoveryTimeout"), &udp_discovery_timeout);

	get_config_int(lookup_config(config_tree, "MTUInfoInterval"), &mtu_info_interval);
	get_config_int(lookup_config(config_tree, "UDPInfoInterval"), &udp_info_interval);

	get_config_bool(lookup_config(config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(config_tree, "LocalDiscovery"), &localdiscovery);

	if(get_config_string(lookup_config(config_tree, "Mode"), &rmode)) {
		if(!strcasecmp(rmode, "router")) {
			routing_mode = RMODE_ROUTER;
		} else if(!strcasecmp(rmode, "switch")) {
			routing_mode = RMODE_SWITCH;
		} else if(!strcasecmp(rmode, "hub")) {
			routing_mode = RMODE_HUB;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid routing mode!");
			return false;
		}

		free(rmode);
	}

	char *tmode = NULL;
	if(get_config_string(lookup_config(config_tree, "TransportMode"), &tmode)) {
		if(!strcasecmp(tmode, "legacy")) {
			transport_mode = TMODE_LEGACY;
		} else if(!strcasecmp(tmode, "quic")) {
#ifdef HAVE_MSQUIC
			transport_mode = TMODE_QUIC;
			logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC transport mode enabled");
#else
			logger(DEBUG_ALWAYS, LOG_ERR, "QUIC transport mode requested but not compiled with MsQuic support!");
			free(tmode);
			return false;
#endif
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid transport mode!");
			free(tmode);
			return false;
		}

		free(tmode);
	}

	if(get_config_string(lookup_config(config_tree, "Forwarding"), &fmode)) {
		if(!strcasecmp(fmode, "off")) {
			forwarding_mode = FMODE_OFF;
		} else if(!strcasecmp(fmode, "internal")) {
			forwarding_mode = FMODE_INTERNAL;
		} else if(!strcasecmp(fmode, "kernel")) {
			forwarding_mode = FMODE_KERNEL;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid forwarding mode!");
			return false;
		}

		free(fmode);
	}

	choice = !(myself->options & OPTION_TCPONLY);
	get_config_bool(lookup_config(config_tree, "PMTUDiscovery"), &choice);

	if(choice) {
		myself->options |= OPTION_PMTU_DISCOVERY;
	}

	choice = true;
	get_config_bool(lookup_config(config_tree, "ClampMSS"), &choice);

	if(choice) {
		myself->options |= OPTION_CLAMP_MSS;
	}

	get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);
	get_config_bool(lookup_config(config_tree, "DecrementTTL"), &decrement_ttl);

	if(get_config_string(lookup_config(config_tree, "Broadcast"), &bmode)) {
		if(!strcasecmp(bmode, "no")) {
			broadcast_mode = BMODE_NONE;
		} else if(!strcasecmp(bmode, "yes") || !strcasecmp(bmode, "mst")) {
			broadcast_mode = BMODE_MST;
		} else if(!strcasecmp(bmode, "direct")) {
			broadcast_mode = BMODE_DIRECT;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid broadcast mode!");
			return false;
		}

		free(bmode);
	}

	const char *const DEFAULT_BROADCAST_SUBNETS[] = { "ff:ff:ff:ff:ff:ff", "255.255.255.255", "224.0.0.0/4", "ff00::/8" };

	for(size_t i = 0; i < sizeof(DEFAULT_BROADCAST_SUBNETS) / sizeof(*DEFAULT_BROADCAST_SUBNETS); i++) {
		subnet_t *s = new_subnet();

		if(!str2net(s, DEFAULT_BROADCAST_SUBNETS[i])) {
			abort();
		}

		subnet_add(NULL, s);
	}

	for(config_t *cfg = lookup_config(config_tree, "BroadcastSubnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		subnet_t *s;

		if(!get_config_subnet(cfg, &s)) {
			continue;
		}

		subnet_add(NULL, s);
	}

#if !defined(IP_TOS)

	if(priorityinheritance) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform for IPv4 connections", "PriorityInheritance");
	}

#endif

#if !defined(IPV6_TCLASS)

	if(priorityinheritance) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform for IPv6 connections", "PriorityInheritance");
	}

#endif

	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire)) {
		macexpire = 600;
	}

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus maximum timeout!");
			return false;
		}
	} else {
		maxtimeout = 900;
	}

	if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4")) {
			addressfamily = AF_INET;
		} else if(!strcasecmp(afname, "IPv6")) {
			addressfamily = AF_INET6;
		} else if(!strcasecmp(afname, "any")) {
			addressfamily = AF_UNSPEC;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid address family!");
			return false;
		}

		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime)) {
		keylifetime = 3600;
	}

	if(!get_config_bool(lookup_config(config_tree, "AutoConnect"), &autoconnect)) {
		autoconnect = true;
	}

	get_config_bool(lookup_config(config_tree, "DisableBuggyPeers"), &disablebuggypeers);

	if(!get_config_int(lookup_config(config_tree, "InvitationExpire"), &invitation_lifetime)) {
		invitation_lifetime = 604800;        // 1 week
	}

	/* read_invitation_key() removed - QUIC only mode */

	return true;
}

/*
  Add listening sockets.
*/
static bool add_listen_address(char *address, bool bindto) {
	char *port = myport;

	if(address) {
		char *space = strchr(address, ' ');

		if(space) {
			*space++ = 0;
			port = space;
		}

		if(!strcmp(address, "*")) {
			*address = 0;
		}
	}

	struct addrinfo *ai, hint = {0};

	hint.ai_family = addressfamily;

	hint.ai_socktype = SOCK_STREAM;

	hint.ai_protocol = IPPROTO_TCP;

	hint.ai_flags = AI_PASSIVE;

#if HAVE_DECL_RES_INIT
	res_init();

#endif
	int err = getaddrinfo(address && *address ? address : NULL, port, &hint, &ai);

	free(address);

	if(err || !ai) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "getaddrinfo", err == EAI_SYSTEM ? strerror(err) : gai_strerror(err));
		return false;
	}

	/* Skip traditional listener setup if using QUIC transport mode */
	if(transport_mode != TMODE_QUIC) {
		for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
			// Ignore duplicate addresses
			bool found = false;

			for(int i = 0; i < listen_sockets; i++)
				if(!memcmp(&listen_socket[i].sa, aip->ai_addr, aip->ai_addrlen)) {
					found = true;
					break;
				}

			if(found) {
				continue;
			}

			if(listen_sockets >= MAXSOCKETS) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
				freeaddrinfo(ai);
				return false;
			}

			int tcp_fd = setup_listen_socket((sockaddr_t *) aip->ai_addr);

			if(tcp_fd < 0) {
				continue;
			}

			int udp_fd = setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

			if(udp_fd < 0) {
				close(tcp_fd);
				continue;
			}

			io_add(&listen_socket[listen_sockets].tcp, handle_new_meta_connection, &listen_socket[listen_sockets], tcp_fd, IO_READ);
			io_add(&listen_socket[listen_sockets].udp, handle_incoming_vpn_data, &listen_socket[listen_sockets], udp_fd, IO_READ);

			if(debug_level >= DEBUG_CONNECTIONS) {
				char *hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			listen_socket[listen_sockets].bindto = bindto;
			memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
			listen_sockets++;
		}
	} else {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Skipping traditional TCP/UDP listeners (QUIC transport mode)");
	}

	freeaddrinfo(ai);
	return true;
}

void device_enable(void) {
	if(devops.enable) {
		devops.enable();
	}

	/* Auto-configure interface using VPNAddress from tinc.conf */
	if(!iface) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "No interface name available for configuration");
		return;
	}

	if(!ifconfig_auto_enabled) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No VPNAddress configured in tinc.conf - interface %s not configured", iface);
		logger(DEBUG_ALWAYS, LOG_ERR, "Add 'VPNAddress = <ip>/<prefix>' to tinc.conf");
		return;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Auto-configuring interface %s", iface);

	/* Bring up the interface */
	if(!ifconfig_auto_bring_up(iface)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to bring up interface %s", iface);
	}

	/* Configure IP addresses */
	if(!ifconfig_auto_configure_addresses(iface)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to configure addresses on %s", iface);
	}

	/* Add routes */
	ifconfig_auto_add_routes(iface);

	logger(DEBUG_ALWAYS, LOG_INFO, "Interface %s auto-configuration complete", iface);
}

void device_disable(void) {
	/* Remove auto-configured routes and addresses */
	if(ifconfig_auto_enabled && iface) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Removing auto-configuration from %s", iface);
		ifconfig_auto_remove_routes(iface);
		ifconfig_auto_remove_addresses(iface);
	}

	if(devops.disable) {
		devops.disable();
	}
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
static bool setup_myself(void) {
	char *name, *hostname, *type;
	char *address = NULL;
	bool port_specified = false;

	if(!(name = get_name())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	myname = xstrdup(name);
	myself = new_node();
	myself->connection = new_connection();
	myself->name = name;
	myself->connection->name = xstrdup(name);
	read_host_config(config_tree, name, true);

	/* Ensure QUIC certificates exist (auto-generate if missing) */
	if(!ensure_quic_certificates(confbase, name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to ensure QUIC certificates");
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Port"), &myport)) {
		myport = xstrdup("443");
	} else {
		port_specified = true;
	}

	myself->connection->options = 0;
	myself->connection->protocol_major = PROT_MAJOR;
	myself->connection->protocol_minor = PROT_MINOR;

	myself->options |= PROT_MINOR << 24;

	/* In QUIC mode, TLS certificates (quic-cert.pem/quic-key.pem) are used instead */
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Using QUIC TLS 1.3 certificates for encryption");
	experimental = true;

	/* Ensure myport is numeric */

	if(!atoi(myport)) {
		struct addrinfo *ai = str2addrinfo("localhost", myport, SOCK_DGRAM);
		sockaddr_t sa;

		if(!ai || !ai->ai_addr) {
			return false;
		}

		free(myport);
		memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		sockaddr2str(&sa, NULL, &myport);
	}

	/* Read in all the subnets specified in the host configuration file */

	for(config_t *cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		subnet_t *subnet;

		if(!get_config_subnet(cfg, &subnet)) {
			return false;
		}

		subnet_add(myself, subnet);
	}

	/* Check some options */

	if(!setup_myself_reloadable()) {
		return false;
	}

	get_config_bool(lookup_config(config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);
	strictsubnets |= tunnelserver;

	if(get_config_int(lookup_config(config_tree, "MaxConnectionBurst"), &max_connection_burst)) {
		if(max_connection_burst <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "MaxConnectionBurst cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPRcvBuf"), &udp_rcvbuf)) {
		if(udp_rcvbuf < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPRcvBuf cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPSndBuf"), &udp_sndbuf)) {
		if(udp_sndbuf < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPSndBuf cannot be negative!");
			return false;
		}
	}

	get_config_int(lookup_config(config_tree, "FWMark"), &fwmark);
#ifndef SO_MARK

	if(fwmark) {
		logger(DEBUG_ALWAYS, LOG_ERR, "FWMark not supported on this platform!");
		return false;
	}

#endif

	/* Legacy replay window removed - QUIC only mode */
	int replaywin_int;

	if(get_config_int(lookup_config(config_tree, "ReplayWindow"), &replaywin_int)) {
		if(replaywin_int < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "ReplayWindow cannot be negative!");
			return false;
		}

		replaywin = (unsigned)replaywin_int;
		/* sptps_replaywin removed - not used in QUIC mode */
	}

	/* Legacy cipher/digest/key expiration removed - QUIC uses TLS 1.3 */

	/* Compression */

	if(get_config_int(lookup_config(config_tree, "Compression"), &myself->incompression)) {
		if(myself->incompression < 0 || myself->incompression > 11) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			return false;
		}
	} else {
		myself->incompression = 0;
	}

	/* myself->connection->outcompression removed - QUIC only mode */

	/* Done */

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	myself->last_state_change = now.tv_sec;
	/* myself->status.sptps removed - QUIC only mode */
	node_add(myself);

	graph();

	load_all_nodes();

	/* Load VPNAddress and Route configuration for auto-configuration */
	ifconfig_auto_load_config();

	/* Open device */

	devops = os_devops;

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "dummy")) {
			devops = dummy_devops;
		} else if(!strcasecmp(type, "raw_socket")) {
			devops = raw_socket_devops;
		} else if(!strcasecmp(type, "multicast")) {
			devops = multicast_devops;
		}

#ifdef HAVE_SYS_UN_H
		else if(!strcasecmp(type, "fd")) {
			devops = fd_devops;
		}

#endif
#ifdef ENABLE_UML
		else if(!strcasecmp(type, "uml")) {
			devops = uml_devops;
		}

#endif
#ifdef ENABLE_VDE
		else if(!strcasecmp(type, "vde")) {
			devops = vde_devops;
		}

#endif
		free(type);
	}

	get_config_bool(lookup_config(config_tree, "DeviceStandby"), &device_standby);

	if(!devops.setup()) {
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Device setup complete, device_fd=%d", device_fd);

	/* Apply MTU setting from config to the interface */
	int config_mtu = 0;
	if(get_config_int(lookup_config(config_tree, "MTU"), &config_mtu) && config_mtu > 0) {
		if(iface) {
			int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
			if(sock_fd >= 0) {
				struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
				strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
				ifr.ifr_mtu = config_mtu;

				if(ioctl(sock_fd, SIOCSIFMTU, &ifr) < 0) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Could not set MTU on %s to %d: %s",
					       iface, config_mtu, strerror(errno));
				} else {
					logger(DEBUG_ALWAYS, LOG_INFO, "Set MTU on %s to %d", iface, config_mtu);
				}
				close(sock_fd);
			} else {
				logger(DEBUG_ALWAYS, LOG_WARNING, "Could not create socket to set MTU: %s", strerror(errno));
			}
		}
	}

	if(device_fd >= 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Registering device_fd=%d in event loop", device_fd);
		io_add(&device_io, handle_device_data, NULL, device_fd, IO_READ);
	} else {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Device fd is invalid (%d), NOT registering in event loop!", device_fd);
	}

	/* Open sockets */

	if(!do_detach && getenv("LISTEN_FDS")) {
		sockaddr_t sa;
		socklen_t salen;

		listen_sockets = atoi(getenv("LISTEN_FDS"));
#ifdef HAVE_UNSETENV
		unsetenv("LISTEN_FDS");
#endif

		if(listen_sockets > MAXSOCKETS) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			return false;
		}

		for(int i = 0; i < listen_sockets; i++) {
			salen = sizeof(sa);

			if(getsockname(i + 3, &sa.sa, &salen) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get address of listen fd %d: %s", i + 3, sockstrerror(sockerrno));
				return false;
			}

#ifdef FD_CLOEXEC
			fcntl(i + 3, F_SETFD, FD_CLOEXEC);
#endif

			int udp_fd = setup_vpn_in_socket(&sa);

			if(udp_fd < 0) {
				return false;
			}

			io_add(&listen_socket[i].tcp, (io_cb_t)handle_new_meta_connection, &listen_socket[i], i + 3, IO_READ);
			io_add(&listen_socket[i].udp, (io_cb_t)handle_incoming_vpn_data, &listen_socket[i], udp_fd, IO_READ);

			if(debug_level >= DEBUG_CONNECTIONS) {
				hostname = sockaddr2hostname(&sa);
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			memcpy(&listen_socket[i].sa, &sa, salen);
		}
	} else {
		listen_sockets = 0;
		int cfgs = 0;

		for(config_t *cfg = lookup_config(config_tree, "BindToAddress"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);

			if(!add_listen_address(address, true)) {
				return false;
			}
		}

		for(config_t *cfg = lookup_config(config_tree, "ListenAddress"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			cfgs++;
			get_config_string(cfg, &address);

			if(!add_listen_address(address, false)) {
				return false;
			}
		}

		if(!cfgs)
			if(!add_listen_address(address, NULL)) {
				return false;
			}
	}

	/* Skip this check for QUIC mode - QUIC listener is created later in setup_network() */
	if(!listen_sockets && transport_mode != TMODE_QUIC) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	/* If no Port option was specified, set myport to the port used by the first listening socket. */

	if((!port_specified || atoi(myport) == 0) && transport_mode != TMODE_QUIC) {
		sockaddr_t sa;
		socklen_t salen = sizeof(sa);

		if(!getsockname(listen_socket[0].udp.fd, &sa.sa, &salen)) {
			free(myport);
			sockaddr2str(&sa, NULL, &myport);

			if(!myport) {
				myport = xstrdup("443");
			}
		}
	}

	/* For QUIC mode, ensure myport is set to default if not specified */
	if(transport_mode == TMODE_QUIC && (!myport || atoi(myport) == 0)) {
		free(myport);
		myport = xstrdup("443");
	}

	xasprintf(&myself->hostname, "MYSELF port %s", myport);
	myself->connection->hostname = xstrdup(myself->hostname);

	char *upnp = NULL;
	get_config_string(lookup_config(config_tree, "UPnP"), &upnp);
	bool upnp_tcp = false;
	bool upnp_udp = false;

	if(upnp) {
		if(!strcasecmp(upnp, "yes")) {
			upnp_tcp = upnp_udp = true;
		} else if(!strcasecmp(upnp, "udponly")) {
			upnp_udp = true;
		}

		free(upnp);
	}

	if(upnp_tcp || upnp_udp) {
#ifdef HAVE_MINIUPNPC
		upnp_init(upnp_tcp, upnp_udp);
#else
		logger(DEBUG_ALWAYS, LOG_WARNING, "UPnP was requested, but tinc isn't built with miniupnpc support!");
#endif
	}

	/* Done. */

	last_config_check = now.tv_sec;

	return true;
}

/*
  initialize network
*/
bool setup_network(void) {
	init_connections();
	init_subnets();
	init_nodes();
	init_edges();
	init_requests();

	if(get_config_int(lookup_config(config_tree, "PingInterval"), &pinginterval)) {
		if(pinginterval < 1) {
			pinginterval = 86400;
		}
	} else {
		pinginterval = 60;
	}

	if(!get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout)) {
		pingtimeout = 5;
	}

	if(pingtimeout < 1 || pingtimeout > pinginterval) {
		pingtimeout = pinginterval;
	}

	if(!get_config_int(lookup_config(config_tree, "MaxOutputBufferSize"), &maxoutbufsize)) {
		maxoutbufsize = 10 * MTU;
	}

	if(!setup_myself()) {
		return false;
	}

#ifdef HAVE_MSQUIC
	/* Initialize QUIC only if QUIC transport mode is enabled */
	if(transport_mode == TMODE_QUIC) {
		/* Read QUIC configuration parameters */
		if(!get_config_int(lookup_config(config_tree, "QUICJitterMaxUs"), &quic_jitter_max_us)) {
			quic_jitter_max_us = 1000;  /* Default: 1ms (1000 microseconds) */
		}

		/* Validate jitter value */
		if(quic_jitter_max_us < 0) {
			quic_jitter_max_us = 0;  /* Disable jitter if negative */
		} else if(quic_jitter_max_us > 50000) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICJitterMaxUs too large (%d), capping at 50ms", quic_jitter_max_us);
			quic_jitter_max_us = 50000;  /* Cap at 50ms */
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC timing jitter configured: %d microseconds (%.1f ms)",
		       quic_jitter_max_us, quic_jitter_max_us / 1000.0);

		/* Read QUIC SNI domain pool configuration */
		char *sni_domains_str = NULL;

		if(get_config_string(lookup_config(config_tree, "QUICSNIDomains"), &sni_domains_str)) {
			/* Parse comma-separated domain list */
			int domain_count = 1;  /* At least one domain */

			/* Count commas to determine number of domains */
			for(char *p = sni_domains_str; *p; p++) {
				if(*p == ',') {
					domain_count++;
				}
			}

			/* Allocate array for domain pointers */
			sni_domain_pool = xmalloc(domain_count * sizeof(char *));
			sni_pool_size = 0;

			/* Parse domains */
			char *token = strtok(sni_domains_str, ",");

			while(token && sni_pool_size < domain_count) {
				/* Trim leading/trailing whitespace */
				while(*token == ' ' || *token == '\t') {
					token++;
				}

				char *end = token + strlen(token) - 1;

				while(end > token && (*end == ' ' || *end == '\t')) {
					*end = '\0';
					end--;
				}

				if(*token) {  /* Non-empty domain */
					sni_domain_pool[sni_pool_size] = xstrdup(token);
					sni_pool_size++;
				}

				token = strtok(NULL, ",");
			}

			free(sni_domains_str);

			if(sni_pool_size > 0) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC SNI domain pool configured with %d domain(s):", sni_pool_size);

				for(int i = 0; i < sni_pool_size; i++) {
					logger(DEBUG_CONNECTIONS, LOG_INFO, "  %d: %s", i + 1, sni_domain_pool[i]);
				}
			} else {
				logger(DEBUG_ALWAYS, LOG_WARNING, "QUICSNIDomains specified but no valid domains found, using defaults");
				free(sni_domain_pool);
				sni_domain_pool = NULL;
				sni_pool_size = 0;
			}
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Using default QUIC SNI domain pool (12 domains)");
		}

		/* Read QUIC Connection Multiplexing configuration */
		if(!get_config_int(lookup_config(config_tree, "QUICStreamCount"), &quic_stream_pool_size)) {
			quic_stream_pool_size = QUIC_STREAM_POOL_SIZE_DEFAULT;  /* Default: 6 streams */
		}

		/* Validate stream count */
		if(quic_stream_pool_size < 1) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICStreamCount too small (%d), using minimum: 1", quic_stream_pool_size);
			quic_stream_pool_size = 1;
		} else if(quic_stream_pool_size > QUIC_STREAM_POOL_SIZE_MAX) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICStreamCount too large (%d), capping at %d",
			       quic_stream_pool_size, QUIC_STREAM_POOL_SIZE_MAX);
			quic_stream_pool_size = QUIC_STREAM_POOL_SIZE_MAX;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC stream multiplexing: %d parallel streams", quic_stream_pool_size);

		/* Read keepalive configuration */
		if(!get_config_int(lookup_config(config_tree, "QUICKeepaliveMin"), &quic_keepalive_min_sec)) {
			quic_keepalive_min_sec = QUIC_KEEPALIVE_MIN_DEFAULT;  /* Default: 5 seconds */
		}

		if(!get_config_int(lookup_config(config_tree, "QUICKeepaliveMax"), &quic_keepalive_max_sec)) {
			quic_keepalive_max_sec = QUIC_KEEPALIVE_MAX_DEFAULT;  /* Default: 15 seconds */
		}

		/* Validate keepalive intervals */
		if(quic_keepalive_min_sec < 0) {
			quic_keepalive_min_sec = 0;  /* Disabled */
		}

		if(quic_keepalive_max_sec < quic_keepalive_min_sec) {
			quic_keepalive_max_sec = quic_keepalive_min_sec;
		}

		if(quic_keepalive_max_sec > 60) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICKeepaliveMax too large (%d), capping at 60 seconds",
			       quic_keepalive_max_sec);
			quic_keepalive_max_sec = 60;
		}

		if(quic_keepalive_min_sec == 0 || quic_keepalive_max_sec == 0) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC keepalive: disabled");
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC keepalive interval: %d-%d seconds",
			       quic_keepalive_min_sec, quic_keepalive_max_sec);
		}

		/* Read keepalive packet size */
		if(!get_config_int(lookup_config(config_tree, "QUICKeepaliveSize"), &quic_keepalive_size)) {
			quic_keepalive_size = QUIC_KEEPALIVE_SIZE_DEFAULT;  /* Default: 64 bytes */
		}

		/* Validate keepalive size */
		if(quic_keepalive_size < 16) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICKeepaliveSize too small (%d), using minimum: 16 bytes",
			       quic_keepalive_size);
			quic_keepalive_size = 16;
		} else if(quic_keepalive_size > QUIC_KEEPALIVE_SIZE_MAX) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "QUICKeepaliveSize too large (%d), capping at %d bytes",
			       quic_keepalive_size, QUIC_KEEPALIVE_SIZE_MAX);
			quic_keepalive_size = QUIC_KEEPALIVE_SIZE_MAX;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC keepalive packet size: %d bytes", quic_keepalive_size);

		/* Read HTTP/3 masquerading configuration */
		if(get_config_bool(lookup_config(config_tree, "QUICHTTP3Masquerading"), &quic_http3_masquerading)) {
			if(quic_http3_masquerading) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC HTTP/3 masquerading: ENABLED");
				logger(DEBUG_CONNECTIONS, LOG_INFO, "  Traffic will be wrapped in HTTP/3 frames");
				logger(DEBUG_CONNECTIONS, LOG_INFO, "  Mimics browser behavior (GET/POST requests)");
			} else {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC HTTP/3 masquerading: disabled");
			}
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC HTTP/3 masquerading: disabled (default)");
		}

		/* Read trust public certificates configuration (for Let's Encrypt/DPI evasion) */
		extern bool quic_trust_public_certs;
		if(get_config_bool(lookup_config(config_tree, "QUICTrustPublicCerts"), &quic_trust_public_certs)) {
			if(quic_trust_public_certs) {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC Trust Public Certs: ENABLED");
				logger(DEBUG_CONNECTIONS, LOG_INFO, "  Will accept Let's Encrypt and other public CA certificates");
				logger(DEBUG_CONNECTIONS, LOG_INFO, "  Use for DPI evasion with real domain certificates");
			} else {
				logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC Trust Public Certs: disabled");
			}
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC Trust Public Certs: disabled (default - require CA/self-signed)");
		}

		/* Read HTTP/3 HEADERS interval configuration */
		extern int quic_http3_headers_interval;
		if(get_config_int(lookup_config(config_tree, "HTTP3HeadersInterval"), &quic_http3_headers_interval)) {
			if(quic_http3_headers_interval < 10) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "HTTP3HeadersInterval too low (%d), setting to 10 seconds", quic_http3_headers_interval);
				quic_http3_headers_interval = 10;
			}
			logger(DEBUG_CONNECTIONS, LOG_INFO, "HTTP/3 HEADERS interval: %d seconds", quic_http3_headers_interval);
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "HTTP/3 HEADERS interval: %d seconds (default)", quic_http3_headers_interval);
		}

		/* Read packet padding configuration */
		char *padding_mode_str = NULL;
		if(get_config_string(lookup_config(config_tree, "QUICPaddingMode"), &padding_mode_str)) {
			if(strcasecmp(padding_mode_str, "off") == 0) {
				padding_config.mode = PADDING_OFF;
				logger(DEBUG_CONNECTIONS, LOG_INFO, "Packet padding: disabled");
			} else if(strcasecmp(padding_mode_str, "random") == 0) {
				padding_config.mode = PADDING_RANDOM;
				logger(DEBUG_CONNECTIONS, LOG_INFO, "Packet padding: random mode");
			} else if(strcasecmp(padding_mode_str, "buckets") == 0) {
				padding_config.mode = PADDING_BUCKETS;
				logger(DEBUG_CONNECTIONS, LOG_INFO, "Packet padding: buckets mode");
			} else {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "Invalid QUICPaddingMode '%s', using 'off'", padding_mode_str);
				padding_config.mode = PADDING_OFF;
			}
			free(padding_mode_str);
		}

		if(get_config_int(lookup_config(config_tree, "QUICPaddingMin"), &padding_config.min_size)) {
			if(padding_config.min_size < 0) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUICPaddingMin cannot be negative, setting to 0");
				padding_config.min_size = 0;
			}
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Padding min size: %d bytes", padding_config.min_size);
		}

		if(get_config_int(lookup_config(config_tree, "QUICPaddingMax"), &padding_config.max_size)) {
			if(padding_config.max_size > MAX_PADDING_SIZE) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUICPaddingMax too large (%d), capping at %d",
				       padding_config.max_size, MAX_PADDING_SIZE);
				padding_config.max_size = MAX_PADDING_SIZE;
			}
			if(padding_config.max_size < padding_config.min_size) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUICPaddingMax < QUICPaddingMin, swapping values");
				int tmp = padding_config.max_size;
				padding_config.max_size = padding_config.min_size;
				padding_config.min_size = tmp;
			}
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Padding max size: %d bytes", padding_config.max_size);
		}

		if(get_config_bool(lookup_config(config_tree, "QUICPaddingSmallPacketsOnly"), &padding_config.small_packets_only)) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Padding small packets only: %s",
			       padding_config.small_packets_only ? "yes" : "no");
		}

		if(get_config_int(lookup_config(config_tree, "QUICPaddingThreshold"), &padding_config.threshold)) {
			if(padding_config.threshold < 0) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUICPaddingThreshold cannot be negative, setting to 512");
				padding_config.threshold = 512;
			}
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Padding threshold: %d bytes", padding_config.threshold);
		}

		/* Initialize padding (sets up default buckets if needed) */
		padding_init();

		uint16_t quic_port = 443; // Default tinc port
		char *portstr = myport;
		if(portstr) {
			quic_port = atoi(portstr);
		}

		if(!quic_init(quic_port)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC");
			return false;
		}

		if(!quic_start_listener(quic_port)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start QUIC listener");
			quic_cleanup();
			return false;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC transport layer initialized on port %d", quic_port);
	}
#endif

	if(!init_control()) {
		return false;
	}

	if(!device_standby) {
		device_enable();
	}

	/* Run subnet-up scripts for our own subnets */

	subnet_update(myself, NULL, true);

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(void) {
#ifdef HAVE_MSQUIC
	/* Cleanup QUIC */
	quic_cleanup();
	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC transport layer shut down");
#endif

	for(list_node_t *node = connection_list->head, *next; node; node = next) {
		next = node->next;
		connection_t *c = node->data;

		/* Keep control connections open until the end, so they know when we really terminated */
		if(c->status.control) {
			c->socket = -1;
		}

		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	if(outgoing_list) {
		list_delete_list(outgoing_list);
	}

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		connection_del(myself->connection);
	}

	for(int i = 0; i < listen_sockets; i++) {
		io_del(&listen_socket[i].tcp);
		io_del(&listen_socket[i].udp);
		close(listen_socket[i].tcp.fd);
		close(listen_socket[i].udp.fd);
	}

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();

	if(!device_standby) {
		device_disable();
	}

	free(myport);

	if(device_fd >= 0) {
		io_del(&device_io);
	}

	if(devops.close) {
		devops.close();
	}

	exit_control();

	free(scriptextension);
	free(scriptinterpreter);

	return;
}
