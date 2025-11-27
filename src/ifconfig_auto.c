/*
    ifconfig_auto.c -- Automatic interface configuration
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
#include "ifconfig_auto.h"
#include "conf.h"
#include "logger.h"
#include "xalloc.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Global configuration */
vpn_address_t vpn_addresses[MAX_VPN_ADDRESSES];
int vpn_address_count = 0;
vpn_route_t vpn_routes[MAX_VPN_ROUTES];
int vpn_route_count = 0;
bool ifconfig_auto_enabled = false;

/* Platform-specific command execution */
static int run_command(const char *cmd) {
	logger(DEBUG_ALWAYS, LOG_DEBUG, "Executing: %s", cmd);
	int result = system(cmd);
	if(result != 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Command failed (exit %d): %s", result, cmd);
	}
	return result;
}

/* Check if address looks like IPv6 */
static bool is_ipv6_address(const char *addr) {
	return strchr(addr, ':') != NULL;
}

/* Parse address and extract just the IP part (without prefix) */
static char *extract_ip(const char *addr_with_prefix) {
	char *result = xstrdup(addr_with_prefix);
	char *slash = strchr(result, '/');
	if(slash) {
		*slash = '\0';
	}
	return result;
}

/* Extract prefix length from CIDR notation, returns -1 if no prefix */
static int extract_prefix(const char *addr_with_prefix) {
	const char *slash = strchr(addr_with_prefix, '/');
	if(slash) {
		return atoi(slash + 1);
	}
	return -1;
}

/* Convert prefix length to netmask (IPv4 only) */
static void prefix_to_netmask(int prefix, char *netmask, size_t len) {
	if(prefix < 0 || prefix > 32) {
		snprintf(netmask, len, "255.255.255.255");
		return;
	}
	uint32_t mask = prefix ? (~0U << (32 - prefix)) : 0;
	snprintf(netmask, len, "%u.%u.%u.%u",
	         (mask >> 24) & 0xFF,
	         (mask >> 16) & 0xFF,
	         (mask >> 8) & 0xFF,
	         mask & 0xFF);
}

/*
 * Load VPNAddress and Route configuration from tinc.conf
 */
bool ifconfig_auto_load_config(void) {
	config_t *cfg;
	char *value;

	/* Reset counters */
	vpn_address_count = 0;
	vpn_route_count = 0;
	ifconfig_auto_enabled = false;

	/* Load VPNAddress entries */
	for(cfg = lookup_config(config_tree, "VPNAddress"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		if(vpn_address_count >= MAX_VPN_ADDRESSES) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Too many VPNAddress entries, maximum is %d", MAX_VPN_ADDRESSES);
			break;
		}

		if(!get_config_string(cfg, &value)) {
			continue;
		}

		vpn_addresses[vpn_address_count].address = xstrdup(value);
		vpn_addresses[vpn_address_count].is_ipv6 = is_ipv6_address(value);
		vpn_addresses[vpn_address_count].added = false;
		vpn_address_count++;
		ifconfig_auto_enabled = true;

		logger(DEBUG_ALWAYS, LOG_INFO, "VPN address configured: %s (%s)",
		       value, is_ipv6_address(value) ? "IPv6" : "IPv4");
	}

	/* Load Route entries */
	for(cfg = lookup_config(config_tree, "Route"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		if(vpn_route_count >= MAX_VPN_ROUTES) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Too many Route entries, maximum is %d", MAX_VPN_ROUTES);
			break;
		}

		if(!get_config_string(cfg, &value)) {
			continue;
		}

		/* Parse "network [via gateway]" format */
		char *via = strstr(value, " via ");
		if(via) {
			*via = '\0';
			vpn_routes[vpn_route_count].network = xstrdup(value);
			vpn_routes[vpn_route_count].gateway = xstrdup(via + 5);  /* Skip " via " */
			*via = ' ';  /* Restore for logging */
		} else {
			vpn_routes[vpn_route_count].network = xstrdup(value);
			vpn_routes[vpn_route_count].gateway = NULL;
		}
		vpn_routes[vpn_route_count].added = false;
		vpn_route_count++;

		logger(DEBUG_ALWAYS, LOG_INFO, "VPN route configured: %s%s%s",
		       vpn_routes[vpn_route_count - 1].network,
		       vpn_routes[vpn_route_count - 1].gateway ? " via " : "",
		       vpn_routes[vpn_route_count - 1].gateway ? vpn_routes[vpn_route_count - 1].gateway : "");
	}

	if(vpn_address_count > 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Interface auto-configuration enabled: %d addresses, %d routes",
		       vpn_address_count, vpn_route_count);
	}

	return true;
}

/*
 * Bring up the interface
 */
bool ifconfig_auto_bring_up(const char *iface) {
	if(!iface) {
		return false;
	}

	char cmd[512];

#ifdef _WIN32
	/* Windows: interface comes up automatically with netsh */
	snprintf(cmd, sizeof(cmd), "netsh interface set interface \"%s\" enable", iface);
#else
	/* Linux/Unix: use ip link set up */
	snprintf(cmd, sizeof(cmd), "ip link set dev %s up", iface);
#endif

	if(run_command(cmd) == 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Interface %s brought up", iface);
		return true;
	}

	return false;
}

/*
 * Configure IP addresses on the VPN interface
 */
bool ifconfig_auto_configure_addresses(const char *iface) {
	if(!iface || vpn_address_count == 0) {
		return false;
	}

	bool success = false;
	char cmd[512];

	for(int i = 0; i < vpn_address_count; i++) {
		vpn_address_t *addr = &vpn_addresses[i];
		char *ip = extract_ip(addr->address);
		int prefix = extract_prefix(addr->address);

#ifdef _WIN32
		/* Windows: use netsh */
		if(addr->is_ipv6) {
			snprintf(cmd, sizeof(cmd),
			         "netsh interface ipv6 add address \"%s\" %s/%d",
			         iface, ip, prefix > 0 ? prefix : 64);
		} else {
			char netmask[16];
			prefix_to_netmask(prefix > 0 ? prefix : 24, netmask, sizeof(netmask));
			snprintf(cmd, sizeof(cmd),
			         "netsh interface ip add address \"%s\" %s %s",
			         iface, ip, netmask);
		}
#else
		/* Linux/Unix: use ip addr add */
		snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", addr->address, iface);
#endif

		if(run_command(cmd) == 0) {
			addr->added = true;
			success = true;
			logger(DEBUG_ALWAYS, LOG_INFO, "Added address %s to %s", addr->address, iface);
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to add address %s to %s", addr->address, iface);
		}

		free(ip);
	}

	return success;
}

/*
 * Add routes via the VPN interface
 */
bool ifconfig_auto_add_routes(const char *iface) {
	if(!iface || vpn_route_count == 0) {
		return true;  /* No routes to add is not an error */
	}

	bool all_success = true;
	char cmd[512];

	for(int i = 0; i < vpn_route_count; i++) {
		vpn_route_t *route = &vpn_routes[i];
		bool is_ipv6 = is_ipv6_address(route->network);

#ifdef _WIN32
		/* Windows: use route add or netsh */
		char *ip = extract_ip(route->network);
		int prefix = extract_prefix(route->network);
		char netmask[16];

		if(is_ipv6) {
			if(route->gateway) {
				snprintf(cmd, sizeof(cmd),
				         "netsh interface ipv6 add route %s \"%s\" %s",
				         route->network, iface, route->gateway);
			} else {
				snprintf(cmd, sizeof(cmd),
				         "netsh interface ipv6 add route %s \"%s\"",
				         route->network, iface);
			}
		} else {
			prefix_to_netmask(prefix > 0 ? prefix : 24, netmask, sizeof(netmask));
			if(route->gateway) {
				snprintf(cmd, sizeof(cmd),
				         "route add %s mask %s %s",
				         ip, netmask, route->gateway);
			} else {
				/* For interface-only routes on Windows, we need the interface index */
				snprintf(cmd, sizeof(cmd),
				         "netsh interface ip add route %s \"%s\"",
				         route->network, iface);
			}
		}
		free(ip);
#else
		/* Linux/Unix: use ip route add */
		if(route->gateway) {
			snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s",
			         route->network, route->gateway, iface);
		} else {
			snprintf(cmd, sizeof(cmd), "ip route add %s dev %s",
			         route->network, iface);
		}
#endif

		if(run_command(cmd) == 0) {
			route->added = true;
			logger(DEBUG_ALWAYS, LOG_INFO, "Added route %s%s%s via %s",
			       route->network,
			       route->gateway ? " via " : "",
			       route->gateway ? route->gateway : "",
			       iface);
		} else {
			all_success = false;
			logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to add route %s", route->network);
		}
	}

	return all_success;
}

/*
 * Remove routes that were added
 */
void ifconfig_auto_remove_routes(const char *iface) {
	if(!iface) {
		return;
	}

	char cmd[512];

	for(int i = vpn_route_count - 1; i >= 0; i--) {
		vpn_route_t *route = &vpn_routes[i];

		if(!route->added) {
			continue;
		}

		bool is_ipv6 = is_ipv6_address(route->network);

#ifdef _WIN32
		char *ip = extract_ip(route->network);
		int prefix = extract_prefix(route->network);
		char netmask[16];

		if(is_ipv6) {
			snprintf(cmd, sizeof(cmd),
			         "netsh interface ipv6 delete route %s \"%s\"",
			         route->network, iface);
		} else {
			prefix_to_netmask(prefix > 0 ? prefix : 24, netmask, sizeof(netmask));
			if(route->gateway) {
				snprintf(cmd, sizeof(cmd), "route delete %s", ip);
			} else {
				snprintf(cmd, sizeof(cmd),
				         "netsh interface ip delete route %s \"%s\"",
				         route->network, iface);
			}
		}
		free(ip);
#else
		/* Linux/Unix: use ip route del */
		if(route->gateway) {
			snprintf(cmd, sizeof(cmd), "ip route del %s via %s dev %s",
			         route->network, route->gateway, iface);
		} else {
			snprintf(cmd, sizeof(cmd), "ip route del %s dev %s",
			         route->network, iface);
		}
#endif

		if(run_command(cmd) == 0) {
			route->added = false;
			logger(DEBUG_ALWAYS, LOG_INFO, "Removed route %s", route->network);
		}
	}
}

/*
 * Remove IP addresses from the interface
 */
void ifconfig_auto_remove_addresses(const char *iface) {
	if(!iface) {
		return;
	}

	char cmd[512];

	for(int i = vpn_address_count - 1; i >= 0; i--) {
		vpn_address_t *addr = &vpn_addresses[i];

		if(!addr->added) {
			continue;
		}

#ifdef _WIN32
		char *ip = extract_ip(addr->address);
		if(addr->is_ipv6) {
			snprintf(cmd, sizeof(cmd),
			         "netsh interface ipv6 delete address \"%s\" %s",
			         iface, ip);
		} else {
			snprintf(cmd, sizeof(cmd),
			         "netsh interface ip delete address \"%s\" %s",
			         iface, ip);
		}
		free(ip);
#else
		/* Linux/Unix: use ip addr del */
		snprintf(cmd, sizeof(cmd), "ip addr del %s dev %s", addr->address, iface);
#endif

		if(run_command(cmd) == 0) {
			addr->added = false;
			logger(DEBUG_ALWAYS, LOG_INFO, "Removed address %s from %s", addr->address, iface);
		}
	}
}

/*
 * Cleanup all allocated memory
 */
void ifconfig_auto_cleanup(void) {
	for(int i = 0; i < vpn_address_count; i++) {
		free(vpn_addresses[i].address);
		vpn_addresses[i].address = NULL;
	}
	vpn_address_count = 0;

	for(int i = 0; i < vpn_route_count; i++) {
		free(vpn_routes[i].network);
		free(vpn_routes[i].gateway);
		vpn_routes[i].network = NULL;
		vpn_routes[i].gateway = NULL;
	}
	vpn_route_count = 0;

	ifconfig_auto_enabled = false;
}
