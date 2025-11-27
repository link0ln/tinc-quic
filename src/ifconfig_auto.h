/*
    ifconfig_auto.h -- Automatic interface configuration
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

#ifndef TINC_IFCONFIG_AUTO_H
#define TINC_IFCONFIG_AUTO_H

#include "system.h"
#include <stdbool.h>

/*
 * Configuration options in tinc.conf:
 *
 * VPNAddress = 10.0.0.1/24          # IPv4 address with CIDR prefix
 * VPNAddress = fd00::1/64           # IPv6 address with prefix (multiple allowed)
 *
 * Route = 192.168.100.0/24          # Route via VPN interface
 * Route = 10.10.0.0/16 via 10.0.0.254   # Route with explicit gateway
 * Route = 0.0.0.0/0                 # Default route via VPN interface
 */

/* Maximum number of addresses/routes supported */
#define MAX_VPN_ADDRESSES 16
#define MAX_VPN_ROUTES 64

/* Route entry structure */
typedef struct vpn_route_t {
	char *network;          /* Network address (e.g., "192.168.0.0/24") */
	char *gateway;          /* Optional gateway (NULL = use interface) */
	bool added;             /* True if route was successfully added */
} vpn_route_t;

/* Address entry structure */
typedef struct vpn_address_t {
	char *address;          /* Address with prefix (e.g., "10.0.0.1/24") */
	bool is_ipv6;           /* True if IPv6 address */
	bool added;             /* True if address was successfully added */
} vpn_address_t;

/* Global configuration loaded from tinc.conf */
extern vpn_address_t vpn_addresses[MAX_VPN_ADDRESSES];
extern int vpn_address_count;
extern vpn_route_t vpn_routes[MAX_VPN_ROUTES];
extern int vpn_route_count;
extern bool ifconfig_auto_enabled;

/*
 * Load VPNAddress and Route configuration from tinc.conf
 * Called during setup_myself() in net_setup.c
 */
extern bool ifconfig_auto_load_config(void);

/*
 * Configure IP addresses on the VPN interface
 * Called from device_enable() after interface is up
 * Returns true if at least one address was configured successfully
 */
extern bool ifconfig_auto_configure_addresses(const char *iface);

/*
 * Add routes via the VPN interface
 * Called after VPN connection is established
 * Returns true if all routes were added successfully
 */
extern bool ifconfig_auto_add_routes(const char *iface);

/*
 * Bring up the interface (set link up)
 * Called before configuring addresses
 */
extern bool ifconfig_auto_bring_up(const char *iface);

/*
 * Remove routes that were added
 * Called from device_disable() before shutting down
 */
extern void ifconfig_auto_remove_routes(const char *iface);

/*
 * Remove IP addresses from the interface
 * Called from device_disable()
 */
extern void ifconfig_auto_remove_addresses(const char *iface);

/*
 * Cleanup all allocated memory
 */
extern void ifconfig_auto_cleanup(void);

#endif /* TINC_IFCONFIG_AUTO_H */
