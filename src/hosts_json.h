#ifndef TINC_HOSTS_JSON_H
#define TINC_HOSTS_JSON_H

/*
    hosts_json.h -- JSON-based host configuration
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

#include <stdbool.h>
#include <stdint.h>

/* Maximum values */
#define MAX_HOST_ADDRESSES 8
#define MAX_HOST_NAME_LEN 64
#define MAX_ADDRESS_LEN 128
#define MAX_SUBNET_LEN 64

/*
 * Host entry structure
 * Represents a single node in the VPN network
 */
typedef struct host_entry {
	char name[MAX_HOST_NAME_LEN];           /* Node name */
	char addresses[MAX_HOST_ADDRESSES][MAX_ADDRESS_LEN]; /* External addresses */
	int address_count;                       /* Number of addresses */
	uint16_t port;                           /* QUIC port (default 443) */
	char subnet[MAX_SUBNET_LEN];             /* Subnet owned by this node (e.g., "10.0.0.1/32") */
	char vpn_address[MAX_ADDRESS_LEN];       /* VPN IP address (e.g., "10.0.0.1") */
	bool is_online;                          /* Runtime: is node currently online */
	struct host_entry *next;                 /* Linked list pointer */
} host_entry_t;

/*
 * Hosts database structure
 * Contains all known hosts in the network
 */
typedef struct hosts_db {
	host_entry_t *hosts;                     /* Linked list of hosts */
	int count;                               /* Number of hosts */
	char filepath[256];                      /* Path to hosts.json */
	bool modified;                           /* Needs saving */
} hosts_db_t;

/*
 * Global hosts database (initialized in net_setup.c)
 */
extern hosts_db_t *hosts_db;

/*
 * Initialize hosts database
 * Creates empty database or loads from hosts.json if exists
 */
bool hosts_db_init(const char *confbase);

/*
 * Cleanup hosts database
 * Frees all memory, optionally saves if modified
 */
void hosts_db_cleanup(bool save);

/*
 * Load hosts from JSON file
 * Returns true on success or if file doesn't exist (empty DB)
 */
bool hosts_db_load(void);

/*
 * Save hosts to JSON file
 * Returns true on success
 */
bool hosts_db_save(void);

/*
 * Add or update a host entry
 * If host with same name exists, updates it
 * Returns pointer to host entry or NULL on error
 */
host_entry_t *hosts_db_add(const char *name);

/*
 * Find host by name
 * Returns pointer to host entry or NULL if not found
 */
host_entry_t *hosts_db_find(const char *name);

/*
 * Remove host by name
 * Returns true if host was found and removed
 */
bool hosts_db_remove(const char *name);

/*
 * Check if VPN address is already used
 * Returns name of host using this address, or NULL if free
 */
const char *hosts_db_find_by_vpn_address(const char *vpn_address);

/*
 * Check if external address is already used
 * Returns name of host using this address, or NULL if free
 */
const char *hosts_db_find_by_address(const char *address);

/*
 * Add address to host
 * Returns true on success
 */
bool host_add_address(host_entry_t *host, const char *address);

/*
 * Set host's VPN address and subnet
 */
void host_set_vpn_address(host_entry_t *host, const char *vpn_address, int prefix);

/*
 * Iterate over all hosts
 * Callback returns false to stop iteration
 */
typedef bool (*hosts_iterator_cb)(host_entry_t *host, void *ctx);
void hosts_db_foreach(hosts_iterator_cb callback, void *ctx);

/*
 * Get hosts count
 */
int hosts_db_count(void);

/*
 * Debug: dump hosts database to log
 */
void hosts_db_dump(void);

#endif /* TINC_HOSTS_JSON_H */
