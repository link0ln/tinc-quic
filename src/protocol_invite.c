/*
    protocol_invite.c -- handle the invitation protocol
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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "cert_autogen.h"
#include "conf.h"
#include "connection.h"
#include "hosts_json.h"
#include "invitation.h"
#include "logger.h"
#include "names.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/*
 * Invitation Protocol Flow:
 *
 * 1. INVITE_JOIN: Joining node sends token to inviter
 *    Format: INVITE_JOIN <token>
 *
 * 2. INVITE_DATA: Inviter sends CA cert and network config
 *    Format: INVITE_DATA <assigned_name> <ca_cert_base64> <network_config_base64>
 *
 * 3. INVITE_CSR: Joining node sends CSR
 *    Format: INVITE_CSR <csr_base64>
 *
 * 4. INVITE_CERT: Inviter sends signed certificate
 *    Format: INVITE_CERT <cert_base64> <fingerprint>
 */

/* Simple base64 encode/decode for PEM data */
static char *pem_to_base64(const char *pem) {
	if(!pem) return NULL;

	/* Remove PEM headers/footers and newlines */
	size_t len = strlen(pem);
	char *result = xmalloc(len + 1);
	char *p = result;

	const char *src = pem;
	bool in_body = false;

	while(*src) {
		if(strncmp(src, "-----BEGIN", 10) == 0) {
			/* Skip header line */
			while(*src && *src != '\n') src++;
			if(*src == '\n') src++;
			in_body = true;
			continue;
		}
		if(strncmp(src, "-----END", 8) == 0) {
			break;
		}
		if(in_body && *src != '\n' && *src != '\r') {
			*p++ = *src;
		}
		src++;
	}
	*p = '\0';

	return result;
}

static char *base64_to_pem(const char *base64, const char *type) {
	if(!base64 || !type) return NULL;

	size_t b64_len = strlen(base64);
	/* Add space for headers, footers, and newlines */
	size_t result_len = b64_len + 100 + (b64_len / 64) * 2;
	char *result = xmalloc(result_len);

	snprintf(result, result_len, "-----BEGIN %s-----\n", type);
	char *p = result + strlen(result);

	/* Add base64 data with line breaks every 64 characters */
	for(size_t i = 0; i < b64_len; i++) {
		*p++ = base64[i];
		if((i + 1) % 64 == 0) {
			*p++ = '\n';
		}
	}
	if(b64_len % 64 != 0) {
		*p++ = '\n';
	}

	snprintf(p, result_len - (p - result), "-----END %s-----\n", type);

	return result;
}

/*
 * Send INVITE_JOIN to inviter
 */
bool send_invite_join(connection_t *c, const char *token) {
	if(!c || !token) {
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Sending INVITE_JOIN to %s", c->name);
	return send_request(c, "%d %s", INVITE_JOIN, token);
}

/*
 * Handle INVITE_JOIN from joining node
 */
bool invite_join_h(connection_t *c, const char *request) {
	char token[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, token) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad INVITE_JOIN from %s (%s)", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Got INVITE_JOIN from %s with token", c->hostname);

	/* Validate token and get assigned name and VPN address */
	char *assigned_name = NULL;
	char *vpn_address = NULL;
	if(!validate_invitation_token(token, &assigned_name, &vpn_address)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid invitation token from %s", c->hostname);
		return false;
	}

	/* Mark this as an invitation connection (important for HTTP/3 bypass) */
	c->status.invitation = true;

	/* Store assigned name in connection */
	free(c->name);
	c->name = assigned_name;

	/* Store VPN address for later use when node joins */
	c->invitation_vpn_address = vpn_address; /* Transfer ownership, don't free */

	/* Set expected next request */
	c->allow_request = INVITE_CSR;

	/* Send INVITE_DATA with CA cert, config and VPN address */
	return send_invite_data(c, assigned_name, vpn_address);
}

/*
 * Send INVITE_DATA to joining node
 * vpn_address can be NULL if no IP was allocated
 * Also includes inviter's host info so the joining node can create hosts.json
 */
bool send_invite_data(connection_t *c, const char *name, const char *vpn_address) {
	if(!c || !name) {
		return false;
	}

	/* Read CA certificate */
	char *ca_path = NULL;
	xasprintf(&ca_path, "%s/ca-cert.pem", confbase);

	FILE *f = fopen(ca_path, "r");
	free(ca_path);

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot read CA certificate");
		return false;
	}

	char ca_pem[8192];
	size_t ca_len = fread(ca_pem, 1, sizeof(ca_pem) - 1, f);
	fclose(f);
	ca_pem[ca_len] = '\0';

	/* Convert to base64 */
	char *ca_base64 = pem_to_base64(ca_pem);
	if(!ca_base64) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to encode CA certificate");
		return false;
	}

	/* Build network config - include VPN address if allocated and inviter's info */
	char config_base64[2048];
	int offset = 0;

	/* Start with assigned name and VPN address */
	if(vpn_address && vpn_address[0]) {
		offset = snprintf(config_base64, sizeof(config_base64), "Name=%s,VPNAddress=%s", name, vpn_address);
	} else {
		offset = snprintf(config_base64, sizeof(config_base64), "Name=%s", name);
	}

	/* Add inviter's name so the joining node knows who invited it */
	if(myname) {
		offset += snprintf(config_base64 + offset, sizeof(config_base64) - offset, ",InvName=%s", myname);
	}

	/* Add ALL known hosts from hosts_db to the invitation
	 * Format: Host_N=name|addr1;addr2|port|vpn|subnet
	 * This allows the joining node to learn about the entire network */
	int host_count = 0;

	/* First add the inviter itself (myself) - this is crucial!
	 * The invitee needs to know where to connect to the inviter.
	 * Get inviter's address from config or connection */
	if(myname && c) {
		/* Get inviter's address - try config first, then use connection address */
		char inviter_addr[256] = "";

		/* Try to get Address from config */
		char *conf_addr = NULL;
		if(get_config_string(lookup_config(config_tree, "Address"), &conf_addr) && conf_addr) {
			snprintf(inviter_addr, sizeof(inviter_addr), "%s", conf_addr);
			free(conf_addr);
		}

		/* If no Address in config, use the local address from connection */
		if(!inviter_addr[0] && c->socket >= 0) {
			sockaddr_t sa;
			socklen_t salen = sizeof(sa);
			if(getsockname(c->socket, &sa.sa, &salen) == 0) {
				char addr_str[INET6_ADDRSTRLEN] = "";
				if(sa.sa.sa_family == AF_INET) {
					inet_ntop(AF_INET, &sa.in.sin_addr, addr_str, sizeof(addr_str));
				} else if(sa.sa.sa_family == AF_INET6) {
					inet_ntop(AF_INET6, &sa.in6.sin6_addr, addr_str, sizeof(addr_str));
				}
				if(addr_str[0]) {
					snprintf(inviter_addr, sizeof(inviter_addr), "%s", addr_str);
				}
			}
		}

		/* Get inviter's VPN address from config */
		char *my_vpn = NULL;
		if(get_config_string(lookup_config(config_tree, "VPNAddress"), &my_vpn)) {
			/* Got VPN address */
		}

		/* Get inviter's port */
		int my_port = 443;
		if(myport) {
			my_port = atoi(myport);
		}

		/* Add inviter as Host_0 */
		int written = snprintf(config_base64 + offset, sizeof(config_base64) - offset,
		                       ",Host_%d=%s|%s|%d|%s|",
		                       host_count, myname, inviter_addr, my_port,
		                       my_vpn ? my_vpn : "");

		if(written > 0 && offset + written < (int)sizeof(config_base64)) {
			offset += written;
			host_count++;
			logger(DEBUG_PROTOCOL, LOG_INFO, "Added inviter %s (addr=%s, vpn=%s) to INVITE_DATA",
			       myname, inviter_addr, my_vpn ? my_vpn : "none");
		}

		if(my_vpn) free(my_vpn);
	}

	/* Then add all other hosts from hosts_db */
	if(hosts_db) {
		for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
			/* Skip if this is the inviter (already added above) */
			if(myname && strcasecmp(h->name, myname) == 0) {
				continue;
			}

			/* Build addresses string (semicolon-separated) */
			char addrs[512] = "";
			int addr_offset = 0;
			for(int i = 0; i < h->address_count && addr_offset < (int)sizeof(addrs) - 1; i++) {
				if(i > 0) {
					addrs[addr_offset++] = ';';
				}
				addr_offset += snprintf(addrs + addr_offset, sizeof(addrs) - addr_offset,
				                         "%s", h->addresses[i]);
			}

			/* Add host entry: Host_N=name|addrs|port|vpn|subnet */
			int written = snprintf(config_base64 + offset, sizeof(config_base64) - offset,
			                       ",Host_%d=%s|%s|%d|%s|%s",
			                       host_count, h->name, addrs, h->port,
			                       h->vpn_address[0] ? h->vpn_address : "",
			                       h->subnet[0] ? h->subnet : "");

			if(written > 0 && offset + written < (int)sizeof(config_base64)) {
				offset += written;
				host_count++;
			} else {
				/* Buffer full, stop adding hosts */
				logger(DEBUG_PROTOCOL, LOG_WARNING, "Invitation config buffer full, stopping at %d hosts", host_count);
				break;
			}
		}
	}

	/* Add total host count for easier parsing */
	offset += snprintf(config_base64 + offset, sizeof(config_base64) - offset, ",HostCount=%d", host_count);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Sending INVITE_DATA to %s: name=%s, vpn=%s, inviter=%s, hosts=%d",
	       c->hostname, name, vpn_address ? vpn_address : "none",
	       myname ? myname : "unknown", host_count);

	bool result = send_request(c, "%d %s %s %s", INVITE_DATA, name, ca_base64, config_base64);

	free(ca_base64);
	return result;
}

/*
 * Generic config value extractor
 * Format: "Key1=value1,Key2=value2,..."
 * Returns allocated string or NULL if key not found
 */
static char *extract_config_value(const char *config, const char *key) {
	if(!config || !key) return NULL;

	/* Build search pattern "key=" */
	size_t key_len = strlen(key);
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "%s=", key);

	const char *p = strstr(config, pattern);
	if(!p) return NULL;

	p += key_len + 1; /* Skip "key=" */

	/* Find end of value (comma or end of string) */
	const char *end = strchr(p, ',');
	size_t len = end ? (size_t)(end - p) : strlen(p);

	char *result = xmalloc(len + 1);
	memcpy(result, p, len);
	result[len] = '\0';

	return result;
}

/*
 * Parse config string to extract VPNAddress
 * Format: "Name=xxx,VPNAddress=10.0.0.2/24"
 */
static char *extract_vpn_address(const char *config) {
	return extract_config_value(config, "VPNAddress");
}

/*
 * Parse a single host entry from invitation
 * Format: name|addr1;addr2|port|vpn|subnet
 */
static bool parse_host_from_invite(const char *entry) {
	if(!entry || !entry[0]) return false;

	char *copy = xstrdup(entry);
	char *name = NULL, *addrs = NULL, *port_str = NULL, *vpn = NULL, *subnet = NULL;

	/* Parse pipe-separated fields */
	char *p = copy;
	name = p;

	p = strchr(p, '|');
	if(p) { *p++ = '\0'; addrs = p; }

	if(p) { p = strchr(p, '|'); if(p) { *p++ = '\0'; port_str = p; } }
	if(p) { p = strchr(p, '|'); if(p) { *p++ = '\0'; vpn = p; } }
	if(p) { p = strchr(p, '|'); if(p) { *p++ = '\0'; subnet = p; } }

	if(!name || !name[0]) {
		free(copy);
		return false;
	}

	/* Add host to database */
	host_entry_t *host = hosts_db_add(name);
	if(!host) {
		free(copy);
		return false;
	}

	/* Set port */
	if(port_str && port_str[0]) {
		host->port = (uint16_t)atoi(port_str);
	}

	/* Set VPN address */
	if(vpn && vpn[0]) {
		/* Parse prefix from subnet if available */
		int prefix = 32;
		if(subnet && subnet[0]) {
			char *slash = strchr(subnet, '/');
			if(slash) {
				prefix = atoi(slash + 1);
			}
		}
		host_set_vpn_address(host, vpn, prefix);
	} else if(subnet && subnet[0]) {
		/* Use subnet directly */
		strncpy(host->subnet, subnet, MAX_SUBNET_LEN - 1);
	}

	/* Parse addresses (semicolon-separated) */
	if(addrs && addrs[0]) {
		char *addrs_copy = xstrdup(addrs);
		char *addr = strtok(addrs_copy, ";");
		while(addr && host->address_count < MAX_HOST_ADDRESSES) {
			if(addr[0]) {
				host_add_address(host, addr);
			}
			addr = strtok(NULL, ";");
		}
		free(addrs_copy);
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Parsed host from invite: %s vpn=%s addrs=%d",
	       name, host->vpn_address[0] ? host->vpn_address : "none", host->address_count);

	free(copy);
	return true;
}

/*
 * Create hosts.json with all hosts from invitation
 * Called by joining node after receiving INVITE_DATA
 */
static bool create_hosts_json_from_invite(const char *config, const char *my_name, const char *my_vpn_address) {
	/* Check if this invitation contains host info */
	char *inv_name = extract_config_value(config, "InvName");
	if(!inv_name) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "No host info in INVITE_DATA, skipping hosts.json creation");
		return true; /* Not an error, just old-style invite */
	}

	/* Get host count */
	char *host_count_str = extract_config_value(config, "HostCount");
	int host_count = host_count_str ? atoi(host_count_str) : 0;

	logger(DEBUG_PROTOCOL, LOG_INFO, "Creating hosts.json from invitation: inviter=%s, total hosts=%d",
	       inv_name, host_count);

	free(inv_name);
	free(host_count_str);

	/* Initialize hosts_db if not already done */
	if(!hosts_db) {
		if(!hosts_db_init(confbase)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize hosts_db");
			return true;
		}
	}

	/* Parse all hosts from invitation */
	int added = 0;
	for(int i = 0; i < host_count; i++) {
		char key[32];
		snprintf(key, sizeof(key), "Host_%d", i);
		char *entry = extract_config_value(config, key);
		if(entry) {
			if(parse_host_from_invite(entry)) {
				added++;
			}
			free(entry);
		}
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Added %d hosts from invitation", added);

	/* Add own entry if VPN address was assigned and not already in the list */
	if(my_name && my_vpn_address && my_vpn_address[0]) {
		host_entry_t *my_host = hosts_db_find(my_name);
		if(!my_host) {
			my_host = hosts_db_add(my_name);
		}
		if(my_host) {
			/* Parse "10.0.0.X/24" into IP and prefix */
			char ip_only[64];
			int prefix = 32;
			const char *slash = strchr(my_vpn_address, '/');
			if(slash) {
				size_t ip_len = slash - my_vpn_address;
				if(ip_len < sizeof(ip_only)) {
					strncpy(ip_only, my_vpn_address, ip_len);
					ip_only[ip_len] = '\0';
					prefix = atoi(slash + 1);
				}
			} else {
				strncpy(ip_only, my_vpn_address, sizeof(ip_only) - 1);
				ip_only[sizeof(ip_only) - 1] = '\0';
			}
			host_set_vpn_address(my_host, ip_only, 32); /* Own entry always /32 */
			if(my_host->port == 0) {
				my_host->port = 443; /* Default port */
			}

			logger(DEBUG_PROTOCOL, LOG_INFO, "Added self %s to hosts.json (vpn=%s)",
			       my_name, my_host->vpn_address);
		}
	}

	/* Save hosts.json */
	if(!hosts_db_save()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to save hosts.json");
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Created hosts.json with %d nodes from invitation", hosts_db_count());
	return true;
}

/*
 * Write VPNAddress to tinc.conf
 */
static bool write_vpn_address_to_conf(const char *vpn_address) {
	if(!vpn_address || !vpn_address[0]) return true; /* Nothing to write */

	char *conf_path = NULL;
	xasprintf(&conf_path, "%s/tinc.conf", confbase);

	/* Read existing config */
	FILE *f = fopen(conf_path, "r");
	if(!f) {
		/* Config doesn't exist - will be created during join */
		free(conf_path);
		return true;
	}

	/* Read entire file */
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *content = xmalloc(size + 1);
	size_t read_len = fread(content, 1, size, f);
	content[read_len] = '\0';
	fclose(f);

	/* Check if uncommented VPNAddress already exists */
	bool has_vpn_addr = false;
	char *line = content;
	while(*line) {
		char *next = strchr(line, '\n');
		if(!next) next = line + strlen(line);

		/* Skip whitespace */
		char *p = line;
		while(*p == ' ' || *p == '\t') p++;

		/* Check if this is an uncommented VPNAddress line */
		if(*p != '#' && strncasecmp(p, "VPNAddress", 10) == 0) {
			has_vpn_addr = true;
			break;
		}

		if(*next == '\0') break;
		line = next + 1;
	}

	/* Rewrite config */
	f = fopen(conf_path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot write to %s", conf_path);
		free(conf_path);
		free(content);
		return false;
	}

	if(has_vpn_addr) {
		/* Replace existing VPNAddress line */
		char *line_start = content;
		while(*line_start) {
			char *line_end = strchr(line_start, '\n');
			if(!line_end) line_end = line_start + strlen(line_start);

			/* Check if this line is VPNAddress */
			char *p = line_start;
			while(*p == ' ' || *p == '\t') p++;

			if(strncasecmp(p, "VPNAddress", 10) == 0) {
				/* Write new VPNAddress instead */
				fprintf(f, "VPNAddress = %s\n", vpn_address);
			} else {
				/* Write original line */
				fwrite(line_start, 1, line_end - line_start, f);
				if(*line_end == '\n') fputc('\n', f);
			}

			if(*line_end == '\0') break;
			line_start = line_end + 1;
		}
	} else {
		/* Append VPNAddress at the end */
		fprintf(f, "%s", content);
		if(read_len > 0 && content[read_len - 1] != '\n') {
			fputc('\n', f);
		}
		fprintf(f, "\n# VPN Address assigned during join\nVPNAddress = %s\n", vpn_address);
	}

	fclose(f);
	free(conf_path);
	free(content);

	logger(DEBUG_ALWAYS, LOG_INFO, "Wrote VPNAddress = %s to tinc.conf", vpn_address);
	return true;
}

/*
 * Write ConnectTo to tinc.conf (for inviter node)
 * Also removes invalid ConnectTo = <invitation> entries
 */
static bool write_connect_to_conf(const char *inviter_name) {
	if(!inviter_name || !inviter_name[0]) return true; /* Nothing to write */

	char *conf_path = NULL;
	xasprintf(&conf_path, "%s/tinc.conf", confbase);

	/* Read existing config */
	FILE *f = fopen(conf_path, "r");
	if(!f) {
		/* Config doesn't exist - will be created during join */
		free(conf_path);
		return true;
	}

	/* Read entire file */
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *content = xmalloc(size + 1);
	size_t read_len = fread(content, 1, size, f);
	content[read_len] = '\0';
	fclose(f);

	/* Check if ConnectTo for this inviter already exists and filter out <invitation> entries */
	bool has_connect_to = false;
	bool has_invalid_invitation = false;

	/* Build new content without <invitation> entries */
	char *new_content = xmalloc(size + 256); /* Extra space for new ConnectTo */
	new_content[0] = '\0';
	size_t new_len = 0;

	char *line = content;
	while(*line) {
		char *next = strchr(line, '\n');
		size_t line_len = next ? (size_t)(next - line) : strlen(line);

		/* Skip whitespace for analysis */
		char *p = line;
		while(*p == ' ' || *p == '\t') p++;

		bool skip_line = false;

		/* Check if this is a ConnectTo line */
		if(*p != '#' && strncasecmp(p, "ConnectTo", 9) == 0) {
			char *eq = strchr(p, '=');
			if(eq) {
				eq++;
				while(*eq == ' ' || *eq == '\t') eq++;
				/* Check for <invitation> - skip this line */
				if(strncasecmp(eq, "<invitation>", 12) == 0) {
					skip_line = true;
					has_invalid_invitation = true;
					logger(DEBUG_PROTOCOL, LOG_INFO, "Removing invalid ConnectTo = <invitation> from tinc.conf");
				}
				/* Check if it's for our inviter */
				else if(strncasecmp(eq, inviter_name, strlen(inviter_name)) == 0) {
					has_connect_to = true;
				}
			}
		}
		/* Also skip the comment line before <invitation> */
		else if(*p == '#' && has_invalid_invitation && strstr(p, "inviter") && new_len > 0) {
			/* Check if last line was the comment for invitation */
			/* This is a bit heuristic - skip if previous output ends with this comment */
		}

		if(!skip_line) {
			memcpy(new_content + new_len, line, line_len);
			new_len += line_len;
			if(next) {
				new_content[new_len++] = '\n';
			}
		}

		if(!next || *next == '\0') break;
		line = next + 1;
	}
	new_content[new_len] = '\0';

	/* If already have valid ConnectTo and no invalid entries, nothing to do */
	if(has_connect_to && !has_invalid_invitation) {
		free(conf_path);
		free(content);
		free(new_content);
		logger(DEBUG_PROTOCOL, LOG_INFO, "ConnectTo = %s already exists in tinc.conf", inviter_name);
		return true;
	}

	/* Rewrite file if we had invalid entries, or append if we just need to add ConnectTo */
	if(has_invalid_invitation) {
		/* Rewrite entire file without invalid entries */
		f = fopen(conf_path, "w");
		if(!f) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Cannot write to %s", conf_path);
			free(conf_path);
			free(content);
			free(new_content);
			return false;
		}
		fputs(new_content, f);
	} else {
		/* Just append */
		f = fopen(conf_path, "a");
		if(!f) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Cannot append to %s", conf_path);
			free(conf_path);
			free(content);
			free(new_content);
			return false;
		}
	}

	/* Add ConnectTo if not already present */
	if(!has_connect_to) {
		fprintf(f, "\n# Connect to inviter node\nConnectTo = %s\n", inviter_name);
	}

	fclose(f);
	free(conf_path);
	free(content);
	free(new_content);

	logger(DEBUG_ALWAYS, LOG_INFO, "Wrote ConnectTo = %s to tinc.conf", inviter_name);
	return true;
}

/*
 * Handle INVITE_DATA from inviter
 */
bool invite_data_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];
	char ca_base64[8192];
	char config_base64[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %8000s %2048s", name, ca_base64, config_base64) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad INVITE_DATA from %s (%s)", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Got INVITE_DATA from %s: assigned name=%s", c->hostname, name);

	/* Extract VPN address from config if present */
	char *vpn_address = extract_vpn_address(config_base64);
	if(vpn_address) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Got VPN address from inviter: %s", vpn_address);
	}

	/* Convert CA cert back to PEM */
	char *ca_pem = base64_to_pem(ca_base64, "CERTIFICATE");
	if(!ca_pem) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to decode CA certificate");
		free(vpn_address);
		return false;
	}

	/* Save CA certificate */
	char *ca_path = NULL;
	xasprintf(&ca_path, "%s/ca-cert.pem", confbase);

	FILE *f = fopen(ca_path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot save CA certificate to %s", ca_path);
		free(ca_path);
		free(ca_pem);
		free(vpn_address);
		return false;
	}

	fprintf(f, "%s", ca_pem);
	fclose(f);
	free(ca_path);
	free(ca_pem);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Saved CA certificate");

	/* Write VPN address to tinc.conf if received */
	if(vpn_address) {
		if(!write_vpn_address_to_conf(vpn_address)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to write VPNAddress to tinc.conf");
		}
		/* Don't free vpn_address yet - needed for hosts.json creation */
	}

	/* Extract inviter name from config and write ConnectTo */
	char *inviter_name = extract_config_value(config_base64, "InvName");
	if(inviter_name) {
		if(!write_connect_to_conf(inviter_name)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to write ConnectTo to tinc.conf");
		}
		free(inviter_name);
	} else {
		logger(DEBUG_PROTOCOL, LOG_INFO, "No inviter name in INVITE_DATA, skipping ConnectTo");
	}

	/* Create hosts.json with inviter's info and own entry */
	create_hosts_json_from_invite(config_base64, name, vpn_address);

	/* Now free vpn_address */
	free(vpn_address);

	/* Generate key pair and CSR */
	char *key_pem = NULL;
	char *csr_pem = NULL;

	if(!generate_csr(name, &key_pem, &csr_pem)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate CSR");
		return false;
	}

	/* Save private key */
	char *key_path = NULL;
	xasprintf(&key_path, "%s/server-key.pem", confbase);

	f = fopen(key_path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot save private key to %s", key_path);
		free(key_path);
		free(key_pem);
		free(csr_pem);
		return false;
	}

	fprintf(f, "%s", key_pem);
	fclose(f);
	chmod(key_path, 0600);
	free(key_path);
	free(key_pem);

	logger(DEBUG_PROTOCOL, LOG_INFO, "Generated and saved private key");

	/* Send CSR */
	bool result = send_invite_csr(c, csr_pem);
	free(csr_pem);

	if(result) {
		/* Expect INVITE_CERT response */
		c->allow_request = INVITE_CERT;
	}

	return result;
}

/*
 * Send INVITE_CSR to inviter
 */
bool send_invite_csr(connection_t *c, const char *csr_pem) {
	if(!c || !csr_pem) {
		return false;
	}

	char *csr_base64 = pem_to_base64(csr_pem);
	if(!csr_base64) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to encode CSR");
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Sending INVITE_CSR to %s", c->hostname);

	bool result = send_request(c, "%d %s", INVITE_CSR, csr_base64);

	free(csr_base64);
	return result;
}

/*
 * Handle INVITE_CSR from joining node
 */
bool invite_csr_h(connection_t *c, const char *request) {
	char csr_base64[8192];

	if(sscanf(request, "%*d %8000s", csr_base64) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad INVITE_CSR from %s (%s)", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Got INVITE_CSR from %s", c->name);

	/* Convert CSR back to PEM */
	char *csr_pem = base64_to_pem(csr_base64, "CERTIFICATE REQUEST");
	if(!csr_pem) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to decode CSR");
		return false;
	}

	/* Sign CSR */
	char *cert_pem = NULL;
	if(!handle_join_csr(csr_pem, NULL, &cert_pem)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign CSR from %s", c->name);
		free(csr_pem);
		return false;
	}

	free(csr_pem);

	/* Calculate fingerprint of signed certificate */
	char *fingerprint = calculate_cert_fingerprint(cert_pem);

	/* Send signed certificate */
	bool result = send_invite_cert(c, cert_pem, fingerprint ? fingerprint : "unknown");

	free(cert_pem);
	free(fingerprint);

	/* Add new node to hosts.json database */
	if(hosts_db) {
		host_entry_t *host = hosts_db_add(c->name);
		if(host) {
			/* Set VPN address if allocated */
			if(c->invitation_vpn_address && c->invitation_vpn_address[0]) {
				/* Parse "10.0.0.X/24" into IP and prefix */
				char ip_only[64];
				int prefix = 32;
				char *slash = strchr(c->invitation_vpn_address, '/');
				if(slash) {
					size_t ip_len = slash - c->invitation_vpn_address;
					if(ip_len < sizeof(ip_only)) {
						strncpy(ip_only, c->invitation_vpn_address, ip_len);
						ip_only[ip_len] = '\0';
						prefix = atoi(slash + 1);
					}
				} else {
					strncpy(ip_only, c->invitation_vpn_address, sizeof(ip_only) - 1);
				}
				host_set_vpn_address(host, ip_only, prefix);
			}
			hosts_db_save();
			logger(DEBUG_PROTOCOL, LOG_INFO, "Added node %s to hosts.json (vpn=%s)",
			       c->name, host->vpn_address[0] ? host->vpn_address : "none");
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_WARNING, "hosts_db not initialized, node %s not saved", c->name);
	}

	return result;
}

/*
 * Send INVITE_CERT to joining node
 */
bool send_invite_cert(connection_t *c, const char *cert_pem, const char *fingerprint) {
	if(!c || !cert_pem || !fingerprint) {
		return false;
	}

	char *cert_base64 = pem_to_base64(cert_pem);
	if(!cert_base64) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to encode certificate");
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Sending INVITE_CERT to %s with fingerprint %s",
	       c->name, fingerprint);

	bool result = send_request(c, "%d %s %s", INVITE_CERT, cert_base64, fingerprint);

	free(cert_base64);
	return result;
}

/*
 * Handle INVITE_CERT from inviter
 */
bool invite_cert_h(connection_t *c, const char *request) {
	char cert_base64[8192];
	char fingerprint[MAX_STRING_SIZE];

	if(sscanf(request, "%*d %8000s " MAX_STRING, cert_base64, fingerprint) < 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad INVITE_CERT from %s (%s)", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "Got INVITE_CERT from %s with fingerprint %s",
	       c->hostname, fingerprint);

	/* Convert certificate back to PEM */
	char *cert_pem = base64_to_pem(cert_base64, "CERTIFICATE");
	if(!cert_pem) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to decode certificate");
		return false;
	}

	/* Save certificate */
	char *cert_path = NULL;
	xasprintf(&cert_path, "%s/server-cert.pem", confbase);

	FILE *f = fopen(cert_path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot save certificate to %s", cert_path);
		free(cert_path);
		free(cert_pem);
		return false;
	}

	fprintf(f, "%s", cert_pem);
	fclose(f);
	free(cert_path);
	free(cert_pem);

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Join complete! Certificate saved with fingerprint: %s", fingerprint);
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Please restart tincd to use the new certificate");

	/* Close the invitation connection */
	return false; /* Returning false closes the connection cleanly */
}
