/*
    invitation.c -- Create and accept invitations
    Copyright (C) 2013-2017 Guus Sliepen <guus@tinc-vpn.org>
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
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#include "invitation.h"
#include "cert_autogen.h"
#include "conf.h"
#include "connection.h"
#include "control_common.h"
#include "crypto.h"
#include "hosts_json.h"
#include "logger.h"
#include "names.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Invitation token size (32 bytes = 256 bits) */
#define INVITATION_TOKEN_SIZE 32

/* Invitation validity period: 24 hours */
#define INVITATION_VALIDITY (24 * 3600)

/* Maximum number of IPs in pool (/24 = 254 hosts) */
#define MAX_IP_POOL 254

/* Forward declaration */
static char *get_invitations_dir(void);

/*
 * Parse VPNAddress (e.g., "10.0.0.1/24") into components
 * Returns: base IP as uint32_t, prefix length, and formatted my_ip string
 */
static bool parse_vpn_address(uint32_t *network, int *prefix, char *my_ip, size_t my_ip_size) {
	char vpn_addr[64] = {0};

	/* Read VPNAddress from tinc.conf */
	char *conf_path = NULL;
	xasprintf(&conf_path, "%s/tinc.conf", confbase);

	FILE *f = fopen(conf_path, "r");
	free(conf_path);

	if(!f) {
		return false;
	}

	char line[256];
	while(fgets(line, sizeof(line), f)) {
		char *p = line;
		while(*p == ' ' || *p == '\t') p++;

		if(strncasecmp(p, "VPNAddress", 10) == 0) {
			p += 10;
			while(*p == ' ' || *p == '\t' || *p == '=') p++;
			char *nl = strchr(p, '\n');
			if(nl) *nl = '\0';
			char *cr = strchr(p, '\r');
			if(cr) *cr = '\0';
			strncpy(vpn_addr, p, sizeof(vpn_addr) - 1);
			break;
		}
	}
	fclose(f);

	if(!vpn_addr[0]) {
		return false;
	}

	/* Parse IP/prefix (e.g., "10.0.0.1/24") */
	char *slash = strchr(vpn_addr, '/');
	if(!slash) {
		return false;
	}

	*slash = '\0';
	*prefix = atoi(slash + 1);

	/* Copy my IP */
	if(my_ip && my_ip_size > 0) {
		strncpy(my_ip, vpn_addr, my_ip_size - 1);
	}

	/* Parse IP octets */
	int a, b, c, d;
	if(sscanf(vpn_addr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
		return false;
	}

	uint32_t ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;

	/* Calculate network address */
	uint32_t mask = *prefix ? (~0U << (32 - *prefix)) : 0;
	*network = ip & mask;

	return true;
}

/*
 * Convert uint32_t IP to string
 */
static void ip_to_string(uint32_t ip, char *buf, size_t size) {
	snprintf(buf, size, "%u.%u.%u.%u",
	         (ip >> 24) & 0xFF,
	         (ip >> 16) & 0xFF,
	         (ip >> 8) & 0xFF,
	         ip & 0xFF);
}

/*
 * Parse IP string to uint32_t
 */
static uint32_t string_to_ip(const char *str) {
	int a, b, c, d;
	if(sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
		return 0;
	}
	return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

/*
 * Check if IP is used in hosts.json database
 */
static bool ip_used_in_hosts(uint32_t ip) {
	char ip_str[32];
	ip_to_string(ip, ip_str, sizeof(ip_str));

	/* Check in hosts.json database */
	if(hosts_db) {
		const char *owner = hosts_db_find_by_vpn_address(ip_str);
		if(owner) {
			return true;
		}
	}

	return false;
}

/*
 * Check if IP is reserved in pending invitations
 */
static bool ip_used_in_invitations(uint32_t ip) {
	char *dir = get_invitations_dir();
	DIR *d = opendir(dir);

	if(!d) {
		free(dir);
		return false;
	}

	char ip_str[32];
	ip_to_string(ip, ip_str, sizeof(ip_str));

	struct dirent *ent;
	bool found = false;

	while((ent = readdir(d)) != NULL) {
		if(ent->d_name[0] == '.') continue;

		char *filepath = NULL;
		xasprintf(&filepath, "%s/%s", dir, ent->d_name);

		FILE *f = fopen(filepath, "r");
		if(f) {
			char line[256];
			while(fgets(line, sizeof(line), f)) {
				if(strncasecmp(line, "VPNAddress", 10) == 0 && strstr(line, ip_str)) {
					found = true;
					break;
				}
			}
			fclose(f);
		}
		free(filepath);

		if(found) break;
	}

	closedir(d);
	free(dir);
	return found;
}

/*
 * Check if IP is my own address
 */
static bool ip_is_mine(uint32_t ip, const char *my_ip) {
	return ip == string_to_ip(my_ip);
}

/*
 * Allocate a free IP address from the VPN subnet
 * Returns allocated IP as string (caller must free) or NULL if no free IP
 */
static char *allocate_vpn_ip(void) {
	uint32_t network;
	int prefix;
	char my_ip[32];

	if(!parse_vpn_address(&network, &prefix, my_ip, sizeof(my_ip))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot parse VPNAddress from tinc.conf");
		return NULL;
	}

	/* Calculate number of hosts in subnet */
	uint32_t host_bits = 32 - prefix;
	uint32_t num_hosts = (1U << host_bits) - 2;  /* Exclude network and broadcast */

	if(num_hosts > MAX_IP_POOL) {
		num_hosts = MAX_IP_POOL;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "IP pool: network=%08X, prefix=%d, hosts=%u, my_ip=%s",
	       network, prefix, num_hosts, my_ip);

	/* Try each host address starting from .2 (assuming .1 is server) */
	for(uint32_t i = 2; i <= num_hosts + 1; i++) {
		uint32_t candidate = network | i;

		/* Skip if it's my own IP */
		if(ip_is_mine(candidate, my_ip)) {
			continue;
		}

		/* Skip network address and broadcast */
		if((candidate & ((1U << host_bits) - 1)) == 0 ||
		   (candidate & ((1U << host_bits) - 1)) == ((1U << host_bits) - 1)) {
			continue;
		}

		/* Check if already used */
		if(ip_used_in_hosts(candidate)) {
			continue;
		}

		/* Check if reserved in pending invitation */
		if(ip_used_in_invitations(candidate)) {
			continue;
		}

		/* Found free IP! */
		char *result = xmalloc(32);
		ip_to_string(candidate, result, 32);
		logger(DEBUG_ALWAYS, LOG_INFO, "Allocated VPN IP: %s/%d", result, prefix);

		/* Return with prefix */
		char *full_addr = xmalloc(40);
		snprintf(full_addr, 40, "%s/%d", result, prefix);
		free(result);
		return full_addr;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "No free IP addresses in pool");
	return NULL;
}

/* Base64 URL-safe encoding table */
static const char base64url_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 * Base64 URL-safe encode
 */
static char *base64url_encode(const unsigned char *data, size_t len) {
	size_t outlen = ((len + 2) / 3) * 4 + 1;
	char *out = xmalloc(outlen);
	char *p = out;

	for(size_t i = 0; i < len; i += 3) {
		unsigned int n = data[i] << 16;
		if(i + 1 < len) n |= data[i + 1] << 8;
		if(i + 2 < len) n |= data[i + 2];

		*p++ = base64url_table[(n >> 18) & 0x3f];
		*p++ = base64url_table[(n >> 12) & 0x3f];
		*p++ = (i + 1 < len) ? base64url_table[(n >> 6) & 0x3f] : '=';
		*p++ = (i + 2 < len) ? base64url_table[n & 0x3f] : '=';
	}

	*p = '\0';
	return out;
}

/*
 * Base64 URL-safe decode
 */
static unsigned char *base64url_decode(const char *str, size_t *outlen) {
	size_t len = strlen(str);
	if(len % 4 != 0) {
		return NULL;
	}

	*outlen = (len / 4) * 3;
	if(len > 0 && str[len - 1] == '=') (*outlen)--;
	if(len > 1 && str[len - 2] == '=') (*outlen)--;

	unsigned char *out = xmalloc(*outlen);
	unsigned char *p = out;

	for(size_t i = 0; i < len; i += 4) {
		int n[4];
		for(int j = 0; j < 4; j++) {
			char c = str[i + j];
			if(c >= 'A' && c <= 'Z') n[j] = c - 'A';
			else if(c >= 'a' && c <= 'z') n[j] = c - 'a' + 26;
			else if(c >= '0' && c <= '9') n[j] = c - '0' + 52;
			else if(c == '-') n[j] = 62;
			else if(c == '_') n[j] = 63;
			else if(c == '=') n[j] = 0;
			else { free(out); return NULL; }
		}

		unsigned int val = (n[0] << 18) | (n[1] << 12) | (n[2] << 6) | n[3];
		if(p - out < (ptrdiff_t)*outlen) *p++ = (val >> 16) & 0xff;
		if(p - out < (ptrdiff_t)*outlen) *p++ = (val >> 8) & 0xff;
		if(p - out < (ptrdiff_t)*outlen) *p++ = val & 0xff;
	}

	return out;
}

/*
 * Get the invitations directory path
 */
static char *get_invitations_dir(void) {
	char *path = NULL;
	xasprintf(&path, "%s/invitations", confbase);
	return path;
}

/*
 * Ensure invitations directory exists
 */
static bool ensure_invitations_dir(void) {
	char *dir = get_invitations_dir();

	if(mkdir(dir, 0700) != 0 && errno != EEXIST) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create invitations directory %s: %s",
		       dir, strerror(errno));
		free(dir);
		return false;
	}

	free(dir);
	return true;
}

/*
 * Generate random token
 */
static char *generate_token(void) {
	unsigned char token_bytes[INVITATION_TOKEN_SIZE];
	randomize(token_bytes, sizeof(token_bytes));
	return base64url_encode(token_bytes, sizeof(token_bytes));
}

/*
 * Get hash of token for filename
 */
static char *token_to_filename(const char *token) {
	/* Use first 16 chars of token as filename (safe for filesystem) */
	char *filename = xmalloc(17);
	strncpy(filename, token, 16);
	filename[16] = '\0';
	return filename;
}

/*
 * Clean up expired invitations
 */
static void cleanup_expired_invitations(void) {
	char *dir = get_invitations_dir();
	DIR *d = opendir(dir);

	if(!d) {
		free(dir);
		return;
	}

	time_t now = time(NULL);
	struct dirent *ent;

	while((ent = readdir(d)) != NULL) {
		if(ent->d_name[0] == '.') continue;

		char *filepath = NULL;
		xasprintf(&filepath, "%s/%s", dir, ent->d_name);

		struct stat st;
		if(stat(filepath, &st) == 0) {
			if(now - st.st_mtime > INVITATION_VALIDITY) {
				unlink(filepath);
				logger(DEBUG_ALWAYS, LOG_INFO, "Removed expired invitation: %s", ent->d_name);
			}
		}

		free(filepath);
	}

	closedir(d);
	free(dir);
}

/*
 * Check if node already exists
 */
static bool node_exists(const char *name) {
	/* Check in hosts.json database */
	if(hosts_db && hosts_db_find(name)) {
		return true;
	}
	return false;
}

/*
 * Get our external address for invitation URL
 */
static char *get_my_address(void) {
	/* Try to read Address from hosts.json */
	if(hosts_db) {
		host_entry_t *me = hosts_db_find(myname);
		if(me && me->address_count > 0) {
			return xstrdup(me->addresses[0]);
		}
	}

	/* Fallback: try to determine from listening sockets */
	return xstrdup("127.0.0.1");
}

/*
 * Create an invitation
 */
int create_invitation(const char *name, char **url) {
	if(!name || !url) {
		return -1;
	}

	*url = NULL;

	/* Check if we have CA authority */
	if(!has_ca_authority(confbase)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "This node does not have CA authority");
		return -3;
	}

	/* Check if node already exists */
	if(node_exists(name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Node %s already exists", name);
		return -2;
	}

	/* Ensure invitations directory exists */
	if(!ensure_invitations_dir()) {
		return -4;
	}

	/* Clean up old invitations */
	cleanup_expired_invitations();

	/* Generate token */
	char *token = generate_token();
	char *filename = token_to_filename(token);

	/* Write invitation file */
	char *dir = get_invitations_dir();
	char *filepath = NULL;
	xasprintf(&filepath, "%s/%s", dir, filename);
	free(dir);

	FILE *f = fopen(filepath, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create invitation file: %s", strerror(errno));
		free(filepath);
		free(filename);
		free(token);
		return -4;
	}

	fprintf(f, "Name = %s\n", name);
	fprintf(f, "Token = %s\n", token);
	fprintf(f, "Created = %ld\n", (long)time(NULL));
	fprintf(f, "Expires = %ld\n", (long)(time(NULL) + INVITATION_VALIDITY));

	/* Allocate VPN IP address for this node */
	char *allocated_ip = allocate_vpn_ip();
	if(allocated_ip) {
		fprintf(f, "VPNAddress = %s\n", allocated_ip);
		logger(DEBUG_ALWAYS, LOG_INFO, "Allocated VPN address %s for node %s", allocated_ip, name);
		free(allocated_ip);
	} else {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not allocate VPN address for node %s", name);
	}

	fclose(f);
	free(filepath);
	free(filename);

	/* Build URL */
	char *address = get_my_address();
	xasprintf(url, "https://%s:443/invite/%s", address, token);
	free(address);

	logger(DEBUG_ALWAYS, LOG_INFO, "Created invitation for %s: %s", name, *url);

	free(token);
	return 0;
}

/*
 * Validate invitation token
 * Returns name and vpn_address (if allocated) - caller must free both
 */
bool validate_invitation_token(const char *token, char **name, char **vpn_address) {
	if(!token || !name) {
		return false;
	}

	*name = NULL;
	if(vpn_address) *vpn_address = NULL;

	char *filename = token_to_filename(token);
	char *dir = get_invitations_dir();
	char *filepath = NULL;
	xasprintf(&filepath, "%s/%s", dir, filename);
	free(dir);
	free(filename);

	FILE *f = fopen(filepath, "r");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invitation not found: %s", token);
		free(filepath);
		return false;
	}

	char line[1024];
	char stored_token[256] = {0};
	char stored_name[256] = {0};
	char stored_vpn_address[64] = {0};
	long expires = 0;

	while(fgets(line, sizeof(line), f)) {
		char *p = line;
		while(*p == ' ' || *p == '\t') p++;

		if(strncasecmp(p, "Token", 5) == 0) {
			p += 5;
			while(*p == ' ' || *p == '\t' || *p == '=') p++;
			char *nl = strchr(p, '\n');
			if(nl) *nl = '\0';
			strncpy(stored_token, p, sizeof(stored_token) - 1);
		} else if(strncasecmp(p, "Name", 4) == 0 && strncasecmp(p, "VPNAddress", 10) != 0) {
			p += 4;
			while(*p == ' ' || *p == '\t' || *p == '=') p++;
			char *nl = strchr(p, '\n');
			if(nl) *nl = '\0';
			strncpy(stored_name, p, sizeof(stored_name) - 1);
		} else if(strncasecmp(p, "VPNAddress", 10) == 0) {
			p += 10;
			while(*p == ' ' || *p == '\t' || *p == '=') p++;
			char *nl = strchr(p, '\n');
			if(nl) *nl = '\0';
			strncpy(stored_vpn_address, p, sizeof(stored_vpn_address) - 1);
		} else if(strncasecmp(p, "Expires", 7) == 0) {
			p += 7;
			while(*p == ' ' || *p == '\t' || *p == '=') p++;
			expires = atol(p);
		}
	}

	fclose(f);

	/* Verify token matches */
	if(strcmp(token, stored_token) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Token mismatch for invitation");
		free(filepath);
		return false;
	}

	/* Check expiration */
	if(time(NULL) > expires) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invitation has expired");
		unlink(filepath);
		free(filepath);
		return false;
	}

	/* Delete invitation file (one-time use) */
	unlink(filepath);
	free(filepath);

	*name = xstrdup(stored_name);
	if(vpn_address && stored_vpn_address[0]) {
		*vpn_address = xstrdup(stored_vpn_address);
		logger(DEBUG_ALWAYS, LOG_INFO, "Validated invitation for node: %s, VPN address: %s", *name, *vpn_address);
	} else {
		logger(DEBUG_ALWAYS, LOG_INFO, "Validated invitation for node: %s (no VPN address)", *name);
	}
	return true;
}

/*
 * Handle CSR during join process
 */
bool handle_join_csr(const char *csr_pem, const char *fingerprint, char **cert_pem) {
	if(!csr_pem || !cert_pem) {
		return false;
	}

	/* Sign CSR with CA */
	if(!sign_csr(confbase, csr_pem, cert_pem)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign CSR");
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Signed certificate for node with fingerprint: %s",
	       fingerprint ? fingerprint : "unknown");

	return true;
}

/* External QUIC functions */
extern bool quic_connection_open(connection_t *c, const char *address, uint16_t port);
extern bool quic_connection_start(connection_t *c);

/*
 * Process join request from control socket
 * This initiates a QUIC connection to the inviter
 */
int process_join_request(connection_t *ctrl, const char *host, const char *port_str, const char *token) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Join request: host=%s port=%s token=%s", host, port_str, token);

	/* Send status: connecting */
	send_request(ctrl, "%d %d %d %s", CONTROL, REQ_JOIN, 1, "Connecting to inviter...");

	/* Parse port */
	uint16_t port = 443;
	if(port_str && port_str[0]) {
		port = atoi(port_str);
		if(port == 0) port = 443;
	}

	/* Resolve address */
	char port_buf[16];
	snprintf(port_buf, sizeof(port_buf), "%u", port);
	sockaddr_t addr = str2sockaddr(host, port_buf);
	if(addr.sa.sa_family == AF_UNKNOWN) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot resolve address: %s", host);
		send_request(ctrl, "%d %d %d %s", CONTROL, REQ_JOIN, -1, "Cannot resolve address");
		return -1;
	}

	/* Create invitation connection */
	connection_t *c = new_connection();
	c->name = xstrdup("<invitation>");
	c->hostname = xstrdup(host);
	c->address = addr;
	c->status.invitation = true;
	c->invitation_token = xstrdup(token);
	c->control_connection = ctrl;
	c->port = port;
	c->allow_request = INVITE_DATA; /* Expect INVITE_DATA after we send INVITE_JOIN */

	/* Open QUIC connection */
	if(!quic_connection_open(c, host, port)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open QUIC connection to %s:%d", host, port);
		send_request(ctrl, "%d %d %d %s", CONTROL, REQ_JOIN, -1, "Failed to open connection");
		free(c->invitation_token);
		free_connection(c);
		return -1;
	}

	/* Add to connection list */
	connection_add(c);

	/* Start QUIC connection */
	if(!quic_connection_start(c)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start QUIC connection to %s:%d", host, port);
		send_request(ctrl, "%d %d %d %s", CONTROL, REQ_JOIN, -1, "Failed to start connection");
		connection_del(c);
		return -1;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Invitation connection started to %s:%d", host, port);

	/* The rest happens asynchronously:
	 * 1. QUIC connection callback will be called when connected
	 * 2. We need to send INVITE_JOIN when connected
	 * 3. Handle INVITE_DATA, send INVITE_CSR, handle INVITE_CERT
	 *
	 * For now, return success - the async callbacks will handle the rest
	 * and send status updates to the control connection
	 */
	return 0;
}

/*
 * CLI command: tinc invite <name>
 * Connects to local tincd via control socket
 */
int cmd_invite(int argc, char *argv[]) {
	if(argc < 2) {
		fprintf(stderr, "Usage: tinc invite <name>\n");
		return 1;
	}

	/* TODO: Connect to tincd control socket and send REQ_INVITE */
	fprintf(stderr, "Invite command - connecting to tincd...\n");
	fprintf(stderr, "Node name: %s\n", argv[1]);

	/* This will be implemented in tincctl.c */
	return 1;
}

/*
 * CLI command: tinc join <url>
 * Connects to local tincd via control socket
 */
int cmd_join(int argc, char *argv[]) {
	if(argc < 2) {
		fprintf(stderr, "Usage: tinc join <url>\n");
		return 1;
	}

	/* TODO: Parse URL and connect to tincd control socket */
	fprintf(stderr, "Join command - connecting to tincd...\n");
	fprintf(stderr, "URL: %s\n", argv[1]);

	/* This will be implemented in tincctl.c */
	return 1;
}
