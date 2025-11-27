/*
    hosts_json.c -- JSON-based host configuration
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
#include <ctype.h>
#include <errno.h>

#include "hosts_json.h"
#include "logger.h"
#include "xalloc.h"

/* Global hosts database */
hosts_db_t *hosts_db = NULL;

/*
 * Simple JSON parsing helpers
 * We use a minimal hand-written parser to avoid external dependencies
 */

/* Skip whitespace */
static const char *skip_ws(const char *p) {
	while(*p && isspace((unsigned char)*p)) p++;
	return p;
}

/* Parse a JSON string (including quotes) */
static const char *parse_string(const char *p, char *out, size_t outsize) {
	p = skip_ws(p);
	if(*p != '"') return NULL;
	p++;

	size_t i = 0;
	while(*p && *p != '"' && i < outsize - 1) {
		if(*p == '\\' && *(p + 1)) {
			p++;
			switch(*p) {
				case 'n': out[i++] = '\n'; break;
				case 't': out[i++] = '\t'; break;
				case '\\': out[i++] = '\\'; break;
				case '"': out[i++] = '"'; break;
				default: out[i++] = *p; break;
			}
		} else {
			out[i++] = *p;
		}
		p++;
	}
	out[i] = '\0';

	if(*p == '"') p++;
	return p;
}

/* Parse a JSON number */
static const char *parse_number(const char *p, int *out) {
	p = skip_ws(p);
	char buf[32];
	size_t i = 0;
	while(*p && (isdigit((unsigned char)*p) || *p == '-') && i < sizeof(buf) - 1) {
		buf[i++] = *p++;
	}
	buf[i] = '\0';
	*out = atoi(buf);
	return p;
}

/* Find a key in JSON object (returns pointer after colon) */
static const char *find_key(const char *p, const char *key) {
	char buf[128];
	p = skip_ws(p);

	/* Skip opening brace if present */
	if(*p == '{') p++;

	while(*p) {
		p = skip_ws(p);
		if(*p == '}') return NULL; /* End of object */
		if(*p == '"') {
			const char *next = parse_string(p, buf, sizeof(buf));
			if(!next) return NULL;
			p = skip_ws(next);
			if(*p == ':') {
				p++;
				if(strcmp(buf, key) == 0) {
					return p;
				}
			}
		}
		/* Skip to next key or end */
		int depth = 0;
		while(*p) {
			if(*p == '{' || *p == '[') depth++;
			else if(*p == '}' || *p == ']') {
				if(depth == 0) break;
				depth--;
			} else if(*p == ',' && depth == 0) {
				p++;
				break;
			}
			p++;
		}
	}
	return NULL;
}

/* Parse a single host entry */
static bool parse_host_entry(const char *json, host_entry_t *host) {
	const char *p;

	/* Save next pointer before clearing (it was set by hosts_db_add) */
	host_entry_t *saved_next = host->next;

	memset(host, 0, sizeof(*host));
	host->port = 443; /* Default port */

	/* Restore next pointer to maintain linked list */
	host->next = saved_next;

	/* Parse addresses array */
	p = find_key(json, "addresses");
	if(p) {
		p = skip_ws(p);
		if(*p == '[') {
			p++;
			while(*p && *p != ']' && host->address_count < MAX_HOST_ADDRESSES) {
				p = skip_ws(p);
				if(*p == '"') {
					p = parse_string(p, host->addresses[host->address_count], MAX_ADDRESS_LEN);
					if(p) host->address_count++;
				}
				p = skip_ws(p);
				if(*p == ',') p++;
			}
		}
	}

	/* Parse port */
	p = find_key(json, "port");
	if(p) {
		int port;
		parse_number(p, &port);
		host->port = (uint16_t)port;
	}

	/* Parse subnet */
	p = find_key(json, "subnet");
	if(p) {
		parse_string(p, host->subnet, MAX_SUBNET_LEN);
	}

	/* Parse vpn_address */
	p = find_key(json, "vpn_address");
	if(p) {
		parse_string(p, host->vpn_address, MAX_ADDRESS_LEN);
	}

	return true;
}

/* Parse hosts.json content */
static bool parse_hosts_json(const char *json) {
	const char *p = json;

	/* Find "nodes" object */
	p = find_key(p, "nodes");
	if(!p) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "No 'nodes' key in hosts.json");
		return true; /* Empty is OK */
	}

	p = skip_ws(p);
	if(*p != '{') {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid 'nodes' value in hosts.json");
		return false;
	}
	p++;

	/* Parse each host entry */
	while(*p) {
		p = skip_ws(p);
		if(*p == '}') break; /* End of nodes */

		/* Parse host name */
		char name[MAX_HOST_NAME_LEN];
		if(*p != '"') {
			p++;
			continue;
		}
		p = parse_string(p, name, sizeof(name));
		if(!p || !name[0]) continue;

		p = skip_ws(p);
		if(*p != ':') continue;
		p++;

		/* Find host object boundaries */
		p = skip_ws(p);
		if(*p != '{') continue;

		const char *obj_start = p;
		int depth = 1;
		p++;
		while(*p && depth > 0) {
			if(*p == '{') depth++;
			else if(*p == '}') depth--;
			p++;
		}

		/* Parse host entry */
		size_t obj_len = p - obj_start;
		char *obj = xmalloc(obj_len + 1);
		memcpy(obj, obj_start, obj_len);
		obj[obj_len] = '\0';

		host_entry_t *host = hosts_db_add(name);
		if(host) {
			parse_host_entry(obj, host);
			strncpy(host->name, name, MAX_HOST_NAME_LEN - 1);
		}

		free(obj);

		/* Skip comma */
		p = skip_ws(p);
		if(*p == ',') p++;
	}

	return true;
}

/*
 * Initialize hosts database
 */
bool hosts_db_init(const char *confbase) {
	if(hosts_db) {
		hosts_db_cleanup(false);
	}

	hosts_db = xzalloc(sizeof(hosts_db_t));
	snprintf(hosts_db->filepath, sizeof(hosts_db->filepath), "%s/hosts.json", confbase);

	return hosts_db_load();
}

/*
 * Cleanup hosts database
 */
void hosts_db_cleanup(bool save) {
	if(!hosts_db) return;

	if(save && hosts_db->modified) {
		hosts_db_save();
	}

	/* Free all hosts */
	host_entry_t *h = hosts_db->hosts;
	while(h) {
		host_entry_t *next = h->next;
		free(h);
		h = next;
	}

	free(hosts_db);
	hosts_db = NULL;
}

/*
 * Load hosts from JSON file
 */
bool hosts_db_load(void) {
	if(!hosts_db) return false;

	FILE *f = fopen(hosts_db->filepath, "r");
	if(!f) {
		if(errno == ENOENT) {
			logger(DEBUG_PROTOCOL, LOG_INFO, "hosts.json not found, starting with empty database");
			return true;
		}
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot open %s: %s", hosts_db->filepath, strerror(errno));
		return false;
	}

	/* Read entire file */
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if(size <= 0 || size > 1024 * 1024) { /* Max 1MB */
		fclose(f);
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid hosts.json size: %ld", size);
		return false;
	}

	char *content = xmalloc(size + 1);
	size_t read_len = fread(content, 1, size, f);
	fclose(f);
	content[read_len] = '\0';

	bool result = parse_hosts_json(content);
	free(content);

	if(result) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "Loaded %d hosts from hosts.json", hosts_db->count);
	}

	return result;
}

/*
 * Save hosts to JSON file
 */
bool hosts_db_save(void) {
	if(!hosts_db) return false;

	FILE *f = fopen(hosts_db->filepath, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot write %s: %s", hosts_db->filepath, strerror(errno));
		return false;
	}

	fprintf(f, "{\n");
	fprintf(f, "  \"nodes\": {\n");

	bool first = true;
	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		if(!first) fprintf(f, ",\n");
		first = false;

		fprintf(f, "    \"%s\": {\n", h->name);

		/* Addresses array */
		fprintf(f, "      \"addresses\": [");
		for(int i = 0; i < h->address_count; i++) {
			if(i > 0) fprintf(f, ", ");
			fprintf(f, "\"%s\"", h->addresses[i]);
		}
		fprintf(f, "],\n");

		/* Port */
		fprintf(f, "      \"port\": %d,\n", h->port);

		/* Subnet */
		fprintf(f, "      \"subnet\": \"%s\",\n", h->subnet);

		/* VPN address */
		fprintf(f, "      \"vpn_address\": \"%s\"\n", h->vpn_address);

		fprintf(f, "    }");
	}

	fprintf(f, "\n  }\n");
	fprintf(f, "}\n");

	fclose(f);
	hosts_db->modified = false;

	logger(DEBUG_PROTOCOL, LOG_INFO, "Saved %d hosts to hosts.json", hosts_db->count);
	return true;
}

/*
 * Add or update a host entry
 */
host_entry_t *hosts_db_add(const char *name) {
	if(!hosts_db || !name) return NULL;

	/* Check if host already exists */
	host_entry_t *h = hosts_db_find(name);
	if(h) return h;

	/* Create new host */
	h = xzalloc(sizeof(host_entry_t));
	strncpy(h->name, name, MAX_HOST_NAME_LEN - 1);
	h->port = 443;

	/* Add to list */
	h->next = hosts_db->hosts;
	hosts_db->hosts = h;
	hosts_db->count++;
	hosts_db->modified = true;

	return h;
}

/*
 * Find host by name
 */
host_entry_t *hosts_db_find(const char *name) {
	if(!hosts_db || !name) return NULL;

	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		if(strcasecmp(h->name, name) == 0) {
			return h;
		}
	}
	return NULL;
}

/*
 * Remove host by name
 */
bool hosts_db_remove(const char *name) {
	if(!hosts_db || !name) return false;

	host_entry_t **pp = &hosts_db->hosts;
	while(*pp) {
		if(strcasecmp((*pp)->name, name) == 0) {
			host_entry_t *to_remove = *pp;
			*pp = to_remove->next;
			free(to_remove);
			hosts_db->count--;
			hosts_db->modified = true;
			return true;
		}
		pp = &(*pp)->next;
	}
	return false;
}

/*
 * Find host by VPN address
 */
const char *hosts_db_find_by_vpn_address(const char *vpn_address) {
	if(!hosts_db || !vpn_address) return NULL;

	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		if(h->vpn_address[0] && strcmp(h->vpn_address, vpn_address) == 0) {
			return h->name;
		}
	}
	return NULL;
}

/*
 * Find host by external address
 */
const char *hosts_db_find_by_address(const char *address) {
	if(!hosts_db || !address) return NULL;

	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		for(int i = 0; i < h->address_count; i++) {
			if(strcmp(h->addresses[i], address) == 0) {
				return h->name;
			}
		}
	}
	return NULL;
}

/*
 * Add address to host
 */
bool host_add_address(host_entry_t *host, const char *address) {
	if(!host || !address) return false;
	if(host->address_count >= MAX_HOST_ADDRESSES) return false;

	/* Check for duplicate */
	for(int i = 0; i < host->address_count; i++) {
		if(strcmp(host->addresses[i], address) == 0) {
			return true; /* Already exists */
		}
	}

	strncpy(host->addresses[host->address_count], address, MAX_ADDRESS_LEN - 1);
	host->address_count++;

	if(hosts_db) hosts_db->modified = true;
	return true;
}

/*
 * Set host's VPN address and subnet
 */
void host_set_vpn_address(host_entry_t *host, const char *vpn_address, int prefix) {
	if(!host || !vpn_address) return;

	strncpy(host->vpn_address, vpn_address, MAX_ADDRESS_LEN - 1);

	/* Build subnet (e.g., "10.0.0.2/32") */
	snprintf(host->subnet, MAX_SUBNET_LEN, "%s/%d", vpn_address, prefix > 0 ? prefix : 32);

	if(hosts_db) hosts_db->modified = true;
}

/*
 * Iterate over all hosts
 */
void hosts_db_foreach(hosts_iterator_cb callback, void *ctx) {
	if(!hosts_db || !callback) return;

	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		if(!callback(h, ctx)) break;
	}
}

/*
 * Get hosts count
 */
int hosts_db_count(void) {
	return hosts_db ? hosts_db->count : 0;
}

/*
 * Debug: dump hosts database to log
 */
void hosts_db_dump(void) {
	if(!hosts_db) {
		logger(DEBUG_ALWAYS, LOG_INFO, "hosts_db: NULL");
		return;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "hosts_db: %d hosts", hosts_db->count);
	for(host_entry_t *h = hosts_db->hosts; h; h = h->next) {
		logger(DEBUG_ALWAYS, LOG_INFO, "  %s: vpn=%s subnet=%s port=%d addrs=%d",
		       h->name, h->vpn_address, h->subnet, h->port, h->address_count);
		for(int i = 0; i < h->address_count; i++) {
			logger(DEBUG_ALWAYS, LOG_INFO, "    addr[%d]: %s", i, h->addresses[i]);
		}
	}
}
