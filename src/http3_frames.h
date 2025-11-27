/*
    http3_frames.h -- HTTP/3 frame encoding/decoding for traffic masquerading
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

#ifndef TINC_HTTP3_FRAMES_H
#define TINC_HTTP3_FRAMES_H

#include "system.h"
#include <stdint.h>
#include <stdbool.h>

/* HTTP/3 Frame Types (RFC 9114) */
#define HTTP3_FRAME_DATA       0x00
#define HTTP3_FRAME_HEADERS    0x01
#define HTTP3_FRAME_SETTINGS   0x04

/* HTTP/3 Masquerading Configuration */
#define HTTP3_MAX_HEADER_SIZE  2048
#define HTTP3_MAX_FRAME_SIZE   16384

/* User-Agent strings for different browsers */
typedef enum {
	UA_CHROME,
	UA_FIREFOX,
	UA_SAFARI,
	UA_EDGE,
	UA_RANDOM
} user_agent_type_t;

/* HTTP methods */
typedef enum {
	HTTP_GET,
	HTTP_POST
} http_method_t;

/* HTTP/3 frame header structure */
typedef struct {
	uint8_t type;
	uint64_t length;
} http3_frame_header_t;

/* HTTP/3 masquerading configuration */
typedef struct {
	bool enabled;                    /* Enable HTTP/3 masquerading */
	user_agent_type_t user_agent;    /* User-Agent type */
	char *custom_user_agent;         /* Custom User-Agent string */
	char **url_paths;                /* Realistic URL paths */
	int url_path_count;              /* Number of URL paths */
} http3_config_t;

/* Global HTTP/3 configuration */
extern http3_config_t http3_config;

/* HTTP/3 frame encoding functions */
extern size_t http3_encode_varint(uint64_t value, uint8_t *buffer, size_t buffer_size);
extern size_t http3_decode_varint(const uint8_t *buffer, size_t buffer_size, uint64_t *value);

extern size_t http3_encode_frame_header(uint8_t type, uint64_t length, uint8_t *buffer, size_t buffer_size);
extern bool http3_decode_frame_header(const uint8_t *buffer, size_t buffer_size, http3_frame_header_t *header, size_t *header_len);

/* HTTP/3 DATA frame */
extern size_t http3_create_data_frame(const uint8_t *data, size_t data_len, uint8_t *frame, size_t frame_size);
extern bool http3_parse_data_frame(const uint8_t *frame, size_t frame_len, uint8_t **data, size_t *data_len);

/* HTTP/3 HEADERS frame (simplified, no QPACK compression) */
extern size_t http3_create_headers_frame(http_method_t method, const char *path, const char *authority,
        uint8_t *frame, size_t frame_size);
extern size_t http3_parse_headers_frame(const uint8_t *frame, size_t frame_len);

/* Realistic HTTP traffic generation */
extern const char *http3_get_user_agent(user_agent_type_t type);
extern const char *http3_get_random_path(void);
extern void http3_init_url_paths(void);
extern void http3_cleanup_url_paths(void);

/* Helper functions */
extern bool http3_should_send_headers(void);  /* Decide when to send HEADERS frame */
extern void http3_update_headers_timer(void); /* Update last headers send time */

#endif /* TINC_HTTP3_FRAMES_H */
