/*
    http3_frames.c -- HTTP/3 frame encoding/decoding for traffic masquerading
    Copyright (C) 2025 Tinc VPN Project
*/

#include "http3_frames.h"
#include "logger.h"
#include "xalloc.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

/* Global HTTP/3 configuration */
http3_config_t http3_config = {
	.enabled = false,
	.user_agent = UA_CHROME,
	.custom_user_agent = NULL,
	.url_paths = NULL,
	.url_path_count = 0
};

/* Last time HEADERS frame was sent */
static time_t last_headers_time = 0;

/* User-Agent strings for different browsers (realistic, current versions) */
static const char *user_agent_strings[] = {
	[UA_CHROME] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	[UA_FIREFOX] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	[UA_SAFARI] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	[UA_EDGE] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
};

/* Default realistic URL paths (common web resources) */
static const char *default_url_paths[] = {
	"/api/v1/data",
	"/static/js/main.js",
	"/static/css/style.css",
	"/images/logo.png",
	"/fonts/roboto.woff2",
	"/api/user/profile",
	"/api/messages",
	"/api/notifications",
	"/assets/bundle.js",
	"/metrics"
};

#define DEFAULT_URL_PATH_COUNT (sizeof(default_url_paths) / sizeof(default_url_paths[0]))

/*
 * Encode variable-length integer (QUIC varint encoding)
 * Returns: number of bytes written, or 0 on error
 */
size_t http3_encode_varint(uint64_t value, uint8_t *buffer, size_t buffer_size) {
	if(!buffer || buffer_size == 0) {
		return 0;
	}

	if(value < 64) {
		/* 1-byte encoding: 00xxxxxx */
		if(buffer_size < 1) {
			return 0;
		}

		buffer[0] = (uint8_t)value;
		return 1;
	} else if(value < 16384) {
		/* 2-byte encoding: 01xxxxxx xxxxxxxx */
		if(buffer_size < 2) {
			return 0;
		}

		buffer[0] = 0x40 | (uint8_t)(value >> 8);
		buffer[1] = (uint8_t)value;
		return 2;
	} else if(value < 1073741824) {
		/* 4-byte encoding: 10xxxxxx ... */
		if(buffer_size < 4) {
			return 0;
		}

		buffer[0] = 0x80 | (uint8_t)(value >> 24);
		buffer[1] = (uint8_t)(value >> 16);
		buffer[2] = (uint8_t)(value >> 8);
		buffer[3] = (uint8_t)value;
		return 4;
	} else {
		/* 8-byte encoding: 11xxxxxx ... */
		if(buffer_size < 8) {
			return 0;
		}

		buffer[0] = 0xC0 | (uint8_t)(value >> 56);
		buffer[1] = (uint8_t)(value >> 48);
		buffer[2] = (uint8_t)(value >> 40);
		buffer[3] = (uint8_t)(value >> 32);
		buffer[4] = (uint8_t)(value >> 24);
		buffer[5] = (uint8_t)(value >> 16);
		buffer[6] = (uint8_t)(value >> 8);
		buffer[7] = (uint8_t)value;
		return 8;
	}
}

/*
 * Decode variable-length integer
 * Returns: number of bytes consumed, or 0 on error
 */
size_t http3_decode_varint(const uint8_t *buffer, size_t buffer_size, uint64_t *value) {
	if(!buffer || !value || buffer_size == 0) {
		return 0;
	}

	uint8_t prefix = buffer[0] >> 6;

	switch(prefix) {
	case 0:  /* 1-byte */
		*value = buffer[0] & 0x3F;
		return 1;

	case 1:  /* 2-byte */
		if(buffer_size < 2) {
			return 0;
		}

		*value = ((uint64_t)(buffer[0] & 0x3F) << 8) | buffer[1];
		return 2;

	case 2:  /* 4-byte */
		if(buffer_size < 4) {
			return 0;
		}

		*value = ((uint64_t)(buffer[0] & 0x3F) << 24) |
		         ((uint64_t)buffer[1] << 16) |
		         ((uint64_t)buffer[2] << 8) |
		         buffer[3];
		return 4;

	case 3:  /* 8-byte */
		if(buffer_size < 8) {
			return 0;
		}

		*value = ((uint64_t)(buffer[0] & 0x3F) << 56) |
		         ((uint64_t)buffer[1] << 48) |
		         ((uint64_t)buffer[2] << 40) |
		         ((uint64_t)buffer[3] << 32) |
		         ((uint64_t)buffer[4] << 24) |
		         ((uint64_t)buffer[5] << 16) |
		         ((uint64_t)buffer[6] << 8) |
		         buffer[7];
		return 8;

	default:
		return 0;
	}
}

/*
 * Encode HTTP/3 frame header (type + length)
 */
size_t http3_encode_frame_header(uint8_t type, uint64_t length, uint8_t *buffer, size_t buffer_size) {
	if(!buffer || buffer_size < 2) {
		return 0;
	}

	size_t offset = 0;

	/* Encode frame type */
	size_t type_len = http3_encode_varint(type, buffer + offset, buffer_size - offset);

	if(type_len == 0) {
		return 0;
	}

	offset += type_len;

	/* Encode frame length */
	size_t length_len = http3_encode_varint(length, buffer + offset, buffer_size - offset);

	if(length_len == 0) {
		return 0;
	}

	offset += length_len;

	return offset;
}

/*
 * Decode HTTP/3 frame header
 */
bool http3_decode_frame_header(const uint8_t *buffer, size_t buffer_size,
                                http3_frame_header_t *header, size_t *header_len) {
	if(!buffer || !header || !header_len || buffer_size < 2) {
		return false;
	}

	size_t offset = 0;
	uint64_t type, length;

	/* Decode frame type */
	size_t type_len = http3_decode_varint(buffer + offset, buffer_size - offset, &type);

	if(type_len == 0) {
		return false;
	}

	offset += type_len;

	/* Decode frame length */
	size_t length_len = http3_decode_varint(buffer + offset, buffer_size - offset, &length);

	if(length_len == 0) {
		return false;
	}

	offset += length_len;

	header->type = (uint8_t)type;
	header->length = length;
	*header_len = offset;

	return true;
}

/*
 * Create HTTP/3 DATA frame
 * Frame format: Type (varint) + Length (varint) + Data
 */
size_t http3_create_data_frame(const uint8_t *data, size_t data_len, uint8_t *frame, size_t frame_size) {
	if(!data || !frame || data_len == 0 || frame_size < data_len + 16) {
		return 0;
	}

	/* Encode frame header */
	size_t header_len = http3_encode_frame_header(HTTP3_FRAME_DATA, data_len, frame, frame_size);

	if(header_len == 0) {
		return 0;
	}

	/* Copy data payload */
	memcpy(frame + header_len, data, data_len);

	return header_len + data_len;
}

/*
 * Parse HTTP/3 DATA frame
 */
bool http3_parse_data_frame(const uint8_t *frame, size_t frame_len, uint8_t **data, size_t *data_len) {
	if(!frame || !data || !data_len || frame_len < 2) {
		return false;
	}

	http3_frame_header_t header;
	size_t header_len;

	if(!http3_decode_frame_header(frame, frame_len, &header, &header_len)) {
		return false;
	}

	if(header.type != HTTP3_FRAME_DATA) {
		/* Not a DATA frame - this is normal when checking frame type (might be HEADERS) */
		/* Use DEBUG level instead of WARNING since this is expected during frame type detection */
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Not a DATA frame (type %d), trying other frame types", header.type);
		return false;
	}

	if(header_len + header.length > frame_len) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "DATA frame length mismatch");
		return false;
	}

	*data = (uint8_t *)(frame + header_len);
	*data_len = header.length;

	return true;
}

/*
 * Create HTTP/3 HEADERS frame (simplified, no QPACK compression)
 * This creates a realistic HTTP request with common headers
 */
size_t http3_create_headers_frame(http_method_t method, const char *path, const char *authority,
                                   uint8_t *frame, size_t frame_size) {
	if(!path || !authority || !frame || frame_size < HTTP3_MAX_HEADER_SIZE) {
		return 0;
	}

	/* Build pseudo-headers and real headers as plain text (simplified) */
	char headers[HTTP3_MAX_HEADER_SIZE];
	int offset = 0;
	int remaining = sizeof(headers);
	int written;

	/* Pseudo-headers (HTTP/3 specific) */
	const char *method_str = (method == HTTP_GET) ? "GET" : "POST";

	written = snprintf(headers + offset, remaining,
	                   ":method: %s\r\n"
	                   ":scheme: https\r\n"
	                   ":authority: %s\r\n"
	                   ":path: %s\r\n",
	                   method_str, authority, path);
	if(written < 0 || written >= remaining) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "HTTP/3 HEADERS buffer overflow in pseudo-headers");
		return 0;
	}
	offset += written;
	remaining -= written;

	/* Real HTTP headers */
	const char *user_agent = http3_get_user_agent(http3_config.user_agent);

	written = snprintf(headers + offset, remaining,
	                   "user-agent: %s\r\n"
	                   "accept: text/html,application/json,*/*\r\n"
	                   "accept-language: en-US,en;q=0.9\r\n"
	                   "accept-encoding: gzip, deflate, br\r\n"
	                   "cache-control: no-cache\r\n"
	                   "sec-fetch-dest: empty\r\n"
	                   "sec-fetch-mode: cors\r\n"
	                   "sec-fetch-site: same-origin\r\n",
	                   user_agent);
	if(written < 0 || written >= remaining) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "HTTP/3 HEADERS buffer overflow in real headers");
		return 0;
	}
	offset += written;
	remaining -= written;

	/* Add Content-Type for POST */
	if(method == HTTP_POST) {
		written = snprintf(headers + offset, remaining,
		                   "content-type: application/octet-stream\r\n");
		if(written < 0 || written >= remaining) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "HTTP/3 HEADERS buffer overflow in content-type");
			return 0;
		}
		offset += written;
		remaining -= written;
	}

	/* End headers */
	written = snprintf(headers + offset, remaining, "\r\n");
	if(written < 0 || written >= remaining) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "HTTP/3 HEADERS buffer overflow in end marker");
		return 0;
	}
	offset += written;

	/* Create HEADERS frame */
	size_t header_frame_len = http3_encode_frame_header(HTTP3_FRAME_HEADERS, offset,
	                          frame, frame_size);

	if(header_frame_len == 0) {
		return 0;
	}

	/* Copy headers payload */
	memcpy(frame + header_frame_len, headers, offset);

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Created HTTP/3 HEADERS frame: %s %s (%d bytes)",
	       method_str, path, (int)(header_frame_len + offset));

	return header_frame_len + offset;
}

/*
 * Parse HTTP/3 HEADERS frame (basic validation)
 */
size_t http3_parse_headers_frame(const uint8_t *frame, size_t frame_len) {
	if(!frame || frame_len < 2) {
		return 0;
	}

	http3_frame_header_t header;
	size_t header_len;

	if(!http3_decode_frame_header(frame, frame_len, &header, &header_len)) {
		return 0;
	}

	if(header.type != HTTP3_FRAME_HEADERS) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Expected HEADERS frame, got type %d", header.type);
		return 0;
	}

	/* Validate frame is complete */
	size_t total_frame_size = header_len + header.length;
	if(total_frame_size > frame_len) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "HEADERS frame incomplete: need %zu bytes, have %zu",
		       total_frame_size, frame_len);
		return 0;
	}

	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Received HTTP/3 HEADERS frame (total %zu bytes: header=%zu + payload=%lu)",
	       total_frame_size, header_len, header.length);
	return total_frame_size;
}

/*
 * Get User-Agent string
 */
const char *http3_get_user_agent(user_agent_type_t type) {
	if(http3_config.custom_user_agent) {
		return http3_config.custom_user_agent;
	}

	if(type == UA_RANDOM) {
		type = rand() % 4;  /* Random between CHROME, FIREFOX, SAFARI, EDGE */
	}

	return user_agent_strings[type];
}

/*
 * Get random URL path
 */
const char *http3_get_random_path(void) {
	if(http3_config.url_paths && http3_config.url_path_count > 0) {
		int index = rand() % http3_config.url_path_count;
		return http3_config.url_paths[index];
	}

	int index = rand() % DEFAULT_URL_PATH_COUNT;
	return default_url_paths[index];
}

/*
 * Initialize URL paths from default list
 */
void http3_init_url_paths(void) {
	if(http3_config.url_paths == NULL) {
		http3_config.url_path_count = DEFAULT_URL_PATH_COUNT;
		http3_config.url_paths = xmalloc(DEFAULT_URL_PATH_COUNT * sizeof(char *));

		for(int i = 0; i < DEFAULT_URL_PATH_COUNT; i++) {
			http3_config.url_paths[i] = xstrdup(default_url_paths[i]);
		}

		logger(DEBUG_PROTOCOL, LOG_INFO, "HTTP/3 initialized with %d default URL paths", DEFAULT_URL_PATH_COUNT);
	}
}

/*
 * Cleanup URL paths
 */
void http3_cleanup_url_paths(void) {
	if(http3_config.url_paths) {
		for(int i = 0; i < http3_config.url_path_count; i++) {
			free(http3_config.url_paths[i]);
		}

		free(http3_config.url_paths);
		http3_config.url_paths = NULL;
		http3_config.url_path_count = 0;
	}

	if(http3_config.custom_user_agent) {
		free(http3_config.custom_user_agent);
		http3_config.custom_user_agent = NULL;
	}
}

/*
 * Decide when to send HEADERS frame
 * Send HEADERS periodically to mimic browser behavior
 */
bool http3_should_send_headers(void) {
	extern int quic_http3_headers_interval;
	time_t now = time(NULL);

	/* Use configurable interval with +/- 20% jitter for randomness */
	int jitter = (quic_http3_headers_interval * 20) / 100;  /* 20% of interval */
	int min_interval = quic_http3_headers_interval - jitter;
	int max_interval = quic_http3_headers_interval + jitter;
	int interval = min_interval + (rand() % (max_interval - min_interval + 1));

	if(last_headers_time == 0 || (now - last_headers_time >= interval)) {
		return true;
	}

	return false;
}

/*
 * Update headers timer
 */
void http3_update_headers_timer(void) {
	last_headers_time = time(NULL);
}
