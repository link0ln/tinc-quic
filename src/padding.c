/*
    padding.c -- Packet padding for DPI evasion
    Copyright (C) 2025 Tinc VPN Project
*/

#include <stdarg.h>
#include "padding.h"
#include "logger.h"
#include "xalloc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Global padding configuration */
padding_config_t padding_config = {
	.mode = PADDING_OFF,
	.min_size = 0,
	.max_size = 128,
	.buckets = NULL,
	.bucket_count = 0,
	.small_packets_only = false,
	.threshold = 512
};

/* Default bucket sizes (common MTU values) */
static int default_buckets[] = {512, 1024, 1500};
#define DEFAULT_BUCKET_COUNT (sizeof(default_buckets) / sizeof(default_buckets[0]))

/*
 * Initialize padding configuration with defaults
 */
void padding_init(void) {
	/* Set default buckets */
	if(padding_config.buckets == NULL && padding_config.mode == PADDING_BUCKETS) {
		padding_config.bucket_count = DEFAULT_BUCKET_COUNT;
		padding_config.buckets = xmalloc(DEFAULT_BUCKET_COUNT * sizeof(int));
		memcpy(padding_config.buckets, default_buckets, DEFAULT_BUCKET_COUNT * sizeof(int));
		logger(DEBUG_PROTOCOL, LOG_INFO, "Padding: initialized with %d default buckets", DEFAULT_BUCKET_COUNT);
	}
}

/*
 * Cleanup padding configuration
 */
void padding_cleanup(void) {
	if(padding_config.buckets) {
		free(padding_config.buckets);
		padding_config.buckets = NULL;
		padding_config.bucket_count = 0;
	}
}

/*
 * Calculate padding size based on configuration
 */
size_t padding_calculate_size(size_t data_len) {
	/* Check if padding is disabled */
	if(padding_config.mode == PADDING_OFF) {
		return 0;
	}

	/* Check if we should only pad small packets */
	if(padding_config.small_packets_only && data_len >= padding_config.threshold) {
		return 0;
	}

	/* CRITICAL: Don't pad large packets that are close to MTU
	 * QUIC datagram max payload is typically ~1200 bytes (Ethernet MTU 1500 - IP/UDP/QUIC headers)
	 * With HTTP/3 framing overhead (~3-10 bytes), we need to stay well below to avoid
	 * DatagramSend failures (error 0x16). Conservative limit: 1150 bytes */
	if(data_len > 1150) {
		return 0;
	}

	size_t padding_size = 0;

	switch(padding_config.mode) {
	case PADDING_RANDOM: {
		/* Random padding between min and max */
		if(padding_config.max_size > padding_config.min_size) {
			padding_size = padding_config.min_size +
			               (rand() % (padding_config.max_size - padding_config.min_size + 1));
		} else {
			padding_size = padding_config.min_size;
		}

		break;
	}

	case PADDING_BUCKETS: {
		/* Round up to nearest bucket size */
		if(padding_config.buckets == NULL || padding_config.bucket_count == 0) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Padding: BUCKETS mode but no buckets configured");
			return 0;
		}

		/* Find smallest bucket that fits data + header (3 bytes) */
		size_t total_size = data_len + 3;  /* data + magic + length */

		for(int i = 0; i < padding_config.bucket_count; i++) {
			if(padding_config.buckets[i] >= total_size) {
				padding_size = padding_config.buckets[i] - total_size;
				break;
			}
		}

		/* If data is larger than all buckets, use largest bucket's strategy */
		if(padding_size == 0 && padding_config.bucket_count > 0) {
			/* Add some random padding anyway */
			padding_size = rand() % 64;
		}

		break;
	}

	default:
		return 0;
	}

	/* Sanity check */
	if(padding_size > MAX_PADDING_SIZE) {
		padding_size = MAX_PADDING_SIZE;
	}

	return padding_size;
}

/*
 * Add padding to a packet
 *
 * Packet format: [magic (1)] [original_len (2)] [original_data] [random_padding]
 */
size_t padding_add(const uint8_t *data, size_t data_len,
                   uint8_t *output, size_t output_size) {
	if(!data || !output || data_len == 0) {
		return 0;
	}

	/* Calculate padding size */
	size_t padding_size = padding_calculate_size(data_len);

	/* If no padding needed, return 0 to signal caller to use original data */
	if(padding_size == 0) {
		return 0;
	}

	/* Check output buffer size */
	size_t total_size = 1 + 2 + data_len + padding_size;  /* magic + len + data + padding */

	if(output_size < total_size) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Padding: output buffer too small (%zu < %zu)",
		       output_size, total_size);
		return 0;
	}

	/* Build padded packet */
	size_t offset = 0;

	/* Magic byte */
	output[offset++] = PADDING_MAGIC;

	/* Original length (2 bytes, big-endian) */
	output[offset++] = (data_len >> 8) & 0xFF;
	output[offset++] = data_len & 0xFF;

	/* Original data */
	memcpy(output + offset, data, data_len);
	offset += data_len;

	/* Random padding */
	for(size_t i = 0; i < padding_size; i++) {
		output[offset++] = rand() & 0xFF;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Padding: added %zu bytes to %zu byte packet (total: %zu)",
	       padding_size, data_len, total_size);

	return total_size;
}

/*
 * Remove padding from a packet
 *
 * Returns pointer to original data within input buffer (zero-copy)
 */
bool padding_remove(const uint8_t *data, size_t data_len,
                    const uint8_t **output, size_t *output_len) {
	if(!data || !output || !output_len || data_len == 0) {
		return false;
	}

	/* Check if packet has padding magic */
	if(data_len < 3 || data[0] != PADDING_MAGIC) {
		/* Not a padded packet - return original data */
		*output = data;
		*output_len = data_len;
		return true;
	}

	/* Extract original length */
	size_t original_len = ((size_t)data[1] << 8) | data[2];

	/* Validate length */
	if(original_len == 0 || original_len + 3 > data_len) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Padding: invalid original length %zu (packet: %zu)",
		       original_len, data_len);
		return false;
	}

	/* Return pointer to original data (skip magic + length header) */
	*output = data + 3;
	*output_len = original_len;

	size_t padding_size = data_len - 3 - original_len;
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Padding: removed %zu bytes from %zu byte packet (original: %zu)",
	       padding_size, data_len, original_len);

	return true;
}
