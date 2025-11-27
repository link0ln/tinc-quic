/*
    padding.h -- Packet padding for DPI evasion
    Copyright (C) 2025 Tinc VPN Project
*/

#ifndef TINC_PADDING_H
#define TINC_PADDING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Padding magic byte to identify padded packets */
#define PADDING_MAGIC 0xFD

/* Maximum padding size */
#define MAX_PADDING_SIZE 512

/* Padding modes */
typedef enum {
	PADDING_OFF = 0,      /* No padding */
	PADDING_RANDOM,       /* Random padding size */
	PADDING_BUCKETS       /* Round up to size buckets */
} padding_mode_t;

/* Global padding configuration */
typedef struct {
	padding_mode_t mode;
	int min_size;                  /* Minimum padding bytes */
	int max_size;                  /* Maximum padding bytes */
	int *buckets;                  /* Array of bucket sizes for PADDING_BUCKETS mode */
	int bucket_count;              /* Number of buckets */
	bool small_packets_only;       /* Only pad packets below threshold */
	int threshold;                 /* Threshold for small_packets_only mode */
} padding_config_t;

extern padding_config_t padding_config;

/*
 * Add padding to a packet
 *
 * @param data Original packet data
 * @param data_len Length of original data
 * @param output Buffer to write padded packet (must be large enough)
 * @param output_size Size of output buffer
 * @return Length of padded packet, or 0 on error
 */
size_t padding_add(const uint8_t *data, size_t data_len,
                   uint8_t *output, size_t output_size);

/*
 * Remove padding from a packet
 *
 * @param data Padded packet data
 * @param data_len Length of padded data
 * @param output Pointer to receive original data pointer (points into input buffer)
 * @param output_len Pointer to receive original data length
 * @return true if padding was removed (or no padding present), false on error
 */
bool padding_remove(const uint8_t *data, size_t data_len,
                    const uint8_t **output, size_t *output_len);

/*
 * Calculate padding size based on configuration
 *
 * @param data_len Original data length
 * @return Padding size to add
 */
size_t padding_calculate_size(size_t data_len);

/*
 * Initialize padding configuration with defaults
 */
void padding_init(void);

/*
 * Cleanup padding configuration
 */
void padding_cleanup(void);

#endif /* TINC_PADDING_H */
