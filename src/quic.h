/*
    quic.h -- QUIC protocol abstraction layer using MsQuic
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

#ifndef TINC_QUIC_H
#define TINC_QUIC_H

#include "system.h"

#ifdef HAVE_MSQUIC
#include <msquic.h>
#endif

#include <stdatomic.h>

#include "connection.h"
#include "net.h"

/* QUIC configuration */
/* DPI EVASION Step 1: Change ALPN to less obvious identifier
 * Using generic "quic" protocol name instead of "tinc-vpn-quic"
 * Still custom, but less revealing than explicit VPN signature
 */
#define QUIC_ALPN "quic"
#define QUIC_IDLE_TIMEOUT_MS 60000
#define QUIC_MAX_STREAM_COUNT 100
#define QUIC_DATAGRAM_ENABLED true

/* DPI EVASION: Connection Multiplexing Patterns
 * Mimic browser behavior with multiple parallel streams
 * Note: These can be configured in tinc.conf
 */
#define QUIC_STREAM_POOL_SIZE_MAX 10     /* Maximum number of streams allowed */
#define QUIC_STREAM_POOL_SIZE_DEFAULT 6  /* Default number of parallel streams */
#define QUIC_KEEPALIVE_MIN_DEFAULT 5     /* Default minimum keepalive interval (seconds) */
#define QUIC_KEEPALIVE_MAX_DEFAULT 15    /* Default maximum keepalive interval (seconds) */
#define QUIC_KEEPALIVE_SIZE_DEFAULT 64   /* Default keepalive packet size */
#define QUIC_KEEPALIVE_SIZE_MAX 512      /* Maximum keepalive packet size */

/* Stream priorities mimicking browser behavior */
#define STREAM_PRIORITY_URGENT  0     /* HTML, critical resources */
#define STREAM_PRIORITY_HIGH    1     /* CSS, JavaScript */
#define STREAM_PRIORITY_MEDIUM  3     /* Fonts, important images */
#define STREAM_PRIORITY_LOW     5     /* Background images, analytics */

/* DPI EVASION: Timing jitter configuration
 * Note: QUICJitterMaxUs can be configured in tinc.conf
 * Default: 1000 microseconds (1ms)
 * Range: 0 (disabled) to 50000 (50ms, capped)
 * Example in tinc.conf: QUICJitterMaxUs = 2000
 */

/* Default SNI domain pool for DPI evasion - use common CDN/cloud domains */
#define SNI_POOL_DEFAULT_SIZE 12
static const char *sni_domain_pool_default[SNI_POOL_DEFAULT_SIZE] = {
	"www.cloudflare.com",
	"www.google.com",
	"www.microsoft.com",
	"cdn.jsdelivr.net",
	"ajax.googleapis.com",
	"www.gstatic.com",
	"fonts.googleapis.com",
	"www.youtube.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"www.amazon.com",
	"s3.amazonaws.com"
};

/* Dynamic SNI domain pool (configurable via QUICSNIDomains in tinc.conf) */
extern char **sni_domain_pool;
extern int sni_pool_size;

/* QUIC global state */
typedef struct quic_state_t {
	const QUIC_API_TABLE *api;
	HQUIC registration;
	HQUIC configuration;        /* Server configuration (for listener) */
	HQUIC client_configuration;  /* Client configuration (for outgoing connections) */
	HQUIC listener;
	bool initialized;
	uint16_t port;
} quic_state_t;

/* Stream information for multiplexing */
typedef struct stream_info_t {
	HQUIC handle;           /* Stream handle */
	uint8_t priority;       /* Stream priority (0=urgent, 7=lowest) */
	bool active;            /* Stream is open and ready */
	uint64_t bytes_sent;    /* Total bytes sent on this stream */
	time_t last_activity;   /* Last time data was sent */
} stream_info_t;

/* QUIC connection context */
typedef struct quic_connection_t {
	HQUIC connection;
	HQUIC control_stream;           /* Legacy: single control stream for metadata */
	stream_info_t streams[QUIC_STREAM_POOL_SIZE_MAX];  /* Multiple data streams (max size) */
	int stream_pool_size;           /* Actual number of streams to use */
	atomic_int next_stream_index;   /* Round-robin index for stream selection (atomic for thread safety) */
	int active_stream_count;        /* Number of active streams */
	struct connection_t *tinc_connection;

	/* Reference counting for safe shutdown (prevents use-after-free) */
	atomic_int refcount;            /* Thread-safe reference counter */
	atomic_bool closing;            /* Connection is shutting down (fast path check) */
	bool shutdown_complete;         /* SHUTDOWN_COMPLETE event received */

	bool connected;
	bool control_stream_open;       /* Legacy: control stream status */
	bool streams_initialized;       /* Stream pool initialized */
	time_t last_keepalive;          /* Last keepalive packet sent */
} quic_connection_t;

/* Global QUIC state */
extern quic_state_t quic_state;

/* QUIC configuration parameters (loaded from tinc.conf) */
extern int quic_jitter_max_us;
extern int quic_stream_pool_size;      /* Number of parallel streams */
extern int quic_keepalive_min_sec;     /* Minimum keepalive interval */
extern int quic_keepalive_max_sec;     /* Maximum keepalive interval */
extern int quic_keepalive_size;        /* Keepalive packet size */
extern bool quic_http3_masquerading;   /* Enable HTTP/3 masquerading */
extern int quic_debug_level;           /* QUIC debug level (0=off, 1=info, 2=verbose) */

/* QUIC initialization and cleanup */
extern bool quic_init(uint16_t port);
extern void quic_cleanup(void);

/* QUIC listener management */
extern bool quic_start_listener(uint16_t port);
extern void quic_stop_listener(void);

/* QUIC connection management */
extern bool quic_connection_open(struct connection_t *c, const char *address, uint16_t port);
extern bool quic_connection_start(struct connection_t *c);
extern void quic_connection_close(struct connection_t *c);

/* QUIC data transmission */
extern bool quic_send_meta(struct connection_t *c, const char *buffer, size_t len);
extern bool quic_send_packet(struct connection_t *c, struct vpn_packet_t *packet);

/* Stream multiplexing management */
extern bool quic_init_stream_pool(quic_connection_t *qc);
extern void quic_cleanup_stream_pool(quic_connection_t *qc);
extern HQUIC quic_select_stream(quic_connection_t *qc);
extern void quic_send_keepalive(struct connection_t *c);

/* QUIC callbacks */
extern QUIC_STATUS quic_connection_callback(HQUIC connection, void *context, QUIC_CONNECTION_EVENT *event);
extern QUIC_STATUS quic_stream_callback(HQUIC stream, void *context, QUIC_STREAM_EVENT *event);
extern QUIC_STATUS quic_listener_callback(HQUIC listener, void *context, QUIC_LISTENER_EVENT *event);

/* Helper functions */
extern void quic_set_connection_context(struct connection_t *c);
extern quic_connection_t *quic_get_connection_context(struct connection_t *c);

#endif /* TINC_QUIC_H */
