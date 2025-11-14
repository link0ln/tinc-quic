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

#include "connection.h"
#include "net.h"

/* QUIC configuration */
#define QUIC_ALPN "tinc-vpn-quic"
#define QUIC_IDLE_TIMEOUT_MS 60000
#define QUIC_MAX_STREAM_COUNT 100
#define QUIC_DATAGRAM_ENABLED true

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

/* QUIC connection context */
typedef struct quic_connection_t {
	HQUIC connection;
	HQUIC control_stream;
	struct connection_t *tinc_connection;
	bool connected;
	bool control_stream_open;
} quic_connection_t;

/* Global QUIC state */
extern quic_state_t quic_state;

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

/* QUIC callbacks */
extern QUIC_STATUS quic_connection_callback(HQUIC connection, void *context, QUIC_CONNECTION_EVENT *event);
extern QUIC_STATUS quic_stream_callback(HQUIC stream, void *context, QUIC_STREAM_EVENT *event);
extern QUIC_STATUS quic_listener_callback(HQUIC listener, void *context, QUIC_LISTENER_EVENT *event);

/* Helper functions */
extern void quic_set_connection_context(struct connection_t *c);
extern quic_connection_t *quic_get_connection_context(struct connection_t *c);

#endif /* TINC_QUIC_H */
