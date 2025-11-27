/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2018 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans
                  2006      Scott Lamb <slamb@slamb.org>

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

#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "protocol.h"
#include "quic.h"
#include "utils.h"
#include "xalloc.h"

#ifndef MIN
static ssize_t MIN(ssize_t x, ssize_t y) {
	return x < y ? x : y;
}
#endif

/* Legacy function removed - QUIC only mode */

bool send_meta(connection_t *c, const char *buffer, size_t length) {
	if(!c) {
		logger(DEBUG_ALWAYS, LOG_ERR, "send_meta() called with NULL pointer!");
		abort();
	}

	logger(DEBUG_META, LOG_DEBUG, "Sending %lu bytes of metadata to %s (%s)", (unsigned long)length,
	       c->name, c->hostname);

	/* Control socket connections use Unix socket directly */
	if(c->status.control && c->socket >= 0) {
		ssize_t result = send(c->socket, buffer, length, MSG_NOSIGNAL);
		if(result < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not send to control connection: %s", strerror(errno));
			return false;
		}
		return (size_t)result == length;
	}

#ifdef HAVE_MSQUIC
	/* QUIC only - no fallback */
	if(c->quic_context) {
		return quic_send_meta(c, buffer, length);
	}

	/* If no QUIC context, connection is being torn down */
	logger(DEBUG_META, LOG_DEBUG, "QUIC connection %s (%s) has no context, likely being closed",
	       c->name ? c->name : "unknown", c->hostname ? c->hostname : "unknown");
	return false;
#else
	logger(DEBUG_ALWAYS, LOG_ERR, "QUIC not compiled in!");
	return false;
#endif
}

void send_meta_raw(connection_t *c, const char *buffer, size_t length) {
	if(!c) {
		logger(DEBUG_ALWAYS, LOG_ERR, "send_meta() called with NULL pointer!");
		abort();
	}

	logger(DEBUG_META, LOG_DEBUG, "Sending %lu bytes of raw metadata to %s (%s)", (unsigned long)length,
	       c->name, c->hostname);

	/* Control socket connections use Unix socket directly */
	if(c->status.control && c->socket >= 0) {
		send(c->socket, buffer, length, MSG_NOSIGNAL);
		return;
	}

#ifdef HAVE_MSQUIC
	/* QUIC only */
	if(c->quic_context) {
		quic_send_meta(c, buffer, length);
		return;
	}
#endif

	logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection!");
}

void broadcast_meta(connection_t *from, const char *buffer, size_t length) {
	for list_each(connection_t, c, connection_list)
		if(c != from && c->edge) {
			send_meta(c, buffer, length);
		}
}

/* Legacy function removed - QUIC only mode */

bool receive_meta(connection_t *c) {
	/* Control socket connections read from Unix socket */
	if(c->status.control && c->socket >= 0) {
		char buf[4096];
		ssize_t inlen = recv(c->socket, buf, sizeof(buf), 0);

		if(inlen <= 0) {
			if(inlen == 0) {
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Control connection closed by peer");
			} else if(errno != EINTR && errno != EAGAIN) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error reading from control connection: %s", strerror(errno));
			}
			return false;
		}

		buffer_add(&c->inbuf, buf, inlen);

		while(c->inbuf.len) {
			char *request = buffer_readline(&c->inbuf);
			if(request) {
				bool result = receive_request(c, request);
				if(!result) {
					return false;
				}
			} else {
				break;
			}
		}
		return true;
	}

#ifdef HAVE_MSQUIC
	/* QUIC only - data already in c->inbuf from QUIC stream callback */
	if(c->quic_context) {
		while(c->inbuf.len) {
			char *request = buffer_readline(&c->inbuf);

			if(request) {
				bool result = receive_request(c, request);

				if(!result) {
					return false;
				}

				continue;
			} else {
				break;
			}
		}

		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection!");
	return false;
#else
	logger(DEBUG_ALWAYS, LOG_ERR, "QUIC not compiled in!");
	return false;
#endif
}
