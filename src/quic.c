/*
    quic.c -- QUIC protocol implementation using MsQuic
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

#ifdef HAVE_MSQUIC

#include <msquic.h>

#include "quic.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Global QUIC state */
quic_state_t quic_state = {
	.api = NULL,
	.registration = NULL,
	.configuration = NULL,
	.listener = NULL,
	.initialized = false,
	.port = 0
};

/* ALPN buffer */
static const QUIC_BUFFER quic_alpn = {
	sizeof(QUIC_ALPN) - 1,
	(uint8_t *)QUIC_ALPN
};

/* Registration configuration */
static const QUIC_REGISTRATION_CONFIG quic_reg_config = {
	"tinc-vpn",
	QUIC_EXECUTION_PROFILE_LOW_LATENCY
};

/*
 * Initialize QUIC library and create registration
 */
bool quic_init(uint16_t port) {
	QUIC_STATUS status;

	if(quic_state.initialized) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "QUIC already initialized");
		return true;
	}

	/* Open MsQuic library */
	status = MsQuicOpen2(&quic_state.api);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "MsQuicOpen2 failed: 0x%x", status);
		return false;
	}

	/* Create registration */
	status = quic_state.api->RegistrationOpen(&quic_reg_config, &quic_state.registration);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "RegistrationOpen failed: 0x%x", status);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		return false;
	}

	/* Create configuration */
	QUIC_SETTINGS settings = {0};
	settings.IdleTimeoutMs = QUIC_IDLE_TIMEOUT_MS;
	settings.IsSet.IdleTimeoutMs = true;
	settings.PeerBidiStreamCount = QUIC_MAX_STREAM_COUNT;
	settings.IsSet.PeerBidiStreamCount = true;
	settings.DatagramReceiveEnabled = QUIC_DATAGRAM_ENABLED;
	settings.IsSet.DatagramReceiveEnabled = true;

	/* Allocate credential config */
	QUIC_CREDENTIAL_CONFIG cred_config;
	memset(&cred_config, 0, sizeof(cred_config));
	cred_config.Type = QUIC_CREDENTIAL_TYPE_NONE;
	cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

	status = quic_state.api->ConfigurationOpen(
	             quic_state.registration,
	             &quic_alpn,
	             1,
	             &settings,
	             sizeof(settings),
	             NULL,
	             &quic_state.configuration
	         );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ConfigurationOpen failed: 0x%x", status);
		quic_state.api->RegistrationClose(quic_state.registration);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		quic_state.registration = NULL;
		return false;
	}

	/* Load credentials */
	status = quic_state.api->ConfigurationLoadCredential(quic_state.configuration, &cred_config);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ConfigurationLoadCredential failed: 0x%x", status);
		quic_state.api->ConfigurationClose(quic_state.configuration);
		quic_state.api->RegistrationClose(quic_state.registration);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		quic_state.registration = NULL;
		quic_state.configuration = NULL;
		return false;
	}

	quic_state.port = port;
	quic_state.initialized = true;

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC initialized successfully on port %d", port);
	return true;
}

/*
 * Cleanup QUIC library
 */
void quic_cleanup(void) {
	if(!quic_state.initialized) {
		return;
	}

	/* Stop listener if running */
	quic_stop_listener();

	/* Close configuration */
	if(quic_state.configuration) {
		quic_state.api->ConfigurationClose(quic_state.configuration);
		quic_state.configuration = NULL;
	}

	/* Close registration */
	if(quic_state.registration) {
		quic_state.api->RegistrationClose(quic_state.registration);
		quic_state.registration = NULL;
	}

	/* Close MsQuic */
	if(quic_state.api) {
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
	}

	quic_state.initialized = false;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC cleanup complete");
}

/*
 * Listener callback
 */
QUIC_STATUS quic_listener_callback(HQUIC listener, void *context, QUIC_LISTENER_EVENT *event) {
	(void)listener;
	(void)context;

	switch(event->Type) {
	case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "New QUIC connection attempt");

		/* Create new tinc connection object */
		connection_t *c = new_connection();

		/* Create QUIC connection context */
		quic_connection_t *qc = xzalloc(sizeof(quic_connection_t));
		qc->connection = event->NEW_CONNECTION.Connection;
		qc->tinc_connection = c;
		qc->connected = false;
		qc->control_stream_open = false;

		/* Store context in connection */
		c->quic_context = qc;

		/* Set connection callback */
		quic_state.api->SetCallbackHandler(
		    qc->connection,
		    (void *)quic_connection_callback,
		    c
		);

		/* Configure connection */
		QUIC_STATUS status = quic_state.api->ConnectionSetConfiguration(
		                         qc->connection,
		                         quic_state.configuration
		                     );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "ConnectionSetConfiguration failed: 0x%x", status);
			free(qc);
			free_connection(c);
			return QUIC_STATUS_INTERNAL_ERROR;
		}

		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_LISTENER_EVENT_STOP_COMPLETE:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC listener stopped");
		return QUIC_STATUS_SUCCESS;

	default:
		return QUIC_STATUS_SUCCESS;
	}
}

/*
 * Start QUIC listener
 */
bool quic_start_listener(uint16_t port) {
	if(!quic_state.initialized) {
		logger(DEBUG_ALWAYS, LOG_ERR, "QUIC not initialized");
		return false;
	}

	if(quic_state.listener) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "QUIC listener already running");
		return true;
	}

	QUIC_STATUS status;

	/* Create listener */
	status = quic_state.api->ListenerOpen(
	             quic_state.registration,
	             quic_listener_callback,
	             NULL,
	             &quic_state.listener
	         );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ListenerOpen failed: 0x%x", status);
		return false;
	}

	/* Start listening */
	QUIC_ADDR addr = {0};
	QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
	QuicAddrSetPort(&addr, port);

	status = quic_state.api->ListenerStart(
	             quic_state.listener,
	             &quic_alpn,
	             1,
	             &addr
	         );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ListenerStart failed: 0x%x", status);
		quic_state.api->ListenerClose(quic_state.listener);
		quic_state.listener = NULL;
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC listener started on port %d", port);
	return true;
}

/*
 * Stop QUIC listener
 */
void quic_stop_listener(void) {
	if(quic_state.listener) {
		quic_state.api->ListenerStop(quic_state.listener);
		quic_state.api->ListenerClose(quic_state.listener);
		quic_state.listener = NULL;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC listener stopped");
	}
}

/*
 * Connection callback
 */
QUIC_STATUS quic_connection_callback(HQUIC connection, void *context, QUIC_CONNECTION_EVENT *event) {
	connection_t *c = (connection_t *)context;

	if(!c || !c->quic_context) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid connection context in callback");
		return QUIC_STATUS_INVALID_STATE;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	switch(event->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection established to %s", c->name ? c->name : "unknown");
		qc->connected = true;

		/* Open control stream for metadata */
		QUIC_STATUS status = quic_state.api->StreamOpen(
		                         connection,
		                         QUIC_STREAM_OPEN_FLAG_NONE,
		                         quic_stream_callback,
		                         c,
		                         &qc->control_stream
		                     );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open control stream: 0x%x", status);
			return QUIC_STATUS_INTERNAL_ERROR;
		}

		/* Start control stream */
		status = quic_state.api->StreamStart(
		             qc->control_stream,
		             QUIC_STREAM_START_FLAG_NONE
		         );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start control stream: 0x%x", status);
			return QUIC_STATUS_INTERNAL_ERROR;
		}

		qc->control_stream_open = true;

		/* Trigger tinc protocol handshake */
		send_id(c);

		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown by transport, status=0x%llx",
		       (unsigned long long)event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
		qc->connected = false;
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown by peer, error=0x%llx",
		       (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
		qc->connected = false;
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown complete");
		qc->connected = false;
		quic_state.api->ConnectionClose(connection);
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Peer started new QUIC stream");
		quic_state.api->SetCallbackHandler(
		    event->PEER_STREAM_STARTED.Stream,
		    (void *)quic_stream_callback,
		    c
		);
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
		/* Handle VPN packet via datagram */
		uint32_t len = event->DATAGRAM_RECEIVED.Buffer->Length;
		uint8_t *data = event->DATAGRAM_RECEIVED.Buffer->Buffer;

		if(len > 0 && len <= MAXSIZE) {
			vpn_packet_t packet;
			packet.len = len;
			packet.offset = 0;
			memcpy(packet.data, data, len);

			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received VPN packet via QUIC datagram, %d bytes", len);
			receive_packet(c->node, &packet);
		}

		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC datagram send state changed");
		return QUIC_STATUS_SUCCESS;

	default:
		return QUIC_STATUS_SUCCESS;
	}
}

/*
 * Stream callback
 */
QUIC_STATUS quic_stream_callback(HQUIC stream, void *context, QUIC_STREAM_EVENT *event) {
	connection_t *c = (connection_t *)context;

	if(!c || !c->quic_context) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid connection context in stream callback");
		return QUIC_STATUS_INVALID_STATE;
	}

	switch(event->Type) {
	case QUIC_STREAM_EVENT_START_COMPLETE:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC stream started");
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_RECEIVE: {
		/* Handle metadata protocol messages */
		uint32_t total_len = 0;

		for(uint32_t i = 0; i < event->RECEIVE.BufferCount; i++) {
			uint32_t len = event->RECEIVE.Buffers[i].Length;
			uint8_t *data = event->RECEIVE.Buffers[i].Buffer;

			/* Append to connection input buffer */
			if(!c->inbuf.data) {
				c->inbuf.len = 0;
				c->inbuf.offset = 0;
			}

			/* Process metadata */
			char *buf = (char *)data;

			for(uint32_t j = 0; j < len; j++) {
				if(buf[j] == '\n') {
					/* Process complete line */
					if(!receive_request(c)) {
						logger(DEBUG_ALWAYS, LOG_ERR, "Error processing metadata request");
						return QUIC_STATUS_INVALID_STATE;
					}
				} else {
					/* Buffer incomplete data */
					// TODO: implement proper buffering
				}
			}

			total_len += len;
		}

		logger(DEBUG_META, LOG_DEBUG, "Received %u bytes of metadata via QUIC stream", total_len);
		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC stream send complete");
		/* Free send context if needed */
		if(event->SEND_COMPLETE.ClientContext) {
			free(event->SEND_COMPLETE.ClientContext);
		}

		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC stream peer send shutdown");
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUIC stream peer send aborted");
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "QUIC stream shutdown complete");
		quic_state.api->StreamClose(stream);
		return QUIC_STATUS_SUCCESS;

	default:
		return QUIC_STATUS_SUCCESS;
	}
}

/*
 * Open QUIC connection to remote host
 */
bool quic_connection_open(connection_t *c, const char *address, uint16_t port) {
	if(!quic_state.initialized) {
		logger(DEBUG_ALWAYS, LOG_ERR, "QUIC not initialized");
		return false;
	}

	/* Create QUIC connection context */
	quic_connection_t *qc = xzalloc(sizeof(quic_connection_t));
	qc->tinc_connection = c;
	qc->connected = false;
	qc->control_stream_open = false;

	c->quic_context = qc;

	/* Create connection object */
	QUIC_STATUS status = quic_state.api->ConnectionOpen(
	                         quic_state.registration,
	                         quic_connection_callback,
	                         c,
	                         &qc->connection
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ConnectionOpen failed: 0x%x", status);
		free(qc);
		c->quic_context = NULL;
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection opened to %s:%d", address, port);
	return true;
}

/*
 * Start QUIC connection
 */
bool quic_connection_start(connection_t *c) {
	if(!c->quic_context) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection");
		return false;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	/* Parse address */
	QUIC_ADDR addr = {0};
	QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);

	// TODO: Convert c->address to QUIC_ADDR format
	// For now, use placeholder
	QuicAddrSetPort(&addr, c->port ? c->port : 655);

	/* Start connection */
	QUIC_STATUS status = quic_state.api->ConnectionStart(
	                         qc->connection,
	                         quic_state.configuration,
	                         QUIC_ADDRESS_FAMILY_UNSPEC,
	                         c->hostname ? c->hostname : c->name,
	                         QuicAddrGetPort(&addr)
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ConnectionStart failed: 0x%x", status);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection started to %s", c->name);
	return true;
}

/*
 * Close QUIC connection
 */
void quic_connection_close(connection_t *c) {
	if(!c->quic_context) {
		return;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	/* Close control stream */
	if(qc->control_stream) {
		quic_state.api->StreamClose(qc->control_stream);
		qc->control_stream = NULL;
	}

	/* Shutdown connection */
	if(qc->connection) {
		quic_state.api->ConnectionShutdown(
		    qc->connection,
		    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
		    0
		);
		qc->connection = NULL;
	}

	free(qc);
	c->quic_context = NULL;

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection closed");
}

/*
 * Send metadata over QUIC control stream
 */
bool quic_send_meta(connection_t *c, const char *buffer, size_t len) {
	if(!c->quic_context) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection");
		return false;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	if(!qc->control_stream_open) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Control stream not open");
		return false;
	}

	/* Allocate send buffer */
	QUIC_BUFFER *send_buffer = xmalloc(sizeof(QUIC_BUFFER));
	send_buffer->Length = len;
	send_buffer->Buffer = xmalloc(len);
	memcpy(send_buffer->Buffer, buffer, len);

	/* Send on control stream */
	QUIC_STATUS status = quic_state.api->StreamSend(
	                         qc->control_stream,
	                         send_buffer,
	                         1,
	                         QUIC_SEND_FLAG_NONE,
	                         send_buffer  // Pass as context for cleanup
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "StreamSend failed: 0x%x", status);
		free(send_buffer->Buffer);
		free(send_buffer);
		return false;
	}

	logger(DEBUG_META, LOG_DEBUG, "Sent %zu bytes of metadata via QUIC", len);
	return true;
}

/*
 * Send VPN packet over QUIC datagram
 */
bool quic_send_packet(connection_t *c, vpn_packet_t *packet) {
	if(!c->quic_context) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No QUIC context for connection");
		return false;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	if(!qc->connected) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Connection not established, dropping packet");
		return false;
	}

	/* Prepare datagram buffer */
	QUIC_BUFFER buffer;
	buffer.Length = packet->len;
	buffer.Buffer = packet->data + packet->offset;

	/* Send datagram */
	QUIC_STATUS status = quic_state.api->DatagramSend(
	                         qc->connection,
	                         &buffer,
	                         1,
	                         QUIC_SEND_FLAG_NONE,
	                         NULL
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "DatagramSend failed: 0x%x", status);
		return false;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Sent VPN packet via QUIC datagram, %d bytes", packet->len);
	return true;
}

#else /* !HAVE_MSQUIC */

/* Stub implementations when MsQuic is not available */
bool quic_init(uint16_t port) {
	(void)port;
	return false;
}

void quic_cleanup(void) {}
bool quic_start_listener(uint16_t port) {
	(void)port;
	return false;
}
void quic_stop_listener(void) {}
bool quic_connection_open(connection_t *c, const char *address, uint16_t port) {
	(void)c;
	(void)address;
	(void)port;
	return false;
}
bool quic_connection_start(connection_t *c) {
	(void)c;
	return false;
}
void quic_connection_close(connection_t *c) {
	(void)c;
}
bool quic_send_meta(connection_t *c, const char *buffer, size_t len) {
	(void)c;
	(void)buffer;
	(void)len;
	return false;
}
bool quic_send_packet(connection_t *c, vpn_packet_t *packet) {
	(void)c;
	(void)packet;
	return false;
}

#endif /* HAVE_MSQUIC */
