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
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "quic.h"
#include "buffer.h"
#include "connection.h"
#include "http3_frames.h"
#include "padding.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Global QUIC state */
#ifndef QUIC_CONGESTION_CONTROL_ALGORITHM_BBR
#define QUIC_CONGESTION_CONTROL_ALGORITHM_BBR 1
#endif

quic_state_t quic_state = {
	.api = NULL,
	.registration = NULL,
	.configuration = NULL,
	.client_configuration = NULL,
	.listener = NULL,
	.initialized = false,
	.port = 0
};

/* QUIC configuration parameters (default values, can be overridden in tinc.conf) */
int quic_jitter_max_us = 1000;  /* Default: 1ms jitter */
int quic_stream_pool_size = QUIC_STREAM_POOL_SIZE_DEFAULT;  /* Default: 6 streams */
int quic_keepalive_min_sec = QUIC_KEEPALIVE_MIN_DEFAULT;    /* Default: 5 seconds */
int quic_keepalive_max_sec = QUIC_KEEPALIVE_MAX_DEFAULT;    /* Default: 15 seconds */
int quic_keepalive_size = QUIC_KEEPALIVE_SIZE_DEFAULT;      /* Default: 64 bytes */
bool quic_http3_masquerading = false;  /* Default: disabled */
bool quic_trust_public_certs = false;  /* Trust public CA certs (Let's Encrypt) for DPI evasion */
int quic_http3_headers_interval = 60;  /* Default: 60 seconds between HEADERS frames */

/* Debug level control */
int quic_debug_level = 0;              /* Default: 0 (minimal logging) */

/* Inline logging macro - zero overhead when debug level = 0 */
#define LOG_DEBUG_PROTOCOL(...) do { \
	if(quic_debug_level > 0) { \
		logger(DEBUG_PROTOCOL, LOG_DEBUG, __VA_ARGS__); \
	} \
} while(0)

#define LOG_DEBUG_TRAFFIC(...) do { \
	if(quic_debug_level > 0) { \
		logger(DEBUG_TRAFFIC, LOG_DEBUG, __VA_ARGS__); \
	} \
} while(0)

/* ========== Buffer Pool for Zero-Copy Performance ========== */
#define BUFFER_POOL_SIZE 2048  /* Increased from 1024 for high bandwidth (1000+ Mbps) */
#define BUFFER_SIZE (sizeof(QUIC_BUFFER) + 2200)  /* QUIC_BUFFER + max packet size (MTU 1500 + Padding 512 + Headers) */

typedef struct buffer_pool_entry {
	void *buffer;
	atomic_bool in_use;
} buffer_pool_entry_t;

static buffer_pool_entry_t buffer_pool[BUFFER_POOL_SIZE];
static atomic_bool buffer_pool_initialized = false;

/* Dynamic SNI domain pool (initialized from config or defaults) */
char **sni_domain_pool = NULL;
int sni_pool_size = 0;

/* ALPN buffer */
static const QUIC_BUFFER quic_alpn = {
	sizeof(QUIC_ALPN) - 1,
	(uint8_t *)QUIC_ALPN
};

/* Certificate file paths - must persist beyond quic_init() */
static char cert_path_global[PATH_MAX];
static char key_path_global[PATH_MAX];
static char ca_path_global[PATH_MAX];  /* Path to Root CA certificate */

/* Pre-loaded CA certificate for fast validation in callbacks (no file I/O) */
static X509 *ca_cert_global = NULL;

/* Registration configuration */
static const QUIC_REGISTRATION_CONFIG quic_reg_config = {
	"tinc-vpn",
	QUIC_EXECUTION_PROFILE_LOW_LATENCY
};

/* ========== Reference Counting Helpers (prevents use-after-free) ========== */

/*
 * Increment reference count (thread-safe)
 */
static inline void qc_addref(quic_connection_t *qc) {
	if(!qc) {
		return;
	}

	int old_count = atomic_fetch_add(&qc->refcount, 1);
	LOG_DEBUG_PROTOCOL(
	       "qc_addref: %p refcount %d -> %d", qc, old_count, old_count + 1);
}

/*
 * Decrement reference count and free if zero (thread-safe)
 */
static inline void qc_release(quic_connection_t *qc) {
	if(!qc) {
		return;
	}

	int old_count = atomic_fetch_sub(&qc->refcount, 1);
	LOG_DEBUG_PROTOCOL(
	       "qc_release: %p refcount %d -> %d", qc, old_count, old_count - 1);

	if(old_count == 1) {
		/* Last reference - safe to free */
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "qc_release: freeing %p (refcount reached 0)", qc);

		/* Note: streams array is statically allocated as part of struct, no need to free */

		free(qc);
	} else if(old_count <= 0) {
		/* BUG: Double-free or refcount underflow */
		logger(DEBUG_ALWAYS, LOG_ERR,
		       "BUG: qc_release called on %p with refcount %d", qc, old_count);
	}
}

/*
 * Try to acquire reference for callback use
 * Returns false if connection is closing (fast path rejection)
 */
static inline bool qc_try_acquire(quic_connection_t *qc) {
	if(!qc) {
		return false;
	}

	/* Fast path: check closing flag first (atomic load) */
	if(atomic_load(&qc->closing)) {
		LOG_DEBUG_PROTOCOL(
		       "qc_try_acquire: %p is closing, denied", qc);
		return false;
	}

	/* Slow path: increment refcount */
	qc_addref(qc);

	/* Double-check closing flag (may have been set between check and addref) */
	if(atomic_load(&qc->closing)) {
		LOG_DEBUG_PROTOCOL(
		       "qc_try_acquire: %p became closing after addref, releasing", qc);
		qc_release(qc);
		return false;
	}

	return true;
}

/* ========== Buffer Pool Management (CPU Optimization) ========== */

/*
 * Initialize buffer pool
 */
static void init_buffer_pool(void) {
	if(atomic_load(&buffer_pool_initialized)) {
		return;
	}

	for(int i = 0; i < BUFFER_POOL_SIZE; i++) {
		buffer_pool[i].buffer = xmalloc(BUFFER_SIZE);
		atomic_init(&buffer_pool[i].in_use, false);
	}

	atomic_store(&buffer_pool_initialized, true);
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Initialized buffer pool with %d buffers of %d bytes each",
	       BUFFER_POOL_SIZE, BUFFER_SIZE);
}

/*
 * Acquire buffer from pool (fast path, no malloc)
 */
static void *acquire_buffer(void) {
	/* Try to find free buffer in pool (lock-free) */
	for(int i = 0; i < BUFFER_POOL_SIZE; i++) {
		bool expected = false;

		if(atomic_compare_exchange_strong(&buffer_pool[i].in_use, &expected, true)) {
			return buffer_pool[i].buffer;
		}
	}

	/* Pool exhausted, fallback to malloc */
	logger(DEBUG_TRAFFIC, LOG_WARNING, "Buffer pool exhausted, falling back to malloc");
	return xmalloc(BUFFER_SIZE);
}

/*
 * Release buffer back to pool
 */
static void release_buffer(void *buffer) {
	if(!buffer) {
		return;
	}

	/* CRITICAL: Check if pool still initialized (may be shutting down) */
	if(!atomic_load(&buffer_pool_initialized)) {
		/* Pool already cleaned up, just free the buffer */
		free(buffer);
		LOG_DEBUG_PROTOCOL( "Released buffer after pool cleanup (using free)");
		return;
	}

	/* Find buffer in pool and mark as free */
	for(int i = 0; i < BUFFER_POOL_SIZE; i++) {
		if(buffer_pool[i].buffer == buffer) {
			atomic_store(&buffer_pool[i].in_use, false);
			return;
		}
	}

	/* Not a pool buffer, free it */
	free(buffer);
}

/* ========== Certificate Validation (mTLS Authentication) ========== */

#include <openssl/x509.h>
/*
 * Validate peer certificate against CA
 * Returns true if certificate is valid, false otherwise
 *
 * Supports two modes:
 * 1. Self-signed mode: Each node generates its own certificate. Validation
 *    accepts any self-signed certificate (issuer == subject). This is the
 *    default when using auto-generated certificates.
 * 2. CA mode: All nodes share a common CA. Validation checks that the peer
 *    certificate was signed by our trusted CA.
 */
/* Validate peer certificate using X509* (platform specific - OpenSSL) */
static bool validate_peer_certificate_x509(X509 *peer_cert) {
	if(!peer_cert) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate validation: NULL certificate");
		return false;
	}

	/* NOTE: MsQuic's X509* causes SEGFAULT with X509_verify() and X509_STORE
	 * Using basic validation: check that issuer matches our CA subject
	 * This prevents unauthorized nodes while avoiding OpenSSL crashes */

	/* Extract and log peer CN (Common Name) */
	X509_NAME *peer_subject = X509_get_subject_name(peer_cert);
	X509_NAME *peer_issuer = X509_get_issuer_name(peer_cert);
	char cn[256] = {0};
	if(peer_subject) {
		X509_NAME_get_text_by_NID(peer_subject, NID_commonName, cn, sizeof(cn));
	}

	if(!peer_issuer || !peer_subject) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate validation: Failed to get names");
		return false;
	}

	/* Check if peer certificate is self-signed (issuer == subject) */
	if(X509_NAME_cmp(peer_issuer, peer_subject) == 0) {
		/* Self-signed certificate - accept it in mesh mode
		 * This allows nodes to auto-generate their own certificates
		 * without requiring a shared CA infrastructure */
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "Certificate validation: ACCEPTED self-signed cert - Peer CN=%s", cn);
		return true;
	}

	/* If trust_public_certs is enabled, accept any certificate (for DPI evasion)
	 * This allows servers to use Let's Encrypt/public CA certs to look like real websites */
	if(quic_trust_public_certs) {
		char issuer_str[256] = {0};
		X509_NAME_oneline(peer_issuer, issuer_str, sizeof(issuer_str));
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "Certificate validation: ACCEPTED public cert (DPI evasion mode) - CN=%s, Issuer=%s", cn, issuer_str);
		return true;
	}

	/* Not self-signed - require proper CA chain validation */
	if(!ca_cert_global) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate validation: CA not loaded");
		return false;
	}

	/* Get our CA subject */
	X509_NAME *ca_subject = X509_get_subject_name(ca_cert_global);

	if(!ca_subject) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate validation: Failed to get CA subject");
		return false;
	}

	/* Compare issuer with CA subject - should match for valid chain */
	if(X509_NAME_cmp(peer_issuer, ca_subject) != 0) {
		char peer_issuer_str[256] = {0};
		char ca_subject_str[256] = {0};
		X509_NAME_oneline(peer_issuer, peer_issuer_str, sizeof(peer_issuer_str));
		X509_NAME_oneline(ca_subject, ca_subject_str, sizeof(ca_subject_str));

		logger(DEBUG_ALWAYS, LOG_ERR, "Certificate validation: Issuer mismatch");
		logger(DEBUG_ALWAYS, LOG_ERR, "  Peer issuer: %s", peer_issuer_str);
		logger(DEBUG_ALWAYS, LOG_ERR, "  Expected CA: %s", ca_subject_str);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "Certificate validation: SUCCESS (CA-signed) - Peer CN=%s", cn);

	/* Do NOT free peer_cert - MsQuic owns it and will free it */
	/* Do NOT free ca_cert_global - it's reused for all validations */
	return true;
}

/*
 * Cleanup buffer pool
 */
static void cleanup_buffer_pool(void) {
	if(!atomic_load(&buffer_pool_initialized)) {
		return;
	}

	/* Mark as not initialized FIRST to prevent new pool access */
	atomic_store(&buffer_pool_initialized, false);

	/* Now safe to free all buffers */
	for(int i = 0; i < BUFFER_POOL_SIZE; i++) {
		free(buffer_pool[i].buffer);
		buffer_pool[i].buffer = NULL;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Cleaned up buffer pool");
}

/*
 * Initialize QUIC library and create registration
 */
bool quic_init(uint16_t port) {
	QUIC_STATUS status;

	if(quic_state.initialized) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "QUIC already initialized");
		return true;
	}

	/* Read QUIC debug level from configuration */
	get_config_int(lookup_config(config_tree, "QUICDebugLevel"), &quic_debug_level);
	if(quic_debug_level > 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "QUIC debug level set to %d", quic_debug_level);
	}

	/* Open MsQuic library */
	status = MsQuicOpen2(&quic_state.api);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "MsQuicOpen2 failed: 0x%x", status);
		return false;
	}

	/* Create registration */
	QUIC_REGISTRATION_CONFIG quic_reg_config_local = quic_reg_config;
	quic_reg_config_local.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
	status = quic_state.api->RegistrationOpen(&quic_reg_config_local, &quic_state.registration);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "RegistrationOpen failed: 0x%x", status);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		return false;
	}

	/* Create configuration optimized for high throughput VPN */
	QUIC_SETTINGS settings = {0};
	settings.IdleTimeoutMs = QUIC_IDLE_TIMEOUT_MS;
	settings.IsSet.IdleTimeoutMs = true;
	settings.PeerBidiStreamCount = QUIC_MAX_STREAM_COUNT;
	settings.IsSet.PeerBidiStreamCount = true;
	settings.DatagramReceiveEnabled = QUIC_DATAGRAM_ENABLED;
	settings.IsSet.DatagramReceiveEnabled = true;
	
	/* Enable explicit Datagram Send for batching support */
	// settings.DatagramSendEnabled = true;
	// settings.IsSet.DatagramSendEnabled = true;

	/* Enable send buffering for higher throughput */
	settings.SendBufferingEnabled = true;
	settings.IsSet.SendBufferingEnabled = true;
	
	/* Use BBR congestion control for better performance */
	settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
	settings.IsSet.CongestionControlAlgorithm = true;

	/* Increase Flow Control Windows for high throughput */
	settings.StreamRecvWindowDefault = 16 * 1024 * 1024; // 16 MB
	settings.IsSet.StreamRecvWindowDefault = true;
	settings.ConnFlowControlWindow = 32 * 1024 * 1024;   // 32 MB
	settings.IsSet.ConnFlowControlWindow = true;

	/* Enable explicit Datagram Send for batching support */
	// settings.DatagramSendEnabled = true;
	// settings.IsSet.DatagramSendEnabled = true;

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC Settings: SendBuffering=%d, CongestionControl=%d (1=BBR), StreamWindow=16MB, ConnWindow=32MB",
	       settings.SendBufferingEnabled, settings.CongestionControlAlgorithm);

	/* Allocate credential config with TLS certificate */
	QUIC_CERTIFICATE_FILE cert_file;
	memset(&cert_file, 0, sizeof(cert_file));

	/* Build paths to certificate and key files using global storage */
	/* Check for custom certificate paths from configuration */
	char *custom_cert = NULL;
	char *custom_key = NULL;

	if(get_config_string(lookup_config(config_tree, "QUICCertFile"), &custom_cert)) {
		if(custom_cert[0] == '/') {
			/* Absolute path */
			snprintf(cert_path_global, sizeof(cert_path_global), "%s", custom_cert);
		} else {
			/* Relative to confbase */
			snprintf(cert_path_global, sizeof(cert_path_global), "%s/%s", confbase, custom_cert);
		}
		free(custom_cert);
		logger(DEBUG_ALWAYS, LOG_INFO, "Using custom QUIC certificate: %s", cert_path_global);
	} else {
		snprintf(cert_path_global, sizeof(cert_path_global), "%s/quic-cert.pem", confbase);
	}

	if(get_config_string(lookup_config(config_tree, "QUICKeyFile"), &custom_key)) {
		if(custom_key[0] == '/') {
			/* Absolute path */
			snprintf(key_path_global, sizeof(key_path_global), "%s", custom_key);
		} else {
			/* Relative to confbase */
			snprintf(key_path_global, sizeof(key_path_global), "%s/%s", confbase, custom_key);
		}
		free(custom_key);
		logger(DEBUG_ALWAYS, LOG_INFO, "Using custom QUIC private key: %s", key_path_global);
	} else {
		snprintf(key_path_global, sizeof(key_path_global), "%s/quic-key.pem", confbase);
	}

	snprintf(ca_path_global, sizeof(ca_path_global), "%s/ca.crt", confbase);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC certificate path: %s", cert_path_global);
	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC key path: %s", key_path_global);
	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC CA path: %s", ca_path_global);

	/* Pre-load CA certificate for fast validation (avoid file I/O in callbacks) */
	FILE *ca_file = fopen(ca_path_global, "r");
	if(!ca_file) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open CA certificate file: %s", ca_path_global);
		return false;
	}

	ca_cert_global = PEM_read_X509(ca_file, NULL, NULL, NULL);
	fclose(ca_file);

	if(!ca_cert_global) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to parse CA certificate from %s", ca_path_global);
		ERR_print_errors_fp(stderr);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "CA certificate pre-loaded successfully");

	cert_file.CertificateFile = cert_path_global;
	cert_file.PrivateKeyFile = key_path_global;

	QUIC_CREDENTIAL_CONFIG cred_config;
	memset(&cred_config, 0, sizeof(cred_config));
	cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
	cred_config.CertificateFile = &cert_file;
	/* NO CaCertificateFile - we validate manually in callback */

	/* Require client cert and defer validation to callback (certificate data will be provided) */
	cred_config.Flags = QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
	                    QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
	                    QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "mTLS: Client cert required with custom callback validation");

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

	/* Load server credentials */
	status = quic_state.api->ConfigurationLoadCredential(quic_state.configuration, &cred_config);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Server ConfigurationLoadCredential failed: 0x%x (cert=%s, key=%s)",
		       status, cert_path_global, key_path_global);
		quic_state.api->ConfigurationClose(quic_state.configuration);
		quic_state.api->RegistrationClose(quic_state.registration);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		quic_state.registration = NULL;
		quic_state.configuration = NULL;
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Server credentials loaded successfully from %s", cert_path_global);

	/* Create client configuration */
	status = quic_state.api->ConfigurationOpen(
	             quic_state.registration,
	             &quic_alpn,
	             1,
	             &settings,
	             sizeof(settings),
	             NULL,
	             &quic_state.client_configuration
	         );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Client ConfigurationOpen failed: 0x%x", status);
		quic_state.api->ConfigurationClose(quic_state.configuration);
		quic_state.api->RegistrationClose(quic_state.registration);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		quic_state.registration = NULL;
		quic_state.configuration = NULL;
		return false;
	}

	/* Client credentials - present our certificate and use custom validation */
	QUIC_CREDENTIAL_CONFIG client_cred_config;
	memset(&client_cred_config, 0, sizeof(client_cred_config));
	client_cred_config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
	client_cred_config.CertificateFile = &cert_file;  /* Present our certificate */
	/* NO CaCertificateFile - we validate manually in callback */

	/* Present our cert and defer validation to callback (certificate data will be provided) */
	client_cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT |
	                           QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
	                           QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;

	status = quic_state.api->ConfigurationLoadCredential(quic_state.client_configuration, &client_cred_config);

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Client ConfigurationLoadCredential failed: 0x%x", status);
		quic_state.api->ConfigurationClose(quic_state.client_configuration);
		quic_state.api->ConfigurationClose(quic_state.configuration);
		quic_state.api->RegistrationClose(quic_state.registration);
		MsQuicClose(quic_state.api);
		quic_state.api = NULL;
		quic_state.registration = NULL;
		quic_state.configuration = NULL;
		quic_state.client_configuration = NULL;
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Client credentials loaded successfully (mTLS with custom validation)");

	quic_state.port = port;
	quic_state.initialized = true;

	/* Initialize buffer pool for zero-copy performance */
	init_buffer_pool();

	/* Initialize HTTP/3 masquerading if enabled */
	if(quic_http3_masquerading) {
		http3_init_url_paths();
		logger(DEBUG_CONNECTIONS, LOG_INFO, "HTTP/3 masquerading enabled");
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC initialized successfully on port %d (server + client configs ready)", port);
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

	/* Close configurations */
	if(quic_state.client_configuration) {
		quic_state.api->ConfigurationClose(quic_state.client_configuration);
		quic_state.client_configuration = NULL;
	}

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

	/* Free SNI domain pool if allocated */
	if(sni_domain_pool) {
		for(int i = 0; i < sni_pool_size; i++) {
			free(sni_domain_pool[i]);
		}

		free(sni_domain_pool);
		sni_domain_pool = NULL;
		sni_pool_size = 0;
	}

	/* Cleanup HTTP/3 masquerading */
	if(quic_http3_masquerading) {
		http3_cleanup_url_paths();
	}

	/* Cleanup buffer pool */
	cleanup_buffer_pool();

	/* Free pre-loaded CA certificate */
	if(ca_cert_global) {
		X509_free(ca_cert_global);
		ca_cert_global = NULL;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "CA certificate freed");
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

		/* Initialize connection with timestamp */
		c->last_ping_time = time(NULL);

		/* Create QUIC connection context */
		quic_connection_t *qc = xzalloc(sizeof(quic_connection_t));
		qc->connection = event->NEW_CONNECTION.Connection;
		qc->tinc_connection = c;
		qc->connected = false;
		qc->control_stream_open = false;

		/* Initialize reference counting (Tinc owns 1, MsQuic owns 1) */
		atomic_init(&qc->refcount, 2);
		atomic_init(&qc->closing, false);
		qc->shutdown_complete = false;
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "Created qc %p (incoming) with initial refcount 2", qc);

		/* Store context in connection */
		c->quic_context = qc;

		/* Set connection callback */
		quic_state.api->SetCallbackHandler(
		    qc->connection,
		    (void *)quic_connection_callback,
		    qc  /* Pass qc as context, not c */
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

		/* Add connection to global connection list */
		connection_add(c);

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Accepted QUIC connection (will get peer info on CONNECTED event)");

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
	/* ========== SHUTDOWN_COMPLETE: Final cleanup (context is qc) ========== */
	if(event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
		quic_connection_t *qc = (quic_connection_t *)context;
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "QUIC connection shutdown complete (qc=%p, refcount=%d before release)",
		       qc, qc ? atomic_load(&qc->refcount) : 0);

		/* IMPORTANT: Do NOT call ConnectionClose() here!
		 * MsQuic will clean up the connection handle after this callback returns.
		 * Calling ConnectionClose() inside SHUTDOWN_COMPLETE callback causes SEGFAULT.
		 * We only need to release our application-level resources.
		 */

		/* Mark shutdown as complete and release our reference
		 * If refcount reaches 0, qc will be freed by qc_release()
		 */
		if(qc) {
			/* Clear connection handle since MsQuic owns it now */
			qc->connection = NULL;
			qc->shutdown_complete = true;
			qc_release(qc);
		}

		return QUIC_STATUS_SUCCESS;
	}

	/* ========== All other events: Acquire reference to prevent use-after-free ========== */

	/* ========== All other events: Acquire reference to prevent use-after-free ========== */

	quic_connection_t *qc = (quic_connection_t *)context;
	connection_t *c = NULL;

	if(!qc) {
		logger(DEBUG_ALWAYS, LOG_ERR,
		       "quic_connection_callback: NULL context for event type %d", event->Type);
		return QUIC_STATUS_INVALID_STATE;
	}

	/* Get tinc connection from qc */
	c = qc->tinc_connection;

	/* If c is NULL, we are likely in shutdown phase (detached) */
	if(!c) {
		/* If closing flag is set, we're in shutdown, ignore this event */
		if(atomic_load(&qc->closing)) {
			LOG_DEBUG_PROTOCOL(
			       "Ignoring event type %d during shutdown (qc=%p, detached)", event->Type, qc);
			
			/* CRITICAL: Clean up buffers for DATAGRAM_SEND_STATE_CHANGED even during shutdown */
			if(event->Type == QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED) {
				QUIC_DATAGRAM_SEND_STATE state = event->DATAGRAM_SEND_STATE_CHANGED.State;
				if((state == QUIC_DATAGRAM_SEND_LOST_DISCARDED ||
				    state == QUIC_DATAGRAM_SEND_ACKNOWLEDGED ||
				    state == QUIC_DATAGRAM_SEND_CANCELED) &&
				   event->DATAGRAM_SEND_STATE_CHANGED.ClientContext) {
					release_buffer(event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
					LOG_DEBUG_PROTOCOL( 
					       "Released buffer during shutdown (state %d)", state);
				}
			}
			
			return QUIC_STATUS_SUCCESS;
		}

		/* Otherwise it's an error state or race */
		logger(DEBUG_PROTOCOL, LOG_WARNING,
		       "quic_connection_callback: Detached connection (c is NULL) for event type %d",
		       event->Type);
		/* Proceed with caution, or return if event requires c */
	}

	/* Try to acquire reference (atomic check + increment)
	 * Fails if qc->closing is true (connection shutting down)
	 * This prevents use-after-free by ensuring qc stays alive during callback
	 */
	if(!qc_try_acquire(qc)) {
		LOG_DEBUG_PROTOCOL(
		       "quic_connection_callback: Connection closing, ignoring event type %d (qc=%p)",
		       event->Type, qc);
		return QUIC_STATUS_SUCCESS;
	}

	/* ========== Reference acquired, safe to process event ========== */

	QUIC_STATUS result = QUIC_STATUS_SUCCESS;

	switch(event->Type) {
	case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Peer certificate received for validation");

		/* Certificate is platform specific - on Linux/OpenSSL it's X509* */
		QUIC_CERTIFICATE *cert_ptr = event->PEER_CERTIFICATE_RECEIVED.Certificate;

		if(!cert_ptr) {
			logger(DEBUG_ALWAYS, LOG_ERR, "No certificate provided by peer - rejecting connection");
			result = QUIC_STATUS_HANDSHAKE_FAILURE;
			break;
		}

		/* Cast to X509* (platform specific - OpenSSL on Linux) */
		X509 *peer_cert = (X509 *)cert_ptr;

		/* Validate certificate against our CA */
		bool valid = validate_peer_certificate_x509(peer_cert);

		if(!valid) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer certificate validation FAILED - rejecting connection");
			result = QUIC_STATUS_HANDSHAKE_FAILURE;
		} else {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Peer certificate validation PASSED - accepting connection");
			result = QUIC_STATUS_SUCCESS;
		}
		break;
	}

	case QUIC_CONNECTION_EVENT_CONNECTED:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection established to %s", c ? (c->name ? c->name : "unknown") : "detached");
		qc->connected = true;
		
		if(!c) break; /* Can't update c->address if detached */

		/* Get remote and local addresses from QUIC connection */
		QUIC_ADDR remote_addr = {0};
		QUIC_ADDR local_addr = {0};
		uint32_t remote_addr_len = sizeof(remote_addr);
		uint32_t local_addr_len = sizeof(local_addr);

		/* Get remote (peer) address */
		QUIC_STATUS addr_status = quic_state.api->GetParam(
		                              connection,
		                              QUIC_PARAM_CONN_REMOTE_ADDRESS,
		                              &remote_addr_len,
		                              &remote_addr
		                          );

		if(QUIC_SUCCEEDED(addr_status)) {
			/* Convert QUIC_ADDR to sockaddr_t and set c->address */
			if(remote_addr.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
				c->address.sa.sa_family = AF_INET;
				memcpy(&c->address.in.sin_addr, &remote_addr.Ipv4.sin_addr, sizeof(struct in_addr));
				c->address.in.sin_port = remote_addr.Ipv4.sin_port;
			} else if(remote_addr.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
				c->address.sa.sa_family = AF_INET6;
				memcpy(&c->address.in6.sin6_addr, &remote_addr.Ipv6.sin6_addr, sizeof(struct in6_addr));
				c->address.in6.sin6_port = remote_addr.Ipv6.sin6_port;
			}

			/* Update hostname based on actual peer address */
			if(c->hostname) {
				free(c->hostname);
			}

			c->hostname = sockaddr2hostname(&c->address);
		}

		/* Get local address */
		addr_status = quic_state.api->GetParam(
		                  connection,
		                  QUIC_PARAM_CONN_LOCAL_ADDRESS,
		                  &local_addr_len,
		                  &local_addr
		              );

		if(QUIC_SUCCEEDED(addr_status)) {
			/* Convert QUIC_ADDR to sockaddr_t and set c->local_address */
			if(local_addr.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
				c->local_address.sa.sa_family = AF_INET;
				memcpy(&c->local_address.in.sin_addr, &local_addr.Ipv4.sin_addr, sizeof(struct in_addr));
				c->local_address.in.sin_port = local_addr.Ipv4.sin_port;
			} else if(local_addr.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
				c->local_address.sa.sa_family = AF_INET6;
				memcpy(&c->local_address.in6.sin6_addr, &local_addr.Ipv6.sin6_addr, sizeof(struct in6_addr));
				c->local_address.in6.sin6_port = local_addr.Ipv6.sin6_port;
			}

			LOG_DEBUG_PROTOCOL( "QUIC connection addresses set: remote=%s local=%s",
			       c->hostname ? c->hostname : "unknown",
			       sockaddr2hostname(&c->local_address));
		}

		/* Only open control stream for outgoing connections */
		/* For incoming connections, wait for peer to open their stream (handled in PEER_STREAM_STARTED) */
		/* Invitation connections are also outgoing (we initiated them) */
		if(!c->outgoing && !c->status.invitation) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Incoming connection - waiting for peer to open control stream");
			/* Don't initialize stream pool yet - wait for peer stream */
			break;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Outgoing connection - opening control stream for metadata exchange");

		/* Open control stream for metadata */
		QUIC_STATUS status = quic_state.api->StreamOpen(
		                         connection,
		                         QUIC_STREAM_OPEN_FLAG_NONE,
		                         quic_stream_callback,
		                         qc,  /* Pass qc as context, not c */
		                         &qc->control_stream
		                     );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open control stream: 0x%x", status);
			result = QUIC_STATUS_INTERNAL_ERROR; break;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Control stream opened successfully, starting it...");

		/* Start control stream */
		status = quic_state.api->StreamStart(
		             qc->control_stream,
		             QUIC_STREAM_START_FLAG_NONE
		         );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start control stream: 0x%x", status);
			result = QUIC_STATUS_INTERNAL_ERROR; break;
		}

		qc->control_stream_open = true;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Control stream ready, triggering tinc handshake");

		/* Skip stream pool - causes more problems than it solves */
		/* Keepalive can be done via QUIC PING frames instead */

		/* Check if this is an invitation connection */
		if(c->status.invitation && c->invitation_token) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Invitation connection - sending INVITE_JOIN");
			send_invite_join(c, c->invitation_token);
		} else {
			/* Trigger tinc protocol handshake */
			send_id(c);
		}

		break;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown by transport, status=0x%llx",
		       (unsigned long long)event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
		qc->connected = false;
		break;

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown by peer, error=0x%llx",
		       (unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
		qc->connected = false;
		break;

	/* SHUTDOWN_COMPLETE is handled at the top of this function */

	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
		LOG_DEBUG_PROTOCOL( "Peer started new QUIC stream");

		/* Set first peer stream as control stream for incoming connections */
		quic_connection_t *qc_peer = (quic_connection_t *)c->quic_context;
		if(qc_peer && !qc_peer->control_stream) {
			qc_peer->control_stream = event->PEER_STREAM_STARTED.Stream;
			qc_peer->control_stream_open = true;
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Set peer's first stream as control stream for incoming connection");

			/* Skip stream pool - causes more problems than it solves */

			/* Don't send ID here - it's sent in id_h when we receive ID from peer */
		}

		quic_state.api->SetCallbackHandler(
		    event->PEER_STREAM_STARTED.Stream,
		    (void *)quic_stream_callback,
		    qc  /* Pass qc as context, not c */
		);
		break;
	}

	case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED: {
		if(!c) break; /* Can't update c->address if detached */
		const QUIC_ADDR *new_addr = event->PEER_ADDRESS_CHANGED.Address;

		/* Log old address for debugging */
		char old_addr_str[INET6_ADDRSTRLEN] = {0};
		char new_addr_str[INET6_ADDRSTRLEN] = {0};
		uint16_t old_port = 0;
		uint16_t new_port = 0;

		/* Get old address string */
		if(c->address.sa.sa_family == AF_INET) {
			inet_ntop(AF_INET, &c->address.in.sin_addr, old_addr_str, sizeof(old_addr_str));
			old_port = ntohs(c->address.in.sin_port);
		} else if(c->address.sa.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &c->address.in6.sin6_addr, old_addr_str, sizeof(old_addr_str));
			old_port = ntohs(c->address.in6.sin6_port);
		}

		/* Update connection address with new peer address */
		if(new_addr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
			c->address.sa.sa_family = AF_INET;
			memcpy(&c->address.in.sin_addr, &new_addr->Ipv4.sin_addr, sizeof(struct in_addr));
			c->address.in.sin_port = new_addr->Ipv4.sin_port;

			inet_ntop(AF_INET, &new_addr->Ipv4.sin_addr, new_addr_str, sizeof(new_addr_str));
			new_port = ntohs(new_addr->Ipv4.sin_port);
		} else if(new_addr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
			c->address.sa.sa_family = AF_INET6;
			memcpy(&c->address.in6.sin6_addr, &new_addr->Ipv6.sin6_addr, sizeof(struct in6_addr));
			c->address.in6.sin6_port = new_addr->Ipv6.sin6_port;

			inet_ntop(AF_INET6, &new_addr->Ipv6.sin6_addr, new_addr_str, sizeof(new_addr_str));
			new_port = ntohs(new_addr->Ipv6.sin6_port);
		}

		/* Update hostname to match new address */
		if(c->hostname) {
			free(c->hostname);
		}

		c->hostname = sockaddr2hostname(&c->address);

		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection migrated for %s: %s:%d -> %s:%d (hostname: %s)",
		       c->name ? c->name : "unknown",
		       old_addr_str, old_port,
		       new_addr_str, new_port,
		       c->hostname ? c->hostname : "unknown");

		break;
	}

	case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
		/* Handle VPN packet via datagram */
		if(!c) break; /* Can't process data if detached */
		uint32_t len = event->DATAGRAM_RECEIVED.Buffer->Length;
		uint8_t *data = event->DATAGRAM_RECEIVED.Buffer->Buffer;

		if(len > 0 && len <= MAXSIZE) {
			/* Check if node is established before processing packets */
			if(!c->node) {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Received VPN packet before node established, dropping %d bytes", len);
				break;
			}

			vpn_packet_t packet;
			packet.offset = 0;

			/* Unwrap HTTP/3 DATA frame if masquerading is enabled */
			const uint8_t *payload_data = data;
			size_t payload_len = len;

			if(quic_http3_masquerading && len > 0) {
				uint8_t *unwrapped_data = NULL;
				size_t unwrapped_len = 0;

				/* Try to parse as HTTP/3 DATA frame */
				if(http3_parse_data_frame(data, len, &unwrapped_data, &unwrapped_len)) {
					payload_data = unwrapped_data;
					payload_len = unwrapped_len;
					LOG_DEBUG_TRAFFIC( "Unwrapped HTTP/3 DATA frame for VPN packet: %u -> %zu bytes",
					       len, unwrapped_len);
				} else {
					/* Not a valid HTTP/3 DATA frame, process as raw VPN packet */
					LOG_DEBUG_TRAFFIC( "Received non-HTTP/3 VPN datagram (%u bytes), processing as raw", len);
				}
			}

			/* DPI EVASION: Always try to remove padding if present (regardless of local config) */
			/* This allows nodes with padding disabled to receive from nodes with padding enabled */
			const uint8_t *unpadded_data = NULL;
			size_t unpadded_len = 0;

			/* Try to remove padding (returns true even if no padding was present) */
			if(padding_remove(payload_data, payload_len, &unpadded_data, &unpadded_len)) {
				if(unpadded_data != payload_data) {
					/* Padding was removed */
					LOG_DEBUG_TRAFFIC( "Removed padding: %zu -> %zu bytes",
					       payload_len, unpadded_len);
					payload_data = unpadded_data;
					payload_len = unpadded_len;
				}
			} else {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Failed to remove padding from packet");
				break;
			}

			/* Validate payload size */
			if(payload_len > sizeof(packet.data)) {
				logger(DEBUG_TRAFFIC, LOG_ERR, "Received datagram too large: %zu bytes (max: %zu)",
				       payload_len, sizeof(packet.data));
				break;
			}

			packet.len = payload_len;
			memcpy(packet.data, payload_data, payload_len);

			/* Log Ethernet type received */
			if(payload_len >= 14 && quic_debug_level > 0) {
				uint16_t eth_type = (payload_data[12] << 8) | payload_data[13];
				LOG_DEBUG_TRAFFIC( "Received packet: len=%zu, eth_type=0x%04x",
				       payload_len, eth_type);
			}

			/* Check if this is a UDP probe packet (bytes 12-13 are zero) */
			/* UDP probe packets should not be routed as VPN traffic */
			if(payload_len >= 14 && !payload_data[12] && !payload_data[13]) {
				LOG_DEBUG_TRAFFIC( "Received UDP probe packet via QUIC datagram (%zu bytes), ignoring", payload_len);
				/* TODO: Implement proper UDP probe handling for QUIC if MTU discovery is needed */
				break;
			}

			LOG_DEBUG_TRAFFIC( "Received VPN packet via QUIC datagram, %zu bytes", payload_len);
			receive_packet(c->node, &packet);
		}

		break;
	}

	case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
		QUIC_DATAGRAM_SEND_STATE state = event->DATAGRAM_SEND_STATE_CHANGED.State;
		LOG_DEBUG_PROTOCOL( "QUIC datagram send state changed: %d", state);

		/* Release datagram buffer only on final terminal states */
		/* ACKNOWLEDGED = successfully delivered, LOST_DISCARDED = dropped, CANCELED = cancelled */
		if((state == QUIC_DATAGRAM_SEND_LOST_DISCARDED ||
		    state == QUIC_DATAGRAM_SEND_ACKNOWLEDGED ||
		    state == QUIC_DATAGRAM_SEND_CANCELED) &&
		   event->DATAGRAM_SEND_STATE_CHANGED.ClientContext) {
			release_buffer(event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
			LOG_DEBUG_PROTOCOL( "Released datagram buffer on state %d", state);
		}
		break;
	}

	default:
		break;
	}

	/* ========== Release reference before returning ========== */
	qc_release(qc);
	return result;
}

/*
 * Stream callback
 */
QUIC_STATUS quic_stream_callback(HQUIC stream, void *context, QUIC_STREAM_EVENT *event) {
	quic_connection_t *qc = (quic_connection_t *)context;
	connection_t *c = NULL;

	if(!qc) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid context in stream callback");
		return QUIC_STATUS_INVALID_STATE;
	}

	/* Get tinc connection from qc */
	c = qc->tinc_connection;

	/* If c is NULL, we are likely in shutdown phase */
	if(!c) {
		/* If closing flag is set, we're in shutdown, ignore this event */
		if(atomic_load(&qc->closing)) {
			LOG_DEBUG_PROTOCOL(
			       "Ignoring stream event type %d during shutdown (qc=%p, detached)", event->Type, qc);

			/* CRITICAL: Clean up buffers for SEND_COMPLETE even during shutdown */
			if(event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE &&
			   event->SEND_COMPLETE.ClientContext) {
				free(event->SEND_COMPLETE.ClientContext);
				LOG_DEBUG_PROTOCOL(
				       "Released stream send buffer during shutdown");
			}

			return QUIC_STATUS_SUCCESS;
		}

		/* FIX: c is NULL but not closing - this is a race condition or error state
		 * We MUST return early to prevent Use-After-Free in buffer_add(&c->inbuf, ...)
		 * Still need to clean up any pending buffers
		 */
		if(event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE &&
		   event->SEND_COMPLETE.ClientContext) {
			free(event->SEND_COMPLETE.ClientContext);
			LOG_DEBUG_PROTOCOL(
			       "Released stream send buffer (detached connection)");
		}

		logger(DEBUG_PROTOCOL, LOG_WARNING,
		       "quic_stream_callback: Detached connection (c is NULL) for event type %d - returning early",
		       event->Type);
		return QUIC_STATUS_SUCCESS;
	}

	/* Try to acquire reference to prevent use-after-free */
	if(!qc_try_acquire(qc)) {
		LOG_DEBUG_PROTOCOL(
		       "quic_stream_callback: Connection closing, ignoring stream event type %d (qc=%p)",
		       event->Type, qc);

		/* Clean up any pending buffers before returning */
		if(event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE &&
		   event->SEND_COMPLETE.ClientContext) {
			free(event->SEND_COMPLETE.ClientContext);
			LOG_DEBUG_PROTOCOL(
			       "Released stream send buffer (acquire failed)");
		}

		return QUIC_STATUS_SUCCESS;
	}

	/* ========== Reference acquired, safe to process event ========== */

	QUIC_STATUS result = QUIC_STATUS_SUCCESS;

	switch(event->Type) {
	case QUIC_STREAM_EVENT_START_COMPLETE:
		logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC control stream started successfully");
		break;

	case QUIC_STREAM_EVENT_RECEIVE: {
		/* Only process metadata on control stream */
		/* Other streams are for keepalive/multiplexing (DPI evasion) - ignore their data */

		if(!qc || stream != qc->control_stream) {
			/* This is not the control stream - ignore data (likely keepalive) */
			LOG_DEBUG_TRAFFIC( "Received data on non-control stream, ignoring");
			break;
		}

		/* Handle metadata protocol messages */
		uint32_t total_len = 0;

		for(uint32_t i = 0; i < event->RECEIVE.BufferCount; i++) {
			uint32_t len = event->RECEIVE.Buffers[i].Length;
			uint8_t *data = event->RECEIVE.Buffers[i].Buffer;

			/* Unwrap HTTP/3 frames if masquerading is enabled (skip for invitation connections) */
			if(quic_http3_masquerading && len > 0 && !c->status.invitation) {
				/* Process all frames in the buffer (may contain multiple concatenated frames) */
				uint32_t offset = 0;
				while(offset < len) {
					uint8_t *frame_data = data + offset;
					uint32_t remaining = len - offset;
					uint8_t *payload_data = NULL;
					size_t payload_len = 0;

					/* Try to parse as HTTP/3 DATA frame */
					if(http3_parse_data_frame(frame_data, remaining, &payload_data, &payload_len)) {
						/* Successfully parsed DATA frame, use payload */
						buffer_add(&c->inbuf, (const char *)payload_data, payload_len);
						total_len += payload_len;

						/* Calculate frame size to advance offset */
						/* The payload_data pointer is at frame_data + header_len */
						/* So frame_size = header_len + payload_len */
						size_t header_len = (size_t)(payload_data - frame_data);
						size_t frame_size = header_len + payload_len;
						offset += frame_size;

						LOG_DEBUG_PROTOCOL( "Unwrapped HTTP/3 DATA frame: %zu -> %zu bytes at offset %zu",
						       frame_size, payload_len, offset - frame_size);
					} else {
						/* Try to parse as HEADERS frame */
						size_t headers_frame_size = http3_parse_headers_frame(frame_data, remaining);
						if(headers_frame_size > 0) {
							/* Received HEADERS frame, skip over it (just for realistic traffic) */
							offset += headers_frame_size;
							LOG_DEBUG_PROTOCOL( "Skipped HTTP/3 HEADERS frame (%zu bytes) at offset %u",
							       headers_frame_size, offset - headers_frame_size);
							continue; /* Continue parsing next frame */
						} else {
							/* Not a valid HTTP/3 frame or can't parse more frames */
							if(offset == 0) {
								/* First frame is invalid, treat entire buffer as raw data */
								buffer_add(&c->inbuf, (const char *)data, len);
								total_len += len;
								LOG_DEBUG_PROTOCOL( "Received non-HTTP/3 data (%u bytes), processing as raw",
								       len);
							}
							break;
						}
					}
				}
			} else {
				/* No masquerading, process raw data */
				buffer_add(&c->inbuf, (const char *)data, len);
				total_len += len;
			}
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Received %u bytes of metadata via QUIC stream from %s", total_len, c->name ? c->name : "unknown");

		/* Process buffered metadata requests */
		/* Note: receive_meta() may return false for protocol-level errors (e.g., unauthorized)
		 * but we should NOT close the QUIC stream - let tinc protocol handle it */
		if(!receive_meta(c)) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "receive_meta returned false for %s (may be normal protocol rejection)", c->name ? c->name : "unknown");
			/* Don't return error - continue processing, let tinc protocol handle disconnect if needed */
		}

		break;
	}

	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		LOG_DEBUG_PROTOCOL( "QUIC stream send complete");
		/* Free send context if needed */
		if(event->SEND_COMPLETE.ClientContext) {
			free(event->SEND_COMPLETE.ClientContext);
		}

		break;

	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		LOG_DEBUG_PROTOCOL( "QUIC stream peer send shutdown");
		break;

	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "QUIC stream peer send aborted");
		break;

	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		LOG_DEBUG_PROTOCOL( "QUIC stream shutdown complete");
		quic_state.api->StreamClose(stream);
		break;

	default:
		break;
	}

	/* ========== Release reference before returning ========== */
	qc_release(qc);
	return result;
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

	/* Initialize reference counting (Tinc owns 1, MsQuic owns 1) */
	atomic_init(&qc->refcount, 2);
	atomic_init(&qc->closing, false);
	qc->shutdown_complete = false;
	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "Created qc %p (outgoing %s:%d) with initial refcount 2",
	       qc, address, port);

	c->quic_context = qc;

	/* Create connection object */
	QUIC_STATUS status = quic_state.api->ConnectionOpen(
	                         quic_state.registration,
	                         quic_connection_callback,
	                         qc,  /* Pass qc as context, not c */
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

	/* Extract port from sockaddr_t */
	uint16_t port = 443; /* default tinc port */

	if(c->port) {
		port = c->port;
	} else if(c->address.sa.sa_family == AF_INET) {
		port = ntohs(c->address.in.sin_port);
	} else if(c->address.sa.sa_family == AF_INET6) {
		port = ntohs(c->address.in6.sin6_port);
	}

	if(port == 0) {
		port = 443; /* fallback to default */
	}

	/* Determine address family for ConnectionStart */
	/* Address family is already set in QUIC_ADDR, so we can pass QUIC_ADDRESS_FAMILY_UNSPEC */

	/* DPI EVASION Step 2: Use domain for SNI while connecting to actual IP */
	char ip_address[INET6_ADDRSTRLEN] = {0};

	/* Extract actual IP address for connection target */
	if(c->address.sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &c->address.in.sin_addr, ip_address, sizeof(ip_address));
	} else if(c->address.sa.sa_family == AF_INET6) {
		inet_ntop(AF_INET6, &c->address.in6.sin6_addr, ip_address, sizeof(ip_address));
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown address family for QUIC connection");
		return false;
	}

	/* Set remote address explicitly using the actual peer IP */
	QUIC_ADDR quic_addr = {0};

	if(c->address.sa.sa_family == AF_INET) {
		quic_addr.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
		memcpy(&quic_addr.Ipv4.sin_addr, &c->address.in.sin_addr, sizeof(struct in_addr));
		quic_addr.Ipv4.sin_port = c->address.in.sin_port;
	} else if(c->address.sa.sa_family == AF_INET6) {
		quic_addr.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
		memcpy(&quic_addr.Ipv6.sin6_addr, &c->address.in6.sin6_addr, sizeof(struct in6_addr));
		quic_addr.Ipv6.sin6_port = c->address.in6.sin6_port;
	}

	QUIC_STATUS status = quic_state.api->SetParam(
	                         qc->connection,
	                         QUIC_PARAM_CONN_REMOTE_ADDRESS,
	                         sizeof(quic_addr),
	                         &quic_addr
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "SetParam REMOTE_ADDRESS failed: 0x%x", status);
		return false;
	}

	/* Set SNI to match the expected node name for mTLS validation */
	/* IMPORTANT: SNI must match the certificate's CN (Common Name) for validation to succeed */
	const char *sni_domain;
	
	if(c->name && strlen(c->name) > 0) {
		/* Use the Tinc node name as SNI (matches certificate CN) */
		sni_domain = c->name;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Starting QUIC connection to %s:%d with SNI: %s (mTLS authentication)",
		       ip_address, port, sni_domain);
	} else {
		/* Fallback: use IP address as SNI (will fail validation if cert doesn't have IP SAN) */
		sni_domain = ip_address;
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "No node name available, using IP %s as SNI (may fail mTLS)",
		       ip_address);
	}

	/* Start connection with node name SNI for mTLS validation */
	status = quic_state.api->ConnectionStart(
	             qc->connection,
	             quic_state.client_configuration,
	             QUIC_ADDRESS_FAMILY_UNSPEC, /* Address family already set in QUIC_ADDR */
	             sni_domain, /* SNI for TLS handshake */
	             port
	         );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ConnectionStart failed: 0x%x (target=%s, SNI=%s)", status, ip_address, sni_domain);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection started to %s (SNI: %s)", ip_address, sni_domain);
	return true;
}

/*
 * Close QUIC connection
 */
void quic_connection_close(connection_t *c) {
	if(!c->quic_context) {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "quic_connection_close: no context for %s",
		       c->name ? c->name : "unknown");
		return;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "quic_connection_close: closing connection for %s (qc=%p, refcount=%d)",
	       c->name ? c->name : "unknown", qc, atomic_load(&qc->refcount));

	/* CRITICAL: Set closing flag FIRST (atomic operation)
	 * This prevents new callbacks from acquiring references via qc_try_acquire()
	 * Must happen before any cleanup to stop the race condition
	 */
	bool already_closing = atomic_exchange(&qc->closing, true);
	if(already_closing) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING,
		       "quic_connection_close: %p already closing (double-close prevented)", qc);
		return;
	}

	/* Close all streams in the stream pool */
	if(qc->streams_initialized) {
		LOG_DEBUG_PROTOCOL(
		       "Closing %d streams in pool for %p", qc->stream_pool_size, qc);
		for(int i = 0; i < qc->stream_pool_size; i++) {
			if(qc->streams[i].handle && qc->streams[i].active) {
				quic_state.api->StreamClose(qc->streams[i].handle);
				qc->streams[i].handle = NULL;
				qc->streams[i].active = false;
			}
		}
		qc->streams_initialized = false;
		qc->active_stream_count = 0;
	}

	/* Close legacy control stream if present */
	if(qc->control_stream) {
		LOG_DEBUG_PROTOCOL( "Closing legacy control stream for %p", qc);
		quic_state.api->StreamClose(qc->control_stream);
		qc->control_stream = NULL;
		qc->control_stream_open = false;
	}

	/* Nullify cross-references to prevent dangling pointers
	 * After this point:
	 * - c->quic_context = NULL: tinc won't try to use QUIC
	 * - qc->tinc_connection = NULL: callbacks won't access freed connection_t
	 */
	c->quic_context = NULL;
	qc->tinc_connection = NULL;
	qc->connected = false;

	/* Initiate async shutdown if connection handle exists
	 * The SHUTDOWN_COMPLETE callback will call qc_release() for final cleanup
	 */
	if(qc->connection) {
		logger(DEBUG_CONNECTIONS, LOG_INFO,
		       "Initiating async QUIC shutdown for %p (refcount=%d)",
		       qc, atomic_load(&qc->refcount));

		/* Context is already qc, no need to SetCallbackHandler */
		/* quic_state.api->SetCallbackHandler(qc->connection, ...); */

		quic_state.api->ConnectionShutdown(
		    qc->connection,
		    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
		    0
		);

		/* DO NOT free qc here!
		 * The SHUTDOWN_COMPLETE callback will call qc_release() to decrement refcount.
		 * If no other callbacks hold references, qc will be freed automatically.
		 */
	} else {
		/* No connection handle (rare edge case: allocation failed, or already freed)
		 * Safe to release our reference immediately
		 */
		logger(DEBUG_CONNECTIONS, LOG_WARNING,
		       "No QUIC connection handle for %p, releasing immediately", qc);
	}

	/* Release Tinc's reference to the connection context */
	/* The MsQuic reference will be released in SHUTDOWN_COMPLETE */
	qc_release(qc);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "QUIC connection shutdown initiated");
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

	/* ========== CRITICAL: Acquire reference to prevent use-after-free ========== */
	if(!qc_try_acquire(qc)) {
		LOG_DEBUG_PROTOCOL(
		       "quic_send_meta: Connection closing, cannot send to %s",
		       c->name ? c->name : "unknown");
		return false;
	}

	/* Reference acquired, safe to access qc */

	if(!qc->control_stream_open) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Control stream not open for %s", c->name ? c->name : "unknown");
		qc_release(qc);  /* Release before return! */
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Sending %zu bytes of metadata to %s via QUIC", len, c->name ? c->name : "unknown");

	size_t send_len = len;
	void *send_buffer_raw;
	QUIC_BUFFER *send_buffer;

	/* Wrap in HTTP/3 DATA frame if masquerading is enabled (skip for invitation connections) */
	if(quic_http3_masquerading && !c->status.invitation) {
		/* Allocate buffer for HTTP/3 frame (header + data) */
		size_t frame_size = len + 32;  /* Extra space for frame header */
		send_buffer_raw = xmalloc(sizeof(QUIC_BUFFER) + frame_size);
		send_buffer = (QUIC_BUFFER *)send_buffer_raw;
		send_buffer->Buffer = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

		/* Create HTTP/3 DATA frame */
		send_len = http3_create_data_frame((const uint8_t *)buffer, len,
		                                    send_buffer->Buffer, frame_size);

		if(send_len == 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to create HTTP/3 DATA frame");
			free(send_buffer_raw);
			qc_release(qc);  /* Release before return! */
			return false;
		}

		send_buffer->Length = send_len;
		LOG_DEBUG_PROTOCOL( "Wrapped %zu bytes metadata in HTTP/3 DATA frame (%zu bytes total)",
		       len, send_len);
	} else {
		/* Send raw data without HTTP/3 wrapping */
		send_buffer_raw = xmalloc(sizeof(QUIC_BUFFER) + len);
		send_buffer = (QUIC_BUFFER *)send_buffer_raw;
		send_buffer->Length = len;
		send_buffer->Buffer = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
		memcpy(send_buffer->Buffer, buffer, len);
	}

	/* Send on control stream */
	QUIC_STATUS status = quic_state.api->StreamSend(
	                         qc->control_stream,
	                         send_buffer,
	                         1,
	                         QUIC_SEND_FLAG_NONE,
	                         send_buffer_raw  // Pass raw buffer for correct cleanup
	                     );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "StreamSend failed: 0x%x", status);
		free(send_buffer_raw);  // Single free for entire block
		qc_release(qc);  /* Release before return! */
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Metadata sent successfully to %s (%zu bytes)", c->name ? c->name : "unknown", len);

	/* ========== Release reference ========== */
	qc_release(qc);
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

	/* ========== CRITICAL: Acquire reference to prevent use-after-free ========== */
	if(!qc_try_acquire(qc)) {
		LOG_DEBUG_PROTOCOL(
		       "quic_send_packet: Connection closing, dropping packet");
		return false;
	}

	/* Reference acquired, safe to access qc */

	if(!qc->connected) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Connection not established, dropping packet");
		qc_release(qc);  /* Release before return! */
		return false;
	}

	/* DPI EVASION: Add random timing jitter to hide traffic patterns
	 * CRITICAL: Only apply jitter to data packets (>=100 bytes), not to ACKs
	 * TCP ACKs must be sent immediately to avoid false retransmissions and
	 * congestion window stalling. Small packets are likely ACKs/control packets.
	 */
	if(quic_jitter_max_us > 0 && packet->len >= 100) {
		uint32_t jitter_us = rand() % (quic_jitter_max_us + 1);

		if(jitter_us > 0) {
			struct timespec delay = {
				.tv_sec = jitter_us / 1000000,
				.tv_nsec = (jitter_us % 1000000) * 1000
			};
			nanosleep(&delay, NULL);
		}
	}

	/* DPI EVASION: Send periodic HTTP/3 HEADERS frames to mimic browser */
	if(quic_http3_masquerading && qc->control_stream_open && http3_should_send_headers()) {
		uint8_t headers_frame[HTTP3_MAX_HEADER_SIZE];

		/* Get random URL path and SNI domain for realistic request */
		const char *path = http3_get_random_path();
		const char *authority = sni_domain_pool ? sni_domain_pool[rand() % sni_pool_size] : "www.example.com";
		http_method_t method = (rand() % 2) ? HTTP_GET : HTTP_POST;

		size_t frame_len = http3_create_headers_frame(method, path, authority,
		                                               headers_frame, sizeof(headers_frame));

		if(frame_len > 0) {
			/* Send HEADERS frame on control stream */
			void *headers_buffer_raw = xmalloc(sizeof(QUIC_BUFFER) + frame_len);
			QUIC_BUFFER *headers_buffer = (QUIC_BUFFER *)headers_buffer_raw;
			headers_buffer->Length = frame_len;
			headers_buffer->Buffer = (uint8_t *)headers_buffer_raw + sizeof(QUIC_BUFFER);
			memcpy(headers_buffer->Buffer, headers_frame, frame_len);

			QUIC_STATUS status = quic_state.api->StreamSend(
			                         qc->control_stream,
			                         headers_buffer,
			                         1,
			                         QUIC_SEND_FLAG_NONE,
			                         headers_buffer_raw
			                     );

			if(QUIC_FAILED(status)) {
				logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to send HTTP/3 HEADERS frame: 0x%x", status);
				free(headers_buffer_raw);
			} else {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Sent HTTP/3 HEADERS frame: %s %s (%zu bytes)",
				       (method == HTTP_GET) ? "GET" : "POST", path, frame_len);
				http3_update_headers_timer();
			}
		}
	}

	/* Prepare datagram buffer with HTTP/3 wrapping if enabled */
	uint8_t *original_data = packet->data + packet->offset;
	size_t final_len;

	/* Log Ethernet type being sent */
	if(packet->len >= 14) {
		uint16_t eth_type = (original_data[12] << 8) | original_data[13];
		LOG_DEBUG_TRAFFIC( "Sending packet: offset=%d, len=%d, eth_type=0x%04x",
		       packet->offset, packet->len, eth_type);
	}

	QUIC_STATUS status;

	/* ZERO-COPY OPTIMIZATION:
	 * Construct the final packet directly in the send buffer to avoid intermediate copies.
	 * We need to calculate the total size first:
	 * Total = [HTTP3 Header] + [Payload] + [Padding]
	 */

	size_t payload_len = packet->len;
	size_t padding_len = 0;
	size_t http3_header_len = 0;
	size_t total_alloc_size = 0;

	/* 1. Calculate Padding Size */
	if(padding_config.mode != PADDING_OFF) {
		size_t target_size = 0;
		switch(padding_config.mode) {
			case PADDING_RANDOM:
				/* Add random padding up to MAX_PADDING_SIZE */
				/* We use a simplified calculation here for zero-copy to avoid rand() in hot path if possible,
				   or just use a fixed overhead for now to be safe/fast.
				   Let's use a deterministic size for performance: +64 bytes */
				target_size = packet->len + 64;
				if(target_size > MAX_PADDING_SIZE + packet->len) target_size = MAX_PADDING_SIZE + packet->len;
				break;
			case PADDING_BUCKETS:
				/* Round up to next bucket */
				/* Simplified: just align to 128 bytes */
				target_size = (packet->len + 127) & ~127;
				break;
			default:
				target_size = packet->len;
				break;
		}

		if(target_size > packet->len) {
			padding_len = target_size - packet->len;
		}
	}

	/* 2. Calculate HTTP/3 Header Size */
	if(quic_http3_masquerading) {
		size_t data_len = payload_len + padding_len;
		if (data_len < 64) http3_header_len = 2;
		else if (data_len < 16384) http3_header_len = 3;
		else if (data_len < 1073741824) http3_header_len = 5;
		else http3_header_len = 9;
	}

	/* 3. Allocate Single Buffer */
	/* If padding is enabled, we need 3 extra bytes for header: [Magic(1)][Len(2)] */
	size_t padding_header_len = (padding_len > 0) ? 3 : 0;
	total_alloc_size = http3_header_len + padding_header_len + payload_len + padding_len;
	
	/* Safety check for buffer overflow */
	if(total_alloc_size > (BUFFER_SIZE - sizeof(QUIC_BUFFER))) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Packet too large for buffer: %zu > %zu", 
		       total_alloc_size, (size_t)(BUFFER_SIZE - sizeof(QUIC_BUFFER)));
		qc_release(qc);
		return false;
	}
	
	void *send_buffer_raw = acquire_buffer();
	QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
	
	uint8_t *dest_ptr = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
	send_buffer->Buffer = dest_ptr;
	send_buffer->Length = total_alloc_size;

	/* 4. Construct Packet */
	
	/* A. Write HTTP/3 Header */
	if(quic_http3_masquerading) {
		size_t data_len = padding_header_len + payload_len + padding_len;
		
		*dest_ptr++ = 0x00; /* DATA Frame Type */
		
		if (data_len < 64) {
			*dest_ptr++ = (uint8_t)data_len;
		} else if (data_len < 16384) {
			*dest_ptr++ = (uint8_t)((data_len >> 8) | 0x40);
			*dest_ptr++ = (uint8_t)data_len;
		} else if (data_len < 1073741824) {
			*dest_ptr++ = (uint8_t)((data_len >> 24) | 0x80);
			*dest_ptr++ = (uint8_t)(data_len >> 16);
			*dest_ptr++ = (uint8_t)(data_len >> 8);
			*dest_ptr++ = (uint8_t)data_len;
		} else {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Packet too large for VarInt encoding");
			release_buffer(send_buffer_raw);
			qc_release(qc);
			return false;
		}
	}

	/* B. Write Padding Header (if padding enabled) */
	if(padding_len > 0) {
		*dest_ptr++ = 0xFD; /* PADDING_MAGIC */
		*dest_ptr++ = (payload_len >> 8) & 0xFF;
		*dest_ptr++ = payload_len & 0xFF;
	}

	/* C. Copy Payload */
	memcpy(dest_ptr, original_data, payload_len);
	dest_ptr += payload_len;

	/* D. Add Padding */
	if(padding_len > 0) {
		/* Use memset for speed instead of rand() loop */
		memset(dest_ptr, 0, padding_len);
		dest_ptr += padding_len;
		
		LOG_DEBUG_TRAFFIC( "Added %zu bytes padding (Total: %zu)", padding_len, total_alloc_size);
	}

	final_len = total_alloc_size;

	/* Check if connection still valid before sending */
	if(!qc->connection) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Connection closed during send, dropping packet");
		release_buffer(send_buffer_raw);
		qc_release(qc);
		return false;
	}

	/* Send datagram - Pass buffer as context for cleanup */
	status = quic_state.api->DatagramSend(
							 qc->connection,
							 send_buffer,
							 1,
							 QUIC_SEND_FLAG_NONE,
							 send_buffer_raw
						 );

	if(QUIC_FAILED(status)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "DatagramSend failed: 0x%x", status);
		/* Cleanup on immediate failure */
		release_buffer(send_buffer_raw);
		qc_release(qc);  /* Release before return! */
		return false;
	}

	if(quic_debug_level > 0) {
		LOG_DEBUG_TRAFFIC( "Sent VPN packet via QUIC datagram, %zu bytes (Zero-Copy)", final_len);
	}

	/* ========== Release reference ========== */
	qc_release(qc);
	return true;
}

/*
 * Initialize stream pool for connection multiplexing
 * Creates multiple parallel streams with different priorities to mimic browser behavior
 */
bool quic_init_stream_pool(quic_connection_t *qc) {
	if(!qc || !qc->connection) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid connection for stream pool initialization");
		return false;
	}

	if(qc->streams_initialized) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Stream pool already initialized");
		return true;
	}

	/* Use configured stream pool size */
	qc->stream_pool_size = quic_stream_pool_size;

	/* Validate stream pool size */
	if(qc->stream_pool_size < 1) {
		qc->stream_pool_size = 1;
		logger(DEBUG_ALWAYS, LOG_WARNING, "Stream pool size too small, using minimum: 1");
	} else if(qc->stream_pool_size > QUIC_STREAM_POOL_SIZE_MAX) {
		qc->stream_pool_size = QUIC_STREAM_POOL_SIZE_MAX;
		logger(DEBUG_ALWAYS, LOG_WARNING, "Stream pool size too large, using maximum: %d", QUIC_STREAM_POOL_SIZE_MAX);
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Initializing stream pool with %d streams for multiplexing", qc->stream_pool_size);

	/* Define stream priorities to mimic browser behavior
	 * Priorities are distributed based on stream index:
	 * - First stream: Urgent (HTML/critical)
	 * - Next ~30%: High (CSS/JS)
	 * - Middle ~40%: Medium (fonts/images)
	 * - Last ~30%: Low (analytics/background)
	 */
	const uint8_t stream_priorities[QUIC_STREAM_POOL_SIZE_MAX] = {
		STREAM_PRIORITY_URGENT,   /* Stream 0: Critical resources */
		STREAM_PRIORITY_HIGH,     /* Stream 1: CSS */
		STREAM_PRIORITY_HIGH,     /* Stream 2: JavaScript */
		STREAM_PRIORITY_MEDIUM,   /* Stream 3: Fonts */
		STREAM_PRIORITY_MEDIUM,   /* Stream 4: Images */
		STREAM_PRIORITY_LOW,      /* Stream 5: Background/analytics */
		STREAM_PRIORITY_MEDIUM,   /* Stream 6: Additional medium priority */
		STREAM_PRIORITY_HIGH,     /* Stream 7: Additional high priority */
		STREAM_PRIORITY_LOW,      /* Stream 8: Additional low priority */
		STREAM_PRIORITY_LOW       /* Stream 9: Additional low priority */
	};

	int success_count = 0;

	for(int i = 0; i < qc->stream_pool_size; i++) {
		/* Open stream */
		QUIC_STATUS status = quic_state.api->StreamOpen(
		                         qc->connection,
		                         QUIC_STREAM_OPEN_FLAG_NONE,
		                         quic_stream_callback,
		                         qc->tinc_connection,
		                         &qc->streams[i].handle
		                     );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open stream %d: 0x%x", i, status);
			qc->streams[i].active = false;
			continue;
		}

		/* Set stream priority */
		uint16_t priority = stream_priorities[i];
		status = quic_state.api->SetParam(
		             qc->streams[i].handle,
		             QUIC_PARAM_STREAM_PRIORITY,
		             sizeof(priority),
		             &priority
		         );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to set priority for stream %d: 0x%x", i, status);
			/* Continue anyway - priority is optional */
		}

		/* Start stream */
		status = quic_state.api->StreamStart(
		             qc->streams[i].handle,
		             QUIC_STREAM_START_FLAG_NONE
		         );

		if(QUIC_FAILED(status)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start stream %d: 0x%x", i, status);
			quic_state.api->StreamClose(qc->streams[i].handle);
			qc->streams[i].active = false;
			continue;
		}

		/* Initialize stream info */
		qc->streams[i].priority = stream_priorities[i];
		qc->streams[i].active = true;
		qc->streams[i].bytes_sent = 0;
		qc->streams[i].last_activity = time(NULL);
		success_count++;

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Stream %d opened with priority %d", i, stream_priorities[i]);
	}

	qc->active_stream_count = success_count;
	atomic_init(&qc->next_stream_index, 0);
	qc->streams_initialized = true;
	qc->last_keepalive = time(NULL);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Stream pool initialized: %d/%d streams active",
	       success_count, qc->stream_pool_size);

	return success_count > 0;
}

/*
 * Cleanup stream pool
 */
void quic_cleanup_stream_pool(quic_connection_t *qc) {
	if(!qc || !qc->streams_initialized) {
		return;
	}

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Cleaning up stream pool (%d streams)", qc->stream_pool_size);

	for(int i = 0; i < qc->stream_pool_size && i < QUIC_STREAM_POOL_SIZE_MAX; i++) {
		if(qc->streams[i].active && qc->streams[i].handle) {
			quic_state.api->StreamClose(qc->streams[i].handle);
			qc->streams[i].active = false;
			qc->streams[i].handle = NULL;
		}
	}

	qc->streams_initialized = false;
	qc->active_stream_count = 0;
}

/*
 * Select stream for sending data (round-robin with fallback)
 */
HQUIC quic_select_stream(quic_connection_t *qc) {
	if(!qc || !qc->streams_initialized || qc->active_stream_count == 0) {
		return NULL;
	}

	/* Round-robin selection with atomic index (thread-safe) */
	int attempts = 0;
	int start_index = atomic_fetch_add(&qc->next_stream_index, 1) % qc->stream_pool_size;

	while(attempts < qc->stream_pool_size) {
		int index = (start_index + attempts) % qc->stream_pool_size;

		if(qc->streams[index].active) {
			qc->streams[index].last_activity = time(NULL);
			return qc->streams[index].handle;
		}

		attempts++;
	}

	logger(DEBUG_TRAFFIC, LOG_WARNING, "No active streams available");
	return NULL;
}

/*
 * Send HTTP/3 HEADERS frame to mimic browser requests
 * NOTE: This is an internal function called from quic_send_keepalive()
 *       which already holds a refcount, so NO refcount protection here!
 */
static void quic_send_http3_headers(connection_t *c) {
	if(!c || !c->quic_context || !quic_http3_masquerading) {
		return;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	/* NO qc_try_acquire() - caller (quic_send_keepalive) already holds refcount */

	if(!qc->streams_initialized || qc->active_stream_count == 0) {
		return;
	}

	/* Check if it's time to send HEADERS */
	if(!http3_should_send_headers()) {
		return;
	}

	/* Select random stream for HEADERS */
	int stream_index = rand() % qc->stream_pool_size;
	int attempts = 0;

	while(attempts < qc->stream_pool_size && !qc->streams[stream_index].active) {
		stream_index = (stream_index + 1) % qc->stream_pool_size;
		attempts++;
	}

	if(!qc->streams[stream_index].active) {
		return;
	}

	/* Prepare HTTP/3 HEADERS frame */
	uint8_t *headers_frame = xmalloc(HTTP3_MAX_HEADER_SIZE);
	http_method_t method = (rand() % 2) ? HTTP_GET : HTTP_POST;
	const char *path = http3_get_random_path();
	const char *authority = c->name ? c->name : "example.com";

	size_t frame_len = http3_create_headers_frame(method, path, authority,
	                   headers_frame, HTTP3_MAX_HEADER_SIZE);

	if(frame_len == 0) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Failed to create HTTP/3 HEADERS frame");
		free(headers_frame);
		return;
	}

	/* Allocate send buffer */
	void *send_buffer_raw = xmalloc(sizeof(QUIC_BUFFER) + frame_len);
	QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
	send_buffer->Length = frame_len;
	send_buffer->Buffer = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
	memcpy(send_buffer->Buffer, headers_frame, frame_len);
	free(headers_frame);

	/* Send on selected stream */
	QUIC_STATUS status = quic_state.api->StreamSend(
	                         qc->streams[stream_index].handle,
	                         send_buffer,
	                         1,
	                         QUIC_SEND_FLAG_NONE,
	                         send_buffer_raw
	                     );

	if(QUIC_SUCCEEDED(status)) {
		http3_update_headers_timer();
		qc->streams[stream_index].bytes_sent += frame_len;
		LOG_DEBUG_PROTOCOL( "Sent HTTP/3 HEADERS frame on stream %d (%s %s, %zu bytes)",
		       stream_index, method == HTTP_GET ? "GET" : "POST", path, frame_len);
	} else {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "HTTP/3 HEADERS send failed on stream %d: 0x%x",
		       stream_index, status);
		free(send_buffer_raw);
	}

	/* NO qc_release() - caller (quic_send_keepalive) will release */
}

/*
 * Send keepalive packet to maintain connection and mimic browser activity
 */
void quic_send_keepalive(connection_t *c) {
	if(!c || !c->quic_context) {
		return;
	}

	quic_connection_t *qc = (quic_connection_t *)c->quic_context;

	/* ========== CRITICAL: Acquire reference to prevent use-after-free ========== */
	if(!qc_try_acquire(qc)) {
		LOG_DEBUG_PROTOCOL(
		       "quic_send_keepalive: Connection closing, skip");
		return;
	}

	/* Reference acquired, safe to access qc */

	if(!qc->streams_initialized || qc->active_stream_count == 0) {
		qc_release(qc);  /* Release before return! */
		return;
	}

	/* Send HTTP/3 HEADERS frames if masquerading is enabled */
	if(quic_http3_masquerading) {
		quic_send_http3_headers(c);
	}

	/* Check if keepalive is disabled */
	if(quic_keepalive_min_sec == 0 || quic_keepalive_max_sec == 0) {
		qc_release(qc);  /* Release before return! */
		return;  /* Keepalive disabled */
	}

	time_t now = time(NULL);

	/* Check if keepalive is needed */
	int range = quic_keepalive_max_sec - quic_keepalive_min_sec;
	int keepalive_interval = quic_keepalive_min_sec;

	if(range > 0) {
		keepalive_interval += (rand() % (range + 1));
	}

	if(now - qc->last_keepalive < keepalive_interval) {
		qc_release(qc);  /* Release before return! */
		return;  /* Too soon */
	}

	/* Select random stream for keepalive */
	int stream_index = rand() % qc->stream_pool_size;
	int attempts = 0;

	while(attempts < qc->stream_pool_size && !qc->streams[stream_index].active) {
		stream_index = (stream_index + 1) % qc->stream_pool_size;
		attempts++;
	}

	if(!qc->streams[stream_index].active) {
		qc_release(qc);  /* Release before return! */
		return;  /* No active streams */
	}

	/* Prepare small keepalive data (random bytes) */
	int keepalive_size = quic_keepalive_size;

	if(keepalive_size < 16) {
		keepalive_size = 16;
	} else if(keepalive_size > QUIC_KEEPALIVE_SIZE_MAX) {
		keepalive_size = QUIC_KEEPALIVE_SIZE_MAX;
	}

	uint8_t *keepalive_data = xmalloc(keepalive_size);

	for(int i = 0; i < keepalive_size; i++) {
		keepalive_data[i] = rand() & 0xFF;
	}

	/* Allocate send buffer */
	void *send_buffer_raw = xmalloc(sizeof(QUIC_BUFFER) + keepalive_size);
	QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
	send_buffer->Length = keepalive_size;
	send_buffer->Buffer = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
	memcpy(send_buffer->Buffer, keepalive_data, keepalive_size);
	free(keepalive_data);

	/* Send on selected stream */
	QUIC_STATUS status = quic_state.api->StreamSend(
	                         qc->streams[stream_index].handle,
	                         send_buffer,
	                         1,
	                         QUIC_SEND_FLAG_NONE,
	                         send_buffer_raw  /* Will be freed in callback */
	                     );

	if(QUIC_SUCCEEDED(status)) {
		qc->last_keepalive = now;
		qc->streams[stream_index].bytes_sent += keepalive_size;
		LOG_DEBUG_TRAFFIC( "Sent keepalive on stream %d (%d bytes)",
		       stream_index, keepalive_size);
	} else {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Keepalive send failed on stream %d: 0x%x",
		       stream_index, status);
		free(send_buffer_raw);
	}

	/* ========== Release reference ========== */
	qc_release(qc);
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
