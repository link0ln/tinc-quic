/*
    cert_autogen.c -- Automatic TLS certificate generation
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
#include "cert_autogen.h"
#include "logger.h"
#include "xalloc.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* Certificate validity period: 10 years in seconds */
#define CERT_VALIDITY_SECONDS (3650L * 24L * 3600L)

/*
 * Generate RSA key pair using OpenSSL 3.0+ API
 */
static EVP_PKEY *generate_rsa_key(int bits) {
	EVP_PKEY *pkey = EVP_RSA_gen(bits);
	if(!pkey) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate RSA key: %s",
		       ERR_error_string(ERR_get_error(), NULL));
	}
	return pkey;
}

/*
 * Create self-signed X.509 certificate
 */
static X509 *create_self_signed_cert(EVP_PKEY *pkey, const char *node_name) {
	X509 *x509 = X509_new();
	if(!x509) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to allocate X509 structure");
		return NULL;
	}

	/* Set certificate version to v3 */
	if(!X509_set_version(x509, 2)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set X509 version");
		X509_free(x509);
		return NULL;
	}

	/* Set serial number (random for uniqueness) */
	ASN1_INTEGER *serial = X509_get_serialNumber(x509);
	if(!ASN1_INTEGER_set(serial, (long)time(NULL))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set serial number");
		X509_free(x509);
		return NULL;
	}

	/* Set validity period */
	if(!X509_gmtime_adj(X509_getm_notBefore(x509), 0)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set notBefore");
		X509_free(x509);
		return NULL;
	}
	if(!X509_gmtime_adj(X509_getm_notAfter(x509), CERT_VALIDITY_SECONDS)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set notAfter");
		X509_free(x509);
		return NULL;
	}

	/* Set public key */
	if(!X509_set_pubkey(x509, pkey)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set public key");
		X509_free(x509);
		return NULL;
	}

	/* Set subject name */
	X509_NAME *name = X509_get_subject_name(x509);
	if(!name) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to get subject name");
		X509_free(x509);
		return NULL;
	}

	/* Add CN (Common Name) = node name */
	if(!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                               (const unsigned char *)node_name, -1, -1, 0)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to add CN to certificate");
		X509_free(x509);
		return NULL;
	}

	/* Add O (Organization) */
	if(!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	                               (const unsigned char *)"TincVPN", -1, -1, 0)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to add O to certificate");
		X509_free(x509);
		return NULL;
	}

	/* Self-signed: issuer = subject */
	if(!X509_set_issuer_name(x509, name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to set issuer name");
		X509_free(x509);
		return NULL;
	}

	/* Sign the certificate with the private key */
	if(!X509_sign(x509, pkey, EVP_sha256())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign certificate: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		X509_free(x509);
		return NULL;
	}

	return x509;
}

/*
 * Write private key to file with restricted permissions
 */
static bool write_private_key(const char *path, EVP_PKEY *pkey) {
	FILE *f = fopen(path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open %s for writing: %s",
		       path, strerror(errno));
		return false;
	}

	/* Set restrictive permissions before writing */
	if(chmod(path, 0600) != 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Failed to set permissions on %s: %s",
		       path, strerror(errno));
	}

	if(!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to write private key to %s: %s",
		       path, ERR_error_string(ERR_get_error(), NULL));
		fclose(f);
		return false;
	}

	fclose(f);
	return true;
}

/*
 * Write certificate to file
 */
static bool write_certificate(const char *path, X509 *x509) {
	FILE *f = fopen(path, "w");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open %s for writing: %s",
		       path, strerror(errno));
		return false;
	}

	if(!PEM_write_X509(f, x509)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to write certificate to %s: %s",
		       path, ERR_error_string(ERR_get_error(), NULL));
		fclose(f);
		return false;
	}

	fclose(f);
	return true;
}

/*
 * Check if all required certificate files exist
 */
static bool certificates_exist(const char *cert_path, const char *key_path, const char *ca_path) {
	return (access(cert_path, R_OK) == 0 &&
	        access(key_path, R_OK) == 0 &&
	        access(ca_path, R_OK) == 0);
}

/*
 * Main function: ensure certificates exist, generate if missing
 */
bool ensure_quic_certificates(const char *confbase, const char *node_name) {
	char cert_path[PATH_MAX];
	char key_path[PATH_MAX];
	char ca_path[PATH_MAX];

	if(!confbase || !node_name) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid arguments to ensure_quic_certificates");
		return false;
	}

	/* Build file paths */
	snprintf(cert_path, sizeof(cert_path), "%s/quic-cert.pem", confbase);
	snprintf(key_path, sizeof(key_path), "%s/quic-key.pem", confbase);
	snprintf(ca_path, sizeof(ca_path), "%s/ca.crt", confbase);

	/* Check if all certificates already exist */
	if(certificates_exist(cert_path, key_path, ca_path)) {
		logger(DEBUG_ALWAYS, LOG_INFO, "QUIC certificates found in %s", confbase);
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Generating QUIC certificates for node '%s'...", node_name);

	/* Generate RSA key pair */
	EVP_PKEY *pkey = generate_rsa_key(2048);
	if(!pkey) {
		return false;
	}

	/* Create self-signed certificate */
	X509 *x509 = create_self_signed_cert(pkey, node_name);
	if(!x509) {
		EVP_PKEY_free(pkey);
		return false;
	}

	/* Write private key */
	if(!write_private_key(key_path, pkey)) {
		X509_free(x509);
		EVP_PKEY_free(pkey);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Generated private key: %s", key_path);

	/* Write node certificate */
	if(!write_certificate(cert_path, x509)) {
		X509_free(x509);
		EVP_PKEY_free(pkey);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Generated certificate: %s", cert_path);

	/* Write CA certificate (same as node cert for self-signed) */
	if(!write_certificate(ca_path, x509)) {
		X509_free(x509);
		EVP_PKEY_free(pkey);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Generated CA certificate: %s", ca_path);

	/* Cleanup */
	X509_free(x509);
	EVP_PKEY_free(pkey);

	logger(DEBUG_ALWAYS, LOG_INFO, "QUIC certificate generation complete for node '%s'", node_name);
	return true;
}

/*
 * Check if this node has CA authority (ca-key.pem exists)
 */
bool has_ca_authority(const char *confbase) {
	char ca_key_path[PATH_MAX];
	snprintf(ca_key_path, sizeof(ca_key_path), "%s/ca-key.pem", confbase);
	return access(ca_key_path, R_OK) == 0;
}

/*
 * Generate CA key and certificate
 */
bool generate_ca(const char *confbase) {
	char ca_key_path[PATH_MAX];
	char ca_cert_path[PATH_MAX];

	if(!confbase) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid confbase for CA generation");
		return false;
	}

	snprintf(ca_key_path, sizeof(ca_key_path), "%s/ca-key.pem", confbase);
	snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/ca.crt", confbase);

	/* Check if CA already exists */
	if(access(ca_key_path, R_OK) == 0 && access(ca_cert_path, R_OK) == 0) {
		logger(DEBUG_ALWAYS, LOG_INFO, "CA already exists in %s", confbase);
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Generating CA key and certificate...");

	/* Generate 4096-bit RSA key for CA (stronger than node keys) */
	EVP_PKEY *ca_key = EVP_RSA_gen(4096);
	if(!ca_key) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate CA key: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	/* Create CA certificate */
	X509 *ca_cert = X509_new();
	if(!ca_cert) {
		EVP_PKEY_free(ca_key);
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to allocate CA certificate");
		return false;
	}

	/* Set version to v3 */
	X509_set_version(ca_cert, 2);

	/* Set serial number */
	ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);

	/* Set validity */
	X509_gmtime_adj(X509_getm_notBefore(ca_cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(ca_cert), CERT_VALIDITY_SECONDS);

	/* Set public key */
	X509_set_pubkey(ca_cert, ca_key);

	/* Set subject/issuer name */
	X509_NAME *name = X509_get_subject_name(ca_cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                           (const unsigned char *)"TincVPN CA", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	                           (const unsigned char *)"TincVPN", -1, -1, 0);
	X509_set_issuer_name(ca_cert, name);

	/* Add CA extensions */
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, ca_cert, ca_cert, NULL, NULL, 0);

	X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
	if(ext) {
		X509_add_ext(ca_cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
	if(ext) {
		X509_add_ext(ca_cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	/* Sign the CA certificate */
	if(!X509_sign(ca_cert, ca_key, EVP_sha256())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign CA certificate: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}

	/* Write CA private key */
	if(!write_private_key(ca_key_path, ca_key)) {
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Generated CA private key: %s", ca_key_path);

	/* Write CA certificate */
	if(!write_certificate(ca_cert_path, ca_cert)) {
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}
	logger(DEBUG_ALWAYS, LOG_INFO, "Generated CA certificate: %s", ca_cert_path);

	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);

	logger(DEBUG_ALWAYS, LOG_INFO, "CA generation complete");
	return true;
}

/*
 * Load CA private key from file
 */
static EVP_PKEY *load_ca_key(const char *confbase) {
	char ca_key_path[PATH_MAX];
	snprintf(ca_key_path, sizeof(ca_key_path), "%s/ca-key.pem", confbase);

	FILE *f = fopen(ca_key_path, "r");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open CA key %s: %s",
		       ca_key_path, strerror(errno));
		return NULL;
	}

	EVP_PKEY *ca_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
	fclose(f);

	if(!ca_key) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read CA key: %s",
		       ERR_error_string(ERR_get_error(), NULL));
	}

	return ca_key;
}

/*
 * Load CA certificate from file
 */
static X509 *load_ca_cert(const char *confbase) {
	char ca_cert_path[PATH_MAX];
	snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/ca.crt", confbase);

	FILE *f = fopen(ca_cert_path, "r");
	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to open CA cert %s: %s",
		       ca_cert_path, strerror(errno));
		return NULL;
	}

	X509 *ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
	fclose(f);

	if(!ca_cert) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read CA cert: %s",
		       ERR_error_string(ERR_get_error(), NULL));
	}

	return ca_cert;
}

/*
 * Sign a CSR with the CA key
 */
bool sign_csr(const char *confbase, const char *csr_pem, char **cert_pem) {
	if(!confbase || !csr_pem || !cert_pem) {
		return false;
	}

	*cert_pem = NULL;

	/* Load CA key and certificate */
	EVP_PKEY *ca_key = load_ca_key(confbase);
	if(!ca_key) {
		return false;
	}

	X509 *ca_cert = load_ca_cert(confbase);
	if(!ca_cert) {
		EVP_PKEY_free(ca_key);
		return false;
	}

	/* Parse CSR from PEM */
	BIO *csr_bio = BIO_new_mem_buf(csr_pem, -1);
	X509_REQ *csr = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
	BIO_free(csr_bio);

	if(!csr) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to parse CSR: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}

	/* Create new certificate */
	X509 *cert = X509_new();
	if(!cert) {
		X509_REQ_free(csr);
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}

	/* Set version and serial */
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));

	/* Set validity */
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), CERT_VALIDITY_SECONDS);

	/* Copy subject from CSR */
	X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));

	/* Set issuer from CA */
	X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

	/* Set public key from CSR */
	EVP_PKEY *csr_key = X509_REQ_get_pubkey(csr);
	X509_set_pubkey(cert, csr_key);
	EVP_PKEY_free(csr_key);

	/* Sign with CA key */
	if(!X509_sign(cert, ca_key, EVP_sha256())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign certificate: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		X509_free(cert);
		X509_REQ_free(csr);
		X509_free(ca_cert);
		EVP_PKEY_free(ca_key);
		return false;
	}

	/* Convert certificate to PEM */
	BIO *cert_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(cert_bio, cert);

	BUF_MEM *mem;
	BIO_get_mem_ptr(cert_bio, &mem);
	*cert_pem = xstrdup(mem->data);

	BIO_free(cert_bio);
	X509_free(cert);
	X509_REQ_free(csr);
	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);

	logger(DEBUG_ALWAYS, LOG_INFO, "Signed certificate for node");
	return true;
}

/*
 * Generate a CSR for this node
 */
bool generate_csr(const char *node_name, char **key_pem, char **csr_pem) {
	if(!node_name || !key_pem || !csr_pem) {
		return false;
	}

	*key_pem = NULL;
	*csr_pem = NULL;

	/* Generate RSA key */
	EVP_PKEY *pkey = EVP_RSA_gen(2048);
	if(!pkey) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to generate key for CSR: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	/* Create CSR */
	X509_REQ *csr = X509_REQ_new();
	if(!csr) {
		EVP_PKEY_free(pkey);
		return false;
	}

	/* Set subject name */
	X509_NAME *name = X509_REQ_get_subject_name(csr);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                           (const unsigned char *)node_name, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	                           (const unsigned char *)"TincVPN", -1, -1, 0);

	/* Set public key */
	X509_REQ_set_pubkey(csr, pkey);

	/* Sign CSR */
	if(!X509_REQ_sign(csr, pkey, EVP_sha256())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to sign CSR: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		X509_REQ_free(csr);
		EVP_PKEY_free(pkey);
		return false;
	}

	/* Convert key to PEM */
	BIO *key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
	BUF_MEM *key_mem;
	BIO_get_mem_ptr(key_bio, &key_mem);
	*key_pem = xstrdup(key_mem->data);
	BIO_free(key_bio);

	/* Convert CSR to PEM */
	BIO *csr_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(csr_bio, csr);
	BUF_MEM *csr_mem;
	BIO_get_mem_ptr(csr_bio, &csr_mem);
	*csr_pem = xstrdup(csr_mem->data);
	BIO_free(csr_bio);

	X509_REQ_free(csr);
	EVP_PKEY_free(pkey);

	return true;
}

/*
 * Calculate SHA256 fingerprint of an X509 certificate object
 */
char *calculate_cert_fingerprint_x509(void *cert_ptr) {
	X509 *cert = (X509 *)cert_ptr;
	if(!cert) {
		return NULL;
	}

	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	if(!X509_digest(cert, EVP_sha256(), md, &md_len)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to calculate certificate fingerprint: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* Base64 encode the fingerprint */
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *mem = BIO_new(BIO_s_mem());
	BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, md, md_len);
	BIO_flush(b64);

	BUF_MEM *bptr;
	BIO_get_mem_ptr(b64, &bptr);

	/* Format: "SHA256:<base64>" */
	size_t result_len = 7 + bptr->length + 1; /* "SHA256:" + base64 + null */
	char *result = xmalloc(result_len);
	snprintf(result, result_len, "SHA256:%.*s", (int)bptr->length, bptr->data);

	BIO_free_all(b64);

	return result;
}

/*
 * Calculate SHA256 fingerprint of a PEM-encoded certificate
 */
char *calculate_cert_fingerprint(const char *cert_pem) {
	if(!cert_pem) {
		return NULL;
	}

	/* Parse PEM to X509 */
	BIO *bio = BIO_new_mem_buf(cert_pem, -1);
	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if(!cert) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to parse certificate for fingerprint: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	char *result = calculate_cert_fingerprint_x509(cert);
	X509_free(cert);

	return result;
}
