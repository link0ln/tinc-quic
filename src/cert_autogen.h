/*
    cert_autogen.h -- Automatic TLS certificate generation
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

#ifndef TINC_CERT_AUTOGEN_H
#define TINC_CERT_AUTOGEN_H

#include <stdbool.h>

/*
 * Ensure QUIC TLS certificates exist in the configuration directory.
 *
 * If any of the required certificate files are missing, this function
 * generates new self-signed certificates:
 *   - quic-cert.pem: Node certificate (X.509)
 *   - quic-key.pem: Private key (RSA 2048-bit)
 *   - ca.crt: CA certificate (same as node cert for self-signed)
 *
 * @param confbase  Path to the tinc configuration directory
 * @param node_name Name of this node (used as certificate CN)
 * @return true if certificates exist or were generated successfully
 */
extern bool ensure_quic_certificates(const char *confbase, const char *node_name);

/*
 * Generate CA key and certificate for invite/join mechanism.
 *
 * Creates:
 *   - ca-key.pem: CA private key (RSA 4096-bit)
 *   - ca.crt: CA certificate (self-signed, 10 years validity)
 *
 * @param confbase  Path to the tinc configuration directory
 * @return true if CA was generated successfully
 */
extern bool generate_ca(const char *confbase);

/*
 * Check if this node has CA authority (ca-key.pem exists).
 *
 * @param confbase  Path to the tinc configuration directory
 * @return true if ca-key.pem exists and is readable
 */
extern bool has_ca_authority(const char *confbase);

/*
 * Sign a Certificate Signing Request (CSR) with the CA key.
 *
 * @param confbase  Path to the tinc configuration directory
 * @param csr_pem   CSR in PEM format
 * @param cert_pem  Output: signed certificate in PEM format (caller must free)
 * @return true if CSR was signed successfully
 */
extern bool sign_csr(const char *confbase, const char *csr_pem, char **cert_pem);

/*
 * Generate a CSR for this node.
 *
 * @param node_name  Name of this node (used as CN)
 * @param key_pem    Output: generated private key in PEM format (caller must free)
 * @param csr_pem    Output: CSR in PEM format (caller must free)
 * @return true if CSR was generated successfully
 */
extern bool generate_csr(const char *node_name, char **key_pem, char **csr_pem);

/*
 * Calculate SHA256 fingerprint of a certificate.
 *
 * @param cert_pem  Certificate in PEM format
 * @return fingerprint string "SHA256:base64..." (caller must free), or NULL on error
 */
extern char *calculate_cert_fingerprint(const char *cert_pem);

/*
 * Calculate SHA256 fingerprint of an X509 certificate object.
 *
 * @param cert  X509 certificate object
 * @return fingerprint string "SHA256:base64..." (caller must free), or NULL on error
 */
extern char *calculate_cert_fingerprint_x509(void *cert);

#endif /* TINC_CERT_AUTOGEN_H */
