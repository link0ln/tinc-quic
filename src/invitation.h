#ifndef TINC_INVITATION_H
#define TINC_INVITATION_H

/*
    invitation.h -- header for invitation.c.
    Copyright (C) 2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "connection.h"

/* CLI commands (used by tincctl) */
int cmd_invite(int argc, char *argv[]);
int cmd_join(int argc, char *argv[]);

/*
 * Create an invitation for a new node.
 * Called from control socket handler (REQ_INVITE).
 *
 * @param name   Name of the node to invite
 * @param url    Output: invitation URL (caller must free)
 * @return 0 on success, negative error code on failure:
 *         -1: Invalid arguments
 *         -2: Node already exists
 *         -3: No CA authority (ca-key.pem missing)
 *         -4: Failed to create invitation
 */
int create_invitation(const char *name, char **url);

/*
 * Process a join request from control socket.
 * Called from control socket handler (REQ_JOIN).
 *
 * @param c      Control connection to send status updates
 * @param host   Inviter's host address
 * @param port   Inviter's port
 * @param token  Invitation token
 * @return 0 on success, negative error code on failure
 */
int process_join_request(connection_t *c, const char *host, const char *port, const char *token);

/*
 * Validate an incoming invitation token from QUIC connection.
 * Called from QUIC protocol handler (INVITE_JOIN).
 *
 * @param token       Base64-encoded invitation token
 * @param name        Output: assigned node name (caller must free)
 * @param vpn_address Output: allocated VPN address (caller must free, may be NULL)
 * @return true if token is valid, false otherwise
 */
bool validate_invitation_token(const char *token, char **name, char **vpn_address);

/*
 * Handle incoming CSR during join process.
 * Called from QUIC protocol handler (INVITE_CSR).
 *
 * @param csr_pem     CSR in PEM format
 * @param fingerprint Joiner's certificate fingerprint
 * @param cert_pem    Output: signed certificate in PEM format (caller must free)
 * @return true on success
 */
bool handle_join_csr(const char *csr_pem, const char *fingerprint, char **cert_pem);

#endif
