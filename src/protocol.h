#ifndef TINC_PROTOCOL_H
#define TINC_PROTOCOL_H

/*
    protocol.h -- header for protocol.c
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>

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

/* Protocol version. Different major versions are incompatible. */

#define PROT_MAJOR 17
#define PROT_MINOR 7 /* Should not exceed 255! */

/* Silly Windows */

#ifdef ERROR
#undef ERROR
#endif

/* Request numbers */

typedef enum request_t {
	ALL = -1,                                       /* Guardian for allow_request */
	ID = 0, METAKEY, CHALLENGE, CHAL_REPLY, ACK,
	STATUS, ERROR, TERMREQ,
	PING, PONG,
	ADD_SUBNET, DEL_SUBNET,
	ADD_EDGE, DEL_EDGE,
	KEY_CHANGED, REQ_KEY, ANS_KEY,
	PACKET,
	/* Tinc 1.1 requests */
	CONTROL,
	REQ_PUBKEY, ANS_PUBKEY,
	/* SPTPS_PACKET removed */
	UDP_INFO, MTU_INFO,
	/* Invitation protocol requests */
	INVITE_JOIN,     /* Joining node sends token to inviter */
	INVITE_DATA,     /* Inviter sends CA cert and network config */
	INVITE_CSR,      /* Joining node sends CSR */
	INVITE_CERT,     /* Inviter sends signed certificate */
	LAST                                            /* Guardian for the highest request number */
} request_t;

typedef struct past_request_t {
	const char *request;
	time_t firstseen;
} past_request_t;

extern bool tunnelserver;
extern bool strictsubnets;
extern bool experimental;

extern int invitation_lifetime;

/* Maximum size of strings in a request.
 * scanf terminates %2048s with a NUL character,
 * but the NUL character can be written after the 2048th non-NUL character.
 */

#define MAX_STRING_SIZE 2049
#define MAX_STRING "%2048s"

#include "edge.h"
#include "net.h"
#include "node.h"
#include "subnet.h"

/* Basic functions */

extern bool send_request(struct connection_t *c, const char *format, ...) __attribute__((__format__(printf, 2, 3)));
extern void forward_request(struct connection_t *c, const char *request);
extern bool receive_request(struct connection_t *c, const char *request);

extern void init_requests(void);
extern void exit_requests(void);
extern bool seen_request(const char *request);

/* Requests */

extern bool send_id(struct connection_t *c);
extern bool send_ack(struct connection_t *c);
extern bool send_termreq(struct connection_t *c);
extern bool send_ping(struct connection_t *c);
extern bool send_pong(struct connection_t *c);
extern bool send_add_subnet(struct connection_t *c, const struct subnet_t *subnet);
extern bool send_del_subnet(struct connection_t *c, const struct subnet_t *subnet);
extern bool send_add_edge(struct connection_t *c, const struct edge_t *e);
extern bool send_del_edge(struct connection_t *c, const struct edge_t *e);
extern bool send_udp_info(struct node_t *from, struct node_t *to);
extern bool send_mtu_info(struct node_t *from, struct node_t *to, int mtu);

/* Request handlers  */

extern bool id_h(struct connection_t *c, const char *request);
extern bool ack_h(struct connection_t *c, const char *request);
extern bool status_h(struct connection_t *c, const char *request);
extern bool error_h(struct connection_t *c, const char *request);
extern bool termreq_h(struct connection_t *c, const char *request);
extern bool ping_h(struct connection_t *c, const char *request);
extern bool pong_h(struct connection_t *c, const char *request);
extern bool add_subnet_h(struct connection_t *c, const char *request);
extern bool del_subnet_h(struct connection_t *c, const char *request);
extern bool add_edge_h(struct connection_t *c, const char *request);
extern bool del_edge_h(struct connection_t *c, const char *request);
extern bool control_h(struct connection_t *c, const char *request);
extern bool udp_info_h(struct connection_t *c, const char *request);
extern bool mtu_info_h(struct connection_t *c, const char *request);

/* Invitation protocol handlers */
extern bool invite_join_h(struct connection_t *c, const char *request);
extern bool invite_data_h(struct connection_t *c, const char *request);
extern bool invite_csr_h(struct connection_t *c, const char *request);
extern bool invite_cert_h(struct connection_t *c, const char *request);

/* Invitation protocol senders */
extern bool send_invite_join(struct connection_t *c, const char *token);
extern bool send_invite_data(struct connection_t *c, const char *name, const char *vpn_address);
extern bool send_invite_csr(struct connection_t *c, const char *csr_pem);
extern bool send_invite_cert(struct connection_t *c, const char *cert_pem, const char *fingerprint);

#endif
