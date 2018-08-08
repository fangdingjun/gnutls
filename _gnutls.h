#ifndef _GNUTLS_H
#define _GNUTLS_H
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct session
{
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
	void *data;
};

extern int onDataReadCallback(void *, char *, int);
extern int onDataWriteCallback(void *, char *, int);
extern int onDataTimeoutRead(void *, int);

struct session *init_gnutls_client_session();
struct session *init_gnutls_server_session();

int pull_timeout_function(gnutls_transport_ptr_t ptr, unsigned int ms);
ssize_t pull_function(gnutls_transport_ptr_t ptr, void *data, size_t len);
ssize_t push_function(gnutls_transport_ptr_t ptr, const void *data, size_t len);

void set_data(struct session *sess, size_t data);
int handshake(struct session *sess);
int set_callback(struct session *sess);

void session_destroy(struct session *);

int onCertSelectCallback(void *ptr, char *hostname, int namelen,
						 int *pcert_length, gnutls_pcert_st **cert, gnutls_privkey_t *privke);

gnutls_cipher_hd_t new_cipher(int cipher_type, char *key, int keylen, char *iv, int ivlen);

gnutls_hash_hd_t new_hash(int t);

int alpn_set_protocols(struct session *sess, char **, int);
int alpn_get_selected_protocol(struct session *sess, char *buf);

gnutls_privkey_t load_privkey(char *keyfile, int *);
gnutls_pcert_st *load_cert_list(char *certfile, int *, int *);

int get_pcert_alt_name(gnutls_pcert_st *st, int index, int nameindex, char *out);

int get_cert_str(gnutls_pcert_st *st, int index, int flag, char *out);

int get_cert_issuer_dn(gnutls_pcert_st *st, int index, char *out);

int get_cert_dn(gnutls_pcert_st *st, int index, char *out);

void free_cert_list(gnutls_pcert_st *st, int size);
gnutls_pcert_st *get_peer_certificate(gnutls_session_t sess, int *pcert_length);
int cert_check_hostname(gnutls_pcert_st *st, int len, char *hostname);

void init_priority_cache();
void init_xcred();
#endif