#ifndef _GNUTLS_H
#define _GNUTLS_H
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct session
{
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
	int handshake;
	void *data;
};

extern int DataRead(void *, char *, int);
extern int DataWrite(void *, char *, int);
extern int DataTimeoutPull(void *, int);

struct session *init_client_session();
struct session *init_server_session();

int pull_timeout_function(gnutls_transport_ptr_t ptr, unsigned int ms);
ssize_t pull_function(gnutls_transport_ptr_t ptr, void *data, size_t len);
ssize_t push_function(gnutls_transport_ptr_t ptr, const void *data, size_t len);

void set_data(struct session *sess, size_t data);
void set_servername(struct session *sess, char *servername, int namelen);
int handshake(struct session *sess);
int set_callback(struct session *sess);
int set_keyfile(struct session *, char *, char *);

int write_application_data(struct session *sess, char *data, int datalen);
int read_application_data(struct session *sess, char *data, int buflen);

void session_destroy(struct session *);

gnutls_cipher_hd_t new_cipher(int cipher_type, char *key, int keylen, char *iv, int ivlen);

gnutls_hash_hd_t new_hash(int t);

int get_hash_len(int);
int cipher_get_block_size(int);
int cipher_get_iv_size(int);

#endif