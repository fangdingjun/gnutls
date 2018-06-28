#include "_gnutls.h"

#define MAX_BUF 1024
char buffer[MAX_BUF + 1], *desc;
gnutls_datum_t out;
int status;
int type;

int _init_session(struct session *);

struct session *init_client_session()
{
	struct session *sess = malloc(sizeof(struct session));
	memset(sess, sizeof(struct session), 0);

	gnutls_init(&sess->session, GNUTLS_CLIENT);
	_init_session(sess);

	return sess;
}

struct session *init_server_session()
{
	struct session *sess = malloc(sizeof(struct session));
	memset(sess, sizeof(struct session), 0);

	gnutls_init(&sess->session, GNUTLS_SERVER);
	_init_session(sess);

	gnutls_certificate_server_set_request(sess->session, GNUTLS_CERT_IGNORE);

	return sess;
}

int _init_session(struct session *sess)
{
	gnutls_certificate_allocate_credentials(&sess->xcred);
	gnutls_certificate_set_x509_system_trust(sess->xcred);
	gnutls_set_default_priority(sess->session);
	gnutls_credentials_set(sess->session, GNUTLS_CRD_CERTIFICATE, sess->xcred);

	return 0;
}

void session_destroy(struct session *sess)
{
	gnutls_bye(sess->session, GNUTLS_SHUT_WR);
	gnutls_deinit(sess->session);
	gnutls_certificate_free_credentials(sess->xcred);
	free(sess);
}

ssize_t pull_function(gnutls_transport_ptr_t ptr, void *data, size_t len)
{
	return DataRead(ptr, data, len);
}

int pull_timeout_function(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	return DataTimeoutPull(ptr, ms);
}

ssize_t push_function(gnutls_transport_ptr_t ptr, const void *data, size_t len)
{
	return DataWrite(ptr, (char *)data, len);
}

void set_data(struct session *sess, size_t data)
{
	sess->data = (void *)((int *)data);
}

int handshake(struct session *sess)
{
	if (sess->handshake > 0)
	{
		return 0;
	}

	int ret;
	do
	{
		ret = gnutls_handshake(sess->session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0)
	{
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
		{
			// check certificate verification status
			type = gnutls_certificate_type_get(sess->session);
			status = gnutls_session_get_verify_cert_status(sess->session);
			gnutls_certificate_verification_status_print(status,
														 type, &out, 0);
			printf("cert verify output: %s\n", out.data);
			gnutls_free(out.data);
		}
		fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));
	} /*else{
		desc = gnutls_session_get_desc(sess->session);
		printf("- Session info: %s\n", desc);
		gnutls_free(desc);
	}*/
	return ret;
}

int set_callback(struct session *sess)
{
	if (sess->data == NULL)
	{
		return -1;
	}
	gnutls_transport_set_ptr(sess->session, sess->data);
	gnutls_transport_set_pull_function(sess->session, pull_function);
	gnutls_transport_set_push_function(sess->session, push_function);
	gnutls_transport_set_pull_timeout_function(sess->session, pull_timeout_function);
	return 0;
}

gnutls_cipher_hd_t new_cipher(int cipher_type, char *key, int keylen, char *iv, int ivlen)
{
	gnutls_cipher_hd_t handle;
	gnutls_datum_t _key;
	gnutls_datum_t _iv;

	_key.data = key;
	_key.size = keylen;
	_iv.data = iv;
	_iv.size = ivlen;

	int ret = gnutls_cipher_init(&handle, cipher_type, &_key, &_iv);
	if (ret < 0)
	{
		printf("new cipher: %s\n", gnutls_strerror(ret));
		return NULL;
	}
	//printf("new cipher done\n");
	//cipher->handle = handle;
	return handle;
}

gnutls_hash_hd_t new_hash(int t)
{
	gnutls_hash_hd_t hash;
	gnutls_hash_init(&hash, t);
	return hash;
}
