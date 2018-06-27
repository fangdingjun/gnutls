#include "_gnutls.h"

#define MAX_BUF 1024
char buffer[MAX_BUF + 1], *desc;
gnutls_datum_t out;
int status;
int type;

struct session *init_client_session()
{
	struct session *sess = malloc(sizeof(struct session));
	memset(sess, sizeof(struct session), 0);
	gnutls_init(&sess->session, GNUTLS_CLIENT);
	gnutls_certificate_allocate_credentials(&sess->xcred);
	gnutls_certificate_set_x509_system_trust(sess->xcred);
	gnutls_set_default_priority(sess->session);
	gnutls_credentials_set(sess->session, GNUTLS_CRD_CERTIFICATE, sess->xcred);
	return sess;
}

struct session *init_server_session()
{
	struct session *sess = malloc(sizeof(struct session));
	memset(sess, sizeof(struct session), 0);
	gnutls_init(&sess->session, GNUTLS_SERVER);
	gnutls_certificate_allocate_credentials(&sess->xcred);
	gnutls_certificate_set_x509_system_trust(sess->xcred);
	gnutls_set_default_priority(sess->session);
	gnutls_credentials_set(sess->session, GNUTLS_CRD_CERTIFICATE, sess->xcred);
	gnutls_certificate_server_set_request(sess->session, GNUTLS_CERT_IGNORE);
	return sess;
}

int set_keyfile(struct session *sess, char *crtfile, char *keyfile)
{
	return gnutls_certificate_set_x509_key_file(
		sess->xcred, crtfile, keyfile, GNUTLS_X509_FMT_PEM);
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

void set_servername(struct session *sess, char *servername, int namelen)
{
	gnutls_server_name_set(sess->session, GNUTLS_NAME_DNS, servername, namelen);
	gnutls_session_set_verify_cert(sess->session, NULL, 0);
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

int read_application_data(struct session *sess, char *data, int buflen)
{
	int ret = gnutls_record_recv(sess->session, data, buflen);
	return ret;
}

int write_application_data(struct session *sess, char *data, int datalen)
{
	int ret = gnutls_record_send(sess->session, data, datalen);
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

int cipher_get_block_size(int t)
{
	return gnutls_cipher_get_block_size(t);
}

int cipher_get_iv_size(int t)
{
	return gnutls_cipher_get_iv_size(t);
}

gnutls_hash_hd_t new_hash(int t)
{
	gnutls_hash_hd_t hash;
	gnutls_hash_init(&hash, t);
	return hash;
}

int get_hash_len(int t)
{
	return gnutls_hash_get_len(t);
}