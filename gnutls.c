#include "_gnutls.h"

#define MAX_BUF 1024
char buffer[MAX_BUF + 1], *desc;
gnutls_datum_t out;
int status;
int type;

int _init_session(struct session *);
int cert_select_callback(gnutls_session_t sess, const gnutls_datum_t *req_ca_dn,
						 int nreqs, const gnutls_pk_algorithm_t *pk_algos,
						 int pk_algos_length, gnutls_pcert_st **pcert,
						 unsigned int *pcert_length, gnutls_privkey_t *pkey);

struct session *init_gnutls_client_session()
{
	struct session *sess = malloc(sizeof(struct session));
	memset(sess, sizeof(struct session), 0);

	gnutls_init(&sess->session, GNUTLS_CLIENT);
	_init_session(sess);

	return sess;
}

struct session *init_gnutls_server_session()
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
	gnutls_certificate_set_retrieve_function2(sess->xcred, cert_select_callback);
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

int cert_select_callback(gnutls_session_t sess, const gnutls_datum_t *req_ca_dn,
						 int nreqs, const gnutls_pk_algorithm_t *pk_algos,
						 int pk_algos_length, gnutls_pcert_st **pcert,
						 unsigned int *pcert_length, gnutls_privkey_t *pkey)
{
	char hostname[100];
	int namelen = 100;
	int type = GNUTLS_NAME_DNS;
	int ret;
	void *ptr;

	//printf("cert_select callback\n");
	if (sess == NULL)
	{
		//printf("session is NULL\n");
		return -1;
	}
	ptr = gnutls_session_get_ptr(sess);
	if (ptr == NULL)
	{
		//printf("ptr is NULL\n");
		return -1;
	}
	ret = gnutls_server_name_get(sess, hostname, (size_t *)(&namelen), &type, 0);
	if (ret < 0)
	{
		//printf("get server name error: %s\n", gnutls_strerror(ret));
		namelen = 0;
		//return -1;
	}
	//printf("call go callback\n");
	ret = onCertSelectCallback(ptr, hostname, namelen, pcert_length, pcert, pkey);
	//printf("after callback pcert_length %d, pcert 0x%x, pkey 0x%x\n", *pcert_length, pcert, pkey);
	return ret;
}

ssize_t pull_function(gnutls_transport_ptr_t ptr, void *data, size_t len)
{
	return onDataReadCallback(ptr, data, len);
}

int pull_timeout_function(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	return onDataTimeoutRead(ptr, ms);
}

ssize_t push_function(gnutls_transport_ptr_t ptr, const void *data, size_t len)
{
	return onDataWriteCallback(ptr, (char *)data, len);
}

void set_data(struct session *sess, size_t data)
{
	sess->data = (void *)((int *)data);
}

int handshake(struct session *sess)
{

	int ret;
	do
	{
		ret = gnutls_handshake(sess->session);
		//printf("handshake ret %d\n", ret);
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
		//fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));
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
		printf("set callback failed\n");
		return -1;
	}
	gnutls_transport_set_ptr(sess->session, sess->data);
	gnutls_session_set_ptr(sess->session, sess->data);
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

int alpn_set_protocols(struct session *sess, char **names, int namelen)
{
	gnutls_datum_t *t;
	int ret;
	int i;

	t = (gnutls_datum_t *)malloc(namelen * sizeof(gnutls_datum_t));
	for (i = 0; i < namelen; i++)
	{
		t[i].data = names[i];
		t[i].size = strlen(names[i]);
	}

	ret = gnutls_alpn_set_protocols(sess->session, t,
									namelen,
									GNUTLS_ALPN_SERVER_PRECEDENCE);
	free(t);
	return ret;
}

int alpn_get_selected_protocol(struct session *sess, char *buf)
{
	gnutls_datum_t p;
	int ret;
	memset(&p, 0, sizeof(gnutls_datum_t));
	ret = gnutls_alpn_get_selected_protocol(sess->session, &p);
	if (ret < 0)
	{
		return ret;
	}
	strcpy(buf, p.data);

	// note: p.data is constant value, only valid during the session life

	return 0;
}

void free_cert_list(gnutls_pcert_st *st, int size)
{
	int i;
	gnutls_pcert_st *st1;
	for (i = 0; i < size; i++)
	{
		st1 = st + i;
		gnutls_pcert_deinit(st1);
	}
	free(st);
}

gnutls_pcert_st *load_cert_list(char *certfile, int *cert_size, int *retcode)
{
	gnutls_datum_t data;
	int maxsize = 10;
	int ret;
	gnutls_pcert_st *st = malloc(10 * sizeof(gnutls_pcert_st));
	ret = gnutls_load_file(certfile, &data);
	if (ret < 0)
	{
		//printf("load file failed: %s", gnutls_strerror(ret));
		*retcode = ret;
		free(st);
		return NULL;
	}
	ret = gnutls_pcert_list_import_x509_raw(
		st, &maxsize, &data, GNUTLS_X509_FMT_PEM, 0);
	if (ret < 0)
	{
		gnutls_free(data.data);
		//printf("import certificate failed: %s", gnutls_strerror(ret));
		*retcode = ret;
		free(st);
		return NULL;
	}
	gnutls_free(data.data);
	*cert_size = maxsize;
	*retcode = 0;
	return st;
}

gnutls_privkey_t load_privkey(char *keyfile, int *retcode)
{
	gnutls_privkey_t privkey;
	gnutls_datum_t data;
	int ret;
	ret = gnutls_load_file(keyfile, &data);
	if (ret < 0)
	{
		//printf("load file failed: %s", gnutls_strerror(ret));
		*retcode = ret;
		return NULL;
	}
	gnutls_privkey_init(&privkey);
	ret = gnutls_privkey_import_x509_raw(
		privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0)
	{
		//printf("import privkey failed: %s", gnutls_strerror(ret));
		*retcode = ret;
		gnutls_free(data.data);
		gnutls_privkey_deinit(privkey);
		return NULL;
	}
	gnutls_free(data.data);
	*retcode = 0;
	return privkey;
}

int get_pcert_alt_name(
	gnutls_pcert_st *st, int index, int nameindex, char *out)
{
	gnutls_x509_crt_t crt;
	int ret;
	char data[1024];
	size_t size = 1024;
	gnutls_pcert_st *st1 = st + index;
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
	{
		return ret;
	}
	ret = gnutls_pcert_export_x509(st1, &crt);
	if (ret < 0)
	{
		goto err;
	}
	ret = gnutls_x509_crt_get_subject_alt_name(
		crt, nameindex, (void *)data, &size, NULL);
	if (ret < 0)
	{
		goto err;
	}
	//gnutls_x509_crt_deinit(crt);
	memcpy(out, data, size);
	//return size;
	ret = size;
err:
	gnutls_x509_crt_deinit(crt);
	return ret;
}

int get_cert_str(gnutls_pcert_st *st, int index, int flag, char *out)
{
	gnutls_x509_crt_t crt;
	int ret;
	gnutls_datum_t data;
	gnutls_pcert_st *st1 = st + index;
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
	{
		return ret;
	}
	ret = gnutls_pcert_export_x509(st1, &crt);
	if (ret < 0)
	{
		goto err;
	}
	ret = gnutls_x509_crt_print(crt, flag, &data);
	if (ret < 0)
	{
		goto err;
	}
	memcpy(out, data.data, data.size);
	ret = data.size;
	gnutls_free(data.data);
//gnutls_x509_crt_deinit(crt);
//return data.size;
err:
	gnutls_x509_crt_deinit(crt);
	return ret;
}

int get_cert_dn(gnutls_pcert_st *st, int index, char *out)
{

	gnutls_x509_crt_t crt;
	int ret;
	char data[200];
	size_t size = 200;
	gnutls_pcert_st *st1 = st + index;
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
	{
		return ret;
	}
	ret = gnutls_pcert_export_x509(st1, &crt);
	if (ret < 0)
	{
		goto err;
	}
	ret = gnutls_x509_crt_get_dn(crt, data, &size);
	if (ret < 0)
	{
		goto err;
	}
	//gnutls_x509_crt_deinit(crt);
	memcpy(out, data, size);
	//return size;
	ret = size;
err:
	gnutls_x509_crt_deinit(crt);
	return ret;
}

int get_cert_issuer_dn(gnutls_pcert_st *st, int index, char *out)
{

	gnutls_x509_crt_t crt;
	int ret;
	char data[200];
	size_t size = 200;
	gnutls_pcert_st *st1 = st + index;
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
	{
		return ret;
	}
	ret = gnutls_pcert_export_x509(st1, &crt);
	if (ret < 0)
	{
		goto err;
	}
	ret = gnutls_x509_crt_get_issuer_dn(crt, data, &size);
	if (ret < 0)
	{
		goto err;
	}
	//gnutls_x509_crt_deinit(crt);
	memcpy(out, data, size);
	//return size;
	ret = size;
err:
	gnutls_x509_crt_deinit(crt);
	return ret;
}

gnutls_pcert_st *get_peer_certificate(gnutls_session_t sess, int *pcert_length)
{
	const gnutls_datum_t *raw_certs;
	const gnutls_datum_t *d;
	gnutls_pcert_st *st, *st1;
	int ret;
	int i;
	*pcert_length = 0;
	raw_certs = gnutls_certificate_get_peers(sess, pcert_length);
	if (pcert_length == NULL)
	{
		//printf("pcert length is NULL\n");
		return NULL;
	}
	if (*pcert_length == 0)
	{
		//printf("pcert length is 0\n");
		return NULL;
	}
	//printf("pcert length %d\n", *pcert_length);
	st = malloc((*pcert_length) * sizeof(gnutls_pcert_st));
	for (i = 0; i < *pcert_length; i++)
	{
		st1 = st + i;
		d = raw_certs + i;
		ret = gnutls_pcert_import_x509_raw(st1, d, GNUTLS_X509_FMT_DER, 0);
		if (ret < 0)
		{
			printf("import cert failed: %s\n", gnutls_strerror(ret));
		}
	}
	return st;
}

int cert_check_hostname(gnutls_pcert_st *st, int len, char *hostname)
{
	int i;
	int ret;
	int allow = 0;
	gnutls_x509_crt_t crt;
	for (i = 0; i < len; i++)
	{
		gnutls_x509_crt_init(&crt);
		ret = gnutls_pcert_export_x509((st + i), &crt);
		if (ret < 0)
		{
			gnutls_x509_crt_deinit(crt);
			return ret;
		}
		ret = gnutls_x509_crt_check_hostname(crt, hostname);
		if (ret != 0)
		{
			allow = 1;
			gnutls_x509_crt_deinit(crt);
			break;
		}
		gnutls_x509_crt_deinit(crt);
	}
	return allow;
}