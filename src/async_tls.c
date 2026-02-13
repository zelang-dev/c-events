#define NO_REDEF_POSIX_FUNCTIONS
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#   include <openssl/engine.h>
#endif
#include <openssl/rand.h>
#include "events_internal.h"

#ifdef _WIN32
#include <Wincrypt.h>
/* These are from Wincrypt.h, they conflict with OpenSSL */
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#endif

static char default_ssl_conf_filename[MAXHOSTNAMELEN];
static char os_tls_host[MAXHOSTNAMELEN] = {0};
static char os_tls_directory[MAXHOSTNAMELEN] = {0};
static char os_tls_ca_cert[MAXHOSTNAMELEN + 4] = {0};
static char os_tls_cert[MAXHOSTNAMELEN + 4] = {0};
static char os_tls_csr[MAXHOSTNAMELEN + 4] = {0};
static char os_tls_pkey[MAXHOSTNAMELEN + 4] = {0};
static char os_tls_self_touch[MAXHOSTNAMELEN + 6] = {0};

struct x509_request {
    CONF *global_config;	/* Global SSL config */
    CONF *req_config;		/* SSL config for this request */
    const EVP_MD *md_alg;
    const EVP_MD *digest;
    char *section_name,
        config_filename,
        digest_name,
        extensions_section,
        request_extensions_section;
    int priv_key_bits;
    int priv_key_type;
    int priv_key_encrypt;
    int curve_name;

#ifdef HAVE_EVP_PKEY_EC
#endif

    EVP_PKEY *priv_key;
    const EVP_CIPHER *priv_key_encrypt_cipher;
};

enum os_tls_ssl_key_type {
    OPENSSL_KEYTYPE_RSA,
    OPENSSL_KEYTYPE_DSA,
    OPENSSL_KEYTYPE_DH,
    OPENSSL_KEYTYPE_EC,
    OPENSSL_KEYTYPE_DEFAULT = OPENSSL_KEYTYPE_RSA
};

enum os_tls_cipher_type {
    CIPHER_RC2_40,
    CIPHER_RC2_128,
    CIPHER_RC2_64,
    CIPHER_DES,
    CIPHER_3DES,
    CIPHER_AES_128_CBC,
    CIPHER_AES_192_CBC,
    CIPHER_AES_256_CBC,
    CIPHER_DEFAULT = CIPHER_AES_128_CBC
};

typedef enum {
	ssl_generate_pkey = ca_file + 1,
	ssl_create_self,
	ssl_x509_pkey_write,
	ssl_worker
} thrd_worker_types;

enum {
	http_incomplete = 1 << 0,
	http_keepalive = 1 << 1,
	http_outgoing = 1 << 2,
};

typedef struct {
	ssize_t status;
	size_t max;
	unsigned char *buf;
	tasks_t *thread;
} tls_state;

#define READ_BUFFER (1024 * 8)
#define WRITE_BUFFER (1024 * 8)

static volatile bool tls_is_self_signed = false;
static const EVP_CIPHER *get_cipher(long algo) {
    switch (algo) {
        case CIPHER_RC2_40:
            return EVP_rc2_40_cbc();
            break;
        case CIPHER_RC2_64:
            return EVP_rc2_64_cbc();
            break;
        case CIPHER_RC2_128:
            return EVP_rc2_cbc();
            break;
        case CIPHER_DES:
            return EVP_des_cbc();
            break;
        case CIPHER_3DES:
            return EVP_des_ede3_cbc();
            break;
        case CIPHER_AES_128_CBC:
            return EVP_aes_128_cbc();
            break;
        case CIPHER_AES_192_CBC:
            return EVP_aes_192_cbc();
            break;
        case CIPHER_AES_256_CBC:
            return EVP_aes_256_cbc();
            break;
        default:
            return NULL;
            break;
    }
}

static bool add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value) {
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return false;
    sk_X509_EXTENSION_push((struct stack_st_X509_EXTENSION*)sk, ex);
    return true;
}

static bool config_check(const char *section_label, const char *config_filename, const char *sections, CONF *config) {
    X509V3_CTX ctx;

    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, config);
    if (!X509V3_EXT_add_nconf(config, &ctx, (char *)sections, NULL)) {
        events_ssl_error();
        cerr("Error loading %s section %s of %s", section_label, sections, config_filename);
        return false;
    }

    return true;
}

static char *conf_string(CONF *conf, const char *group, const char *name) {
    /* OpenSSL reports an error if a configuration value is not found.
     * However, we don't want to generate errors for optional configuration. */
    ERR_set_mark();
    char *str = NCONF_get_string(conf, group, name);
    ERR_pop_to_mark();
    return str;
}

static long conf_number(CONF *conf, const char *group, const char *name) {
    long res = 0;
    ERR_set_mark();
    NCONF_get_number(conf, group, name, &res);
    ERR_pop_to_mark();
    return res;
}

static void dispose_config(struct x509_request *req) {
	if (req->priv_key) {
        EVP_PKEY_free(req->priv_key);
        req->priv_key = NULL;
    }

    if (req->global_config) {
        NCONF_free(req->global_config);
        req->global_config = NULL;
    }

    if (req->req_config) {
        NCONF_free(req->req_config);
        req->req_config = NULL;
    }
}

#if defined(_WIN32) || OPENSSL_API_VERSION >= 0x10100
#   define RAND_ADD_TIME() ((void) 0)
#else
#   define RAND_ADD_TIME() rand_add_timeval()

static inline void rand_add_timeval(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    RAND_add(&tv, sizeof(tv), 0.0);
}
#endif

static int load_rand_file(const char *file, int *egdsocket, int *seeded) {
	char buffer[MAXHOSTNAMELEN];

    *egdsocket = 0;
    *seeded = 0;

    if (file == NULL) {
        file = RAND_file_name(buffer, sizeof(buffer));
    }

    if (file == NULL || !RAND_load_file(file, -1)) {
        if (RAND_status() == 0) {
            events_ssl_error();
            perror("Unable to load random state; not enough random data!");
            return false;
        }
        return false;
    }
    *seeded = 1;
    return true;
}

static int write_rand_file(const char *file, int egdsocket, int seeded) {
	char buffer[MAXHOSTNAMELEN];

    if (egdsocket || !seeded) {
        /* if we did not manage to read the seed file, we should not write
         * a low-entropy seed file back */
        return false;
    }
    if (file == NULL) {
        file = RAND_file_name(buffer, sizeof(buffer));
    }
    RAND_ADD_TIME();
    if (file == NULL || !RAND_write_file(file)) {
        events_ssl_error();
        perror("Unable to write random state");
        return false;
    }

    return true;
}

static int evp_pkey_type(int key_type) {
    switch (key_type) {
        case OPENSSL_KEYTYPE_RSA:
            return EVP_PKEY_RSA;
        case OPENSSL_KEYTYPE_DSA:
            return EVP_PKEY_DSA;
        case OPENSSL_KEYTYPE_DH:
            return EVP_PKEY_DH;
        case OPENSSL_KEYTYPE_EC:
          return EVP_PKEY_EC;
        default:
            return -1;
    }
}

#define PKEY_MIN_LENGTH		384
static EVP_PKEY *gen_private_key(struct x509_request *req) {
    if (req->priv_key_bits < PKEY_MIN_LENGTH) {
        cerr("Private key length must be at least %d bits, configured to %d", PKEY_MIN_LENGTH, req->priv_key_bits);
        return NULL;
    }

    int type = req->priv_key_type;
    if (type < 0) {
        perror("Unsupported private key type");
        return NULL;
    }

    int egdsocket, seeded;
    char *randfile = conf_string(req->req_config, req->section_name, "RANDFILE");
    load_rand_file(randfile, &egdsocket, &seeded);
    RAND_ADD_TIME();

    EVP_PKEY *key = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!ctx) {
        events_ssl_error();
        goto cleanup;
    }

    if (type != EVP_PKEY_RSA) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0) {
            events_ssl_error();
            goto cleanup;
        }

        switch (type) {
            case EVP_PKEY_DSA:
                if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, req->priv_key_bits) <= 0) {
                    events_ssl_error();
                    goto cleanup;
                }
                break;
            case EVP_PKEY_DH:
                if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, req->priv_key_bits) <= 0) {
                    events_ssl_error();
                    goto cleanup;
                }
                break;
            case EVP_PKEY_EC:
              if (req->curve_name == NID_undef) {
                perror("Missing configuration value: \"curve_name\" not set");
                goto cleanup;
              }
              if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                    ctx, req->curve_name) <= 0 ||
                  EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <=
                    0) {
                events_ssl_error();
                goto cleanup;
              }
              break;
            default:
                break;
        }

        if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
            events_ssl_error();
            goto cleanup;
        }

        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(params, NULL);
        if (!ctx) {
            events_ssl_error();
            goto cleanup;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        events_ssl_error();
        goto cleanup;
    }

    if (type == EVP_PKEY_RSA && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, req->priv_key_bits) <= 0) {
        events_ssl_error();
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        events_ssl_error();
        goto cleanup;
    }

    req->priv_key = key;

cleanup:
    write_rand_file(randfile, egdsocket, seeded);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static bool create_self_ex(EVP_PKEY *pkey, X509 *x509) {
	BIO *x509file = NULL, *pOut = NULL;
	bool no_error = true;
	if (!(pOut = BIO_new_file(pkey_file(), _BIO_MODE_W(PKCS7_BINARY)))) {
		cerr("Unable to open \"%s\" for writing.\n", pkey_file());
		no_error = false;
	} else if (pOut
		&& !PEM_write_bio_PrivateKey(pOut, pkey, NULL, NULL, 0, NULL, NULL)) {
		perror("Unable to write private key to disk.");
		BIO_free_all(pOut);
		no_error = false;
	} else if(pOut) {
		BIO_free_all(pOut);
	}

	if (!(x509file = BIO_new_file(cert_file(), _BIO_MODE_W(PKCS7_BINARY)))) {
		cerr("Unable to open \"%s\" for writing.\n", cert_file());
		no_error = false;
	} else if (x509file && !PEM_write_bio_X509(x509file, x509)) {
		perror("Unable to write certificate to disk.");
		BIO_free_all(x509file);
		no_error = false;
	} else if (x509file) {
		BIO_free_all(x509file);
	}

	return no_error;
}

static bool generate_pkey_ex(EVP_PKEY *pkey, int keylength, int pkey_id) {
	EVP_PKEY_CTX *ctx = NULL;
	bool no_error = true;
	switch (pkey_id) {
		case EVP_PKEY_RSA:
			if (is_empty(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))
				|| (EVP_PKEY_keygen_init(ctx) <= 0)
				|| (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylength) <= 0)
				|| (EVP_PKEY_keygen(ctx, &pkey) <= 0)) {
				events_ssl_error();
				no_error = false;
			}
			break;
		default:
			no_error = false;;
	}

	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return no_error;
}

static array_t thrd_return(array_t args, size_t numof, ...) {
	va_list ap;
	size_t i;
	if (numof > 0) {
		$reset(args);
		va_start(ap, numof);
		for (i = 0; i < numof; i++)
			data_append(args, va_arg(ap, void *));
		va_end(ap);

		return args;
	}

	return null;
}

static void *thrd_worker_thread(param_t args) {
	thrd_worker_types preform = args[0].integer;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	X509_REQ *csr = NULL;
	bool no_error = true;
	switch (preform) {
		case ssl_generate_pkey:
			pkey = args[1].object;
			int keylength = args[2].integer;
			int pkey_id = args[3].integer;
			no_error = generate_pkey_ex(pkey, keylength, pkey_id);
			break;
		case ssl_create_self:
			pkey = EVP_PKEY_new();
			if (no_error = generate_pkey_ex(pkey, 4096, EVP_PKEY_RSA)) {
				no_error = false;
				x509 = x509_self(pkey, NULL, NULL, events_hostname());
				if (x509) {
					no_error = create_self_ex(pkey, x509);
					X509_free(x509);
				}
			}
			EVP_PKEY_free(pkey);
			break;
		case ssl_x509_pkey_write:
			pkey = args[1].object;
			x509 = args[2].object;
			no_error = create_self_ex(pkey, x509);
			break;
		default:
			break;
	}

	return no_error ? casting(true) : null;
}

EVP_PKEY *rsa_pkey(int keylength) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        perror("Unable to create EVP_PKEY structure.");
        return NULL;
    }

	uint32_t fut = queue_work(events_pool(), thrd_worker_thread, 4, casting(ssl_generate_pkey), pkey, casting(keylength), casting(EVP_PKEY_RSA));

	if (!await_for(fut).boolean) {
		EVP_PKEY_free(pkey);
		return NULL;
	}

    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 *x509_self(EVP_PKEY *pkey, const char *country, const char *org, const char *domain) {
    /* Allocate memory for the X509 structure. */
    X509 *x509 = X509_new();
    if (!x509) {
        perror("Unable to create X509 structure.");
        return NULL;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);
    /* Set the country code and common name. */
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)(country == NULL ? "US" : country), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)(org == NULL ? "selfSigned" : org), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)(domain == NULL ? "localhost" : domain), -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        perror("Error signing certificate.");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

EVENTS_INLINE bool x509_self_export(EVP_PKEY *pkey, X509 *x509, const char *path_noext) {
	uint32_t fut = queue_work(events_pool(), thrd_worker_thread, 4, casting(ssl_create_self), pkey, x509, path_noext);

	return await_for(fut).boolean;
}

EVENTS_INLINE bool x509_pkey_write(EVP_PKEY *pkey, X509 *x509) {
	uint32_t fut = queue_work(events_pool(), thrd_worker_thread, 3, casting(ssl_x509_pkey_write), pkey, x509);

	return await_for(fut).boolean;
}

EVP_PKEY *pkey_get(const char *file_path) {
	EVP_PKEY *pkey = NULL;
	BIO *file_in = BIO_new_file(file_path, _BIO_MODE_R(PKCS7_BINARY));
	if (is_empty(file_in))
		return NULL;

	pkey = PEM_read_bio_PrivateKey(file_in, NULL, NULL, NULL);
	BIO_free(file_in);
	if (is_empty(pkey))
		return NULL;

	defer((func_t)EVP_PKEY_free, pkey);
	return pkey;
}

char *x509_str(X509 *cert, bool show_details) {
	char *out = NULL;
	BIO *bio_out;

	if (cert == NULL) {
		perror("X.509 Certificate cannot be retrieved");
		return;
	}

	bio_out = BIO_new(BIO_s_mem());
	if (!bio_out) {
		events_ssl_error();
		goto cleanup;
	}

	if (show_details && !X509_print(bio_out, cert)) {
		events_ssl_error();
	}

	if (PEM_write_bio_X509(bio_out, cert)) {
		BUF_MEM *bio_buf;

		BIO_get_mem_ptr(bio_out, &bio_buf);
		out = str_dup(bio_buf->data);
	} else {
		events_ssl_error();
	}

	BIO_free(bio_out);

cleanup:
	return out;
}

X509 *x509_get(const char *file_path) {
	X509 *cert;
	BIO *file_in = BIO_new_file(file_path, _BIO_MODE_R(PKCS7_BINARY));
	if (is_empty(file_in)) {
		events_ssl_error();
		return NULL;
	}

	cert = PEM_read_bio_X509(file_in, NULL, NULL, NULL);
	if (!BIO_free(file_in)) {
		events_ssl_error();
	}

	if (is_empty(cert)) {
		events_ssl_error();
		return NULL;
	}

	defer((func_t)X509_free, cert);
	return cert;
}

void events_ssl_error(void) {
    int error_code = ERR_get_error();
	char buf[MAXHOSTNAMELEN] = {0};
    if (!error_code)
        return;

    cerr("Error: %s"CLR_LN, ERR_error_string(ERR_get_error(), buf));
}

static void cert_names_setup(void) {
	char *name = (char *)events_hostname();
	if (str_is_empty((const char *)os_tls_cert)) {
		if (!(snprintf(os_tls_cert, sizeof(os_tls_cert), "%s.crt", name))
		|| !(snprintf(os_tls_csr, sizeof(os_tls_csr), "%s.csr", name))
		|| !(snprintf(os_tls_pkey, sizeof(os_tls_pkey), "%s.key", name))
		|| !(snprintf(os_tls_self_touch, sizeof(os_tls_self_touch), "%s.local", name)))
			cerr("Invalid certificate %s names: %s, %s, %s\n", name, os_tls_cert, os_tls_csr, os_tls_pkey);
	}
}

void use_ca_certificate(const char *path) {
	if (str_is_empty((const char *)os_tls_ca_cert)) {
		int r = is_empty(path)
			? snprintf(os_tls_ca_cert, sizeof(os_tls_ca_cert), "%s", X509_get_default_cert_file())
			: snprintf(os_tls_ca_cert, sizeof(os_tls_ca_cert), "%s", path);

		if (!r) {
			perror("Invalid ca trust certificate");
		}
	}
}

EVENTS_INLINE const char *ca_cert_file(void) {
	if (str_is_empty((const char *)os_tls_ca_cert))
		use_ca_certificate(NULL);

	return (const char *)os_tls_ca_cert;
}

EVENTS_INLINE const char *cert_file(void) {
	if (str_is_empty((const char *)os_tls_cert))
		cert_names_setup();

	return (const char *)os_tls_cert;
}

const char *events_hostname(void) {
	if (str_is_empty((const char *)os_tls_host)) {
		if (gethostname(os_tls_host, sizeof(os_tls_host)) != 0) {
			perror("gethostname");
			if (!snprintf(os_tls_host, sizeof(os_tls_host), "localhost"))
				return "localhost";
		}
	}

	return (const char *)os_tls_host;
}

static const char *default_cert_file(char *path) {
	char *name = (char *)events_hostname();
	char *dir = is_empty(path) ? "..\\" SYS_DIRSEP : path;
	if (str_is_empty((const char *)os_tls_directory)) {
		if (!(snprintf(os_tls_directory, sizeof(os_tls_directory), "%s", dir))
			|| !(snprintf(os_tls_cert, sizeof(os_tls_cert), "%s%s.crt", os_tls_directory, name))
			|| !(snprintf(os_tls_csr, sizeof(os_tls_csr), "%s%s.csr", os_tls_directory, name))
			|| !(snprintf(os_tls_pkey, sizeof(os_tls_pkey), "%s%s.key", os_tls_directory, name)))
			cerr("Invalid certificate %s names: %s, %s, %s, %s\n",
			name, os_tls_cert, os_tls_csr, os_tls_pkey, os_tls_directory);
	}

	if (is_empty(path)
		&& (snprintf(os_tls_self_touch, sizeof(os_tls_self_touch), "%s.local", name)))
		return (const char *)os_tls_self_touch;

	return (const char *)os_tls_cert;
}

EVENTS_INLINE const char *csr_file(void) {
	if (str_is_empty((const char *)os_tls_csr))
		cert_names_setup();

	return (const char *)os_tls_csr;
}

EVENTS_INLINE const char *pkey_file(void) {
	if (str_is_empty((const char *)os_tls_pkey))
		cert_names_setup();

	return (const char *)os_tls_pkey;
}

void use_certificate(char *path, uint32_t ctx_pairs, ...) {
	if (is_empty(path)) {
		if (!fs_exists(default_cert_file(path))) {
			if (x509_self_export(NULL, NULL, os_tls_directory))
				fs_touch(os_tls_self_touch);
		}
	} else {
		default_cert_file(path);
	}
}

void events_ssl_init(void) {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* Determine default SSL configuration file */
    char *config_filename = getenv("OPENSSL_CONF");
    if (config_filename == NULL)
        config_filename = getenv("SSLEAY_CONF");

    /* default to 'openssl.cnf' if no environment variable is set */
    if (config_filename == NULL)
        snprintf(default_ssl_conf_filename, sizeof(default_ssl_conf_filename), "%s/%s",
                 X509_get_default_cert_area(),
                 "openssl.cnf");
    else
        snprintf(default_ssl_conf_filename, sizeof(default_ssl_conf_filename), "%s", config_filename);

	tls_init();
}

int cerr(const char *msg, ...) {
	fflush(stdout);
	va_list ap;
	va_start(ap, msg);
	int r = vfprintf(stderr, msg, ap);
	va_end(ap);
	return r;
}

int cout(const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	int r = vfprintf(stdout, msg, ap);
	va_end(ap);
	if (r)
		fflush(stdout);

	return r;
}

static int tlserr(int const rc, struct tls *const secure) {
	if (0 == rc) return 0;
	assert(-1 == rc);
#ifdef USE_DEBUG
	cerr("\n\nTLS error: %s"CLR_LN, tls_error(secure));
	SSL_load_error_strings();
	char x[255 + 1];
	ERR_error_string_n(ERR_get_error(), x, sizeof(x));
	cerr("SSL error: %s"CLR_LN, x);
#endif
	return EPROTO;
}

static int tls_poll(int socket, int event) {
	if (TLS_WANT_POLLIN == event)
		async_wait(socket, 'r');
	else if (TLS_WANT_POLLOUT == event)
		async_wait(socket, 'w');

	events_fd_t *target = events_target(socket);
	return (target->events & EVENTS_READ || target->events & EVENTS_WRITE) ? 0 : EOF;
}

EVENTS_INLINE bool socket_is_secure(int socket) {
	if (!socket) return false;
	return !is_empty(events_target(socket)->tls);
}

bool socket_is_eof(int socket) {
	events_fd_t *target = events_target(socket);
	char buf[1];
	if (!is_empty(target->tls)) {
		if ((tls_read(target->tls, buf, 0) == -1)
			&& (ERR_get_error() == TLS_EOF))
			return true;
	} else {
		if (!recv(fd2socket(socket), buf, 1, MSG_PEEK))
			return true;
	}

	return false;
}

int tls_bind(const char *host, int backlog) {
	fds_t server, has_scheme = str_has(host, "://");
	const char *address = has_scheme ? host : str_cat(2, "tls://", host);
	uri_t *url = parse_uri(address);
	if (!has_scheme)
		events_free((void *)address);

	if (!is_empty(url)) {
		server = async_listener(url->host, url->port, backlog, true);
		if (url->type != DATA_TLS)
			return socket2fd(server);

		events_fd_t *starget = events_target(socket2fd(server));
		starget->tls_config = tls_config_new();
		if (defer(tls_config_free, starget->tls_config) > 0) {
			if (!tls_config_set_keypair_file(starget->tls_config, cert_file(), pkey_file())) {
				starget->tls = tls_server();
				if (defer(tls_free, starget->tls) > 0) {
					if (!tls_configure(starget->tls, starget->tls_config))
						return socket2fd(server);

					cerr("failed to configure bind: %s", tls_error(starget->tls));
				} else {
					cerr("failed to bind: `tls_server`\n");
				}
			} else {
				cerr("failed to set bind: %s\n", tls_config_error(starget->tls_config));
			}
		} else {
			cerr("failed to bind: `tls_config_new`\n");
		}
	}

	return -EINVAL;
}

static int async_tls_accept(int server, int socket) {
	int event, rc = EINVAL;
	if (!server || !socket <= 0)
		return -(rc);

	events_fd_t *starget = events_target(server);
	events_fd_t *ctarget = events_target(socket);
	if (starget->tls) {
		if (!(rc = tlserr(tls_accept_socket(starget->tls, &ctarget->tls, (intptr_t)socket), starget->tls))) {
			for (;;) {
				if (!(event = tls_handshake(ctarget->tls)))
					break;

				event = tls_poll(socket, event);
				ctarget->events = 0;
				if ((rc = tlserr(event, ctarget->tls)) < 0)
					break;
			}
		}
	}

	if (rc < 0)
		async_tls_close(socket);

	return rc;
}

EVENTS_INLINE int tls_accept(int fd, char *server, int *port) {
	return async_tls_accept(fd, socket2fd(async_accept(fd2socket(fd), server, port)));
}

static int async_tls_connect(const char *host, int socket) {
	if (!socket)
		return -EINVAL;

	int event = 0, rc = -ENOMEM;
	events_fd_t *target = events_target(socket);
	if (!is_empty(target->tls = tls_client())) {
		if (tls_is_self_signed)
			tls_config_insecure_noverifycert(target->tls_config);
		else
			tls_config_verify(target->tls_config);

		if (!(rc = tls_configure(target->tls, target->tls_config))) {
			if (!(rc = tlserr(tls_connect_socket(target->tls, (intptr_t)socket, host), target->tls))) {
				for (;;) {
					if (!(event = tls_handshake(target->tls)))
						break;

					event = tls_poll(socket, event);
					target->events = 0;
					if ((rc = tlserr(event, target->tls)) < 0)
						break;
				}
			}
		}
	}

	if (rc < 0)
		async_tls_close(socket);

	return rc;
}

int tls_get(const char *uri) {
	fds_t client, has_scheme = str_has(uri, "://");
	const char *address = has_scheme ? uri : str_cat(2, "tls://", uri);
	uri_t *url = parse_uri(address);
	if (!has_scheme)
		events_free((void *)address);

	if (!is_empty(url)) {
		client = async_connect(url->host, url->port, true);
		int fd = socket2fd(client);
		if (url->type != DATA_TLS)
			return fd;

		events_fd_t *ctarget = events_target(fd);
		ctarget->tls_config = tls_config_new();
		if (defer(tls_config_free, ctarget->tls_config) > 0) {
			if (!tls_config_set_ca_file(ctarget->tls_config, ca_cert_file())
				&& !tls_config_set_keypair_file(ctarget->tls_config, cert_file(), pkey_file())) {
				if (!async_tls_connect(url->host, fd))
					return fd;

				cerr("failed to tls_get/async_tls_connect: %s\n", tls_error(ctarget->tls));
			} else {
				cerr("failed to tls_config_set_ca_file/keypair_file: %s\n", tls_config_error(ctarget->tls_config));
			}
		} else {
			cerr("failed to connect: `tls_get/tls_config_new`\n");
		}
	}

	return -1;
}

static void *tls_client_handler(param_t args) {
	int client = args[0].integer;
	tls_client_cb handlerFunc = (tls_client_cb)args[1].func;
	bool is_tls = false;

	deferring(async_tls_close, client);
	handlerFunc(client);
	return 0;
}

EVENTS_INLINE void tls_handler(tls_client_cb connected, int client) {
	launch((launch_func_t)tls_client_handler, 2, client, connected);
}

bool tls_is_selfserver(void) {
	return tls_is_self_signed;
}

void tls_selfserver_set(void) {
	tls_is_self_signed = true;
}

void tls_selfserver_clear(void) {
	tls_is_self_signed = false;
}

void async_tls_close(int socket) {
	if (!socket)
		return;

	events_fd_t *target = events_target(socket);
	if (target->tls) {
		tls_close(target->tls);
		tls_free(target->tls);
		target->tls = null;
	}
}

const char *async_tls_error(int socket) {
	if (!socket) return null;
	events_fd_t *target = events_target(socket);
	if (!target->tls) return null;
	return tls_error(target->tls);
}

ssize_t tls_reader(int socket, char *buf, size_t max) {
	events_fd_t *target = events_target(socket);
	if (is_empty(target->tls))
		return async_read(socket, buf, max);

	for (;;) {
		ssize_t x = tls_read(target->tls, buf, max);
		if (x >= 0)
			return x;

		if (x == -1 && ERR_get_error() == TLS_EOF)
			return 0;

		x = tls_poll(socket, (int)x);
		target->events = 0;
		if ((x = tlserr(x, target->tls)) < 0)
			return x;
	}

	assert(0);
	return -EINVAL; // Not reached
}

ssize_t tls_writer(int socket, char *buf, size_t len) {
	events_fd_t *target = events_target(socket);
	size_t count = !len ? strlen(buf) : len;
	if (is_empty(target->tls))
		return async_write(socket, buf, count);

	for (;;) {
		ssize_t x = tls_write(target->tls, buf, count);
		if (x >= 0) return x;
		x = tls_poll(socket, (int)x);
		target->events = 0;
		if ((x = tlserr(x, target->tls)) < 0)
			return x;
	}

	assert(0);
	return -EINVAL; // Not reached
}

int tls_flusher(int socket) {
	events_fd_t *target = events_target(socket);
	if (!is_empty(target->tls))
		return tls_flush(target->tls);

	return -EINVAL;
}
