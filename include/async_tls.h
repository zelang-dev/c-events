#ifndef _ASYNC_TLS_H
#define _ASYNC_TLS_H

#define NO_REDEF_POSIX_FUNCTIONS
#undef in
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <tls.h>
#define in ,
#include <arrays.h>

#ifdef _WIN32
#define _BIO_MODE_R(flags) (((flags) & PKCS7_BINARY) ? "rb" : "r")
#define _BIO_MODE_W(flags) (((flags) & PKCS7_BINARY) ? "wb" : "w")
#else
#define _BIO_MODE_R(flags) "r"
#define _BIO_MODE_W(flags) "w"
#endif

#ifndef MAXHOSTNAMELEN
#	define MAXHOSTNAMELEN 256
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* X509v3 distinguished names and extensions */
typedef enum {
    /* country */
    dn_c = DATA_MAXCOUNTER + 1,
    /* state */
    dn_st,
    /* locality */
    dn_l,
    /* organisation */
    dn_o,
    /* organizational unit */
    dn_ou,
    /* common name */
    dn_cn,
    /* Subject Alternative Name */
    ext_san = dn_cn + NID_subject_alt_name,
    /* Issuer Alternative Name */
    ext_ian = dn_cn + NID_issuer_alt_name,
    /* Key Usage */
    ext_ku = dn_cn + NID_key_usage,
    /* Netscape Cert Type */
    ext_nct = dn_cn + NID_netscape_cert_type,
    /* sha256 With RSA Encryption */
    rsa_sha256 = ext_nct + NID_sha256WithRSAEncryption,
    /* sha384 With RSA Encryption */
    rsa_sha384 = ext_nct + NID_sha384WithRSAEncryption,
    /* sha512 With RSA Encryption */
    rsa_sha512 = ext_nct + NID_sha512WithRSAEncryption,
    /* sha224 With RSA Encryption */
    rsa_sha224 = ext_nct + NID_sha224WithRSAEncryption,
    /* sha512_224 With RSA Encryption */
    rsa_sha512_224 = ext_nct + NID_sha512_224WithRSAEncryption,
    /* sha251_256 With RSA Encryption */
    rsa_sha512_256 = ext_nct + NID_sha512_256WithRSAEncryption,
    pkey_type,
    pkey_bits,
    ca_path,
    ca_file
} csr_option_types;

typedef struct tls_config tls_config_t;
typedef struct tls tls_s;
typedef client_cb tls_client_cb;
#define TLS_EOF 0xa000126

C_API bool socket_is_eof(int);
C_API bool socket_is_secure(int);

C_API int tls_out(char *msg, size_t nread);
C_API void tls_closer(int);
C_API ssize_t tls_reader(int, char *buf, size_t max);
C_API ssize_t tls_writer(int, char *buf, size_t len);
C_API int tls_get(const char *);
C_API int tls_bind(const char *, int backlog);
C_API int tls_accept(int, char *server, int *port);
C_API void tls_handler(tls_client_cb, int);
C_API int tls_flusher(int);

C_API bool tls_is_selfserver(void);
C_API void tls_selfserver_set(void);
C_API void tls_selfserver_clear(void);

C_API const char *ca_cert_file(void);
C_API const char *cert_file(void);
C_API const char *pkey_file(void);
C_API const char *csr_file(void);

C_API int cerr(const char *msg, ...);
C_API int cout(const char *msg, ...);

C_API X509 *x509_get(const char *file_path);
C_API EVP_PKEY *pkey_get(const char *file_path);
C_API char *x509_str(X509 *cert, bool show_details);
C_API bool x509_pkey_write(EVP_PKEY *pkey, X509 *x509);

C_API EVP_PKEY *rsa_pkey(int keylength);
C_API X509 *x509_self(EVP_PKEY *pkey, const char *country, const char *org, const char *domain);
C_API bool x509_self_export(EVP_PKEY *pkey, X509 *x509, const char *path_noext);

C_API void use_ca_certificate(const char *path);
C_API void use_certificate(char *path, uint32_t ctx_pairs, ...);

C_API const char *events_uname(void);
C_API const char *events_hostname(void);
C_API void events_ssl_error(void);
C_API void events_ssl_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ASYNC_TLS_H */