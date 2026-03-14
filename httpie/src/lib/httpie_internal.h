#ifndef _HTTPIE_INTERNAL_H
#define _HTTPIE_INTERNAL_H

#include <httpie.h>

#ifdef _WIN32
extern CRITICAL_SECTION global_log_file_lock;
#define flockfile(x) (EnterCriticalSection(&global_log_file_lock))
#define funlockfile(x) (LeaveCriticalSection(&global_log_file_lock))
#define INT64_FMT "I64d"
#define UINT64_FMT "I64u"
#else
#define INT64_FMT PRId64
#define UINT64_FMT PRIu64
#endif

#define PROXY_CONNECTION "proxy-connection"
#define CONNECTION "connection"
#define CONTENT_LENGTH "content-length"
#define TRANSFER_ENCODING "transfer-encoding"
#define UPGRADE "upgrade"
#define CHUNKED "chunked"
#define KEEP_ALIVE "keep-alive"
#define CLOSE "close"

struct cookie_s {
	int maxAge;
	bool httpOnly;
	bool secure;
	char path[64];
	char expiries[64];
	char domain[64];
	char sameSite[64];
	char value[Kb(2)];
};

struct response_s {
	data_types type;
	/* The current response status */
	http_status status;
	/* The protocol version */
	double version;
	/* The current response body */
	string body;
	/* The unchanged data from server */
	string raw;
	/* The protocol */
	string protocol;
	/* The current headers */
	hash_http_t *headers;
};

struct form_data_s {
	size_t bodysize;
	string body;
	string filename;
	string disposition;
	string type;
	string encoding;
};

enum http_dbg {
	/* No error messages are generated at all */
	DEBUG_NONE = 0x00,
	/* Messages for errors impacting multiple connections in a severe way are generated */
	DEBUG_CRASH = 0x10,
	/* Messages for errors impacting single connections in a severe way are generated (default)	*/
	DEBUG_ERROR = 0x20,
	/* Messages for errors impacting single connections in a minor way are generated */
	DEBUG_WARNING = 0x30,
	/* All error, warning and informational messages are generated */
	DEBUG_INFO = 0x40
};

/* Unified socket address. For IPv6 support, add IPv6 address structure in the union u. */
union usa {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

/*
 * enum HTTP_STATUS_...
 *
 * A context can be in several states. It can be running, it can be in the
 * process of terminating and it can be terminated. */
enum http_status_t {
	HTTP_STATUS_RUNNING,
	HTTP_STATUS_STOPPING,
	HTTP_STATUS_TERMINATED
};

enum http_type_t {
	HTTP_TYPE_SERVER,
	HTTP_TYPE_CLIENT
};

enum uri_type_t {
	URI_TYPE_UNKNOWN,
	URI_TYPE_ASTERISK,
	URI_TYPE_RELATIVE,
	URI_TYPE_ABS_NOPORT,
	URI_TYPE_ABS_PORT
};

/* Describes listening socket, or socket which was accept()-ed by the master
 * thread and queued for future handling by the worker thread. */
struct http_socket {
	/* Listening socket */
	SOCKET sock;
	/* Local socket address */
	union usa lsa;
	/* Remote socket address */
	union usa rsa;
	/* Is port SSL-ed */
	bool has_ssl;
	/* Is port supposed to redirect everything to SSL port	*/
	bool has_redir;
	/* Is valid */
	unsigned char in_use;
};

struct file {
	int is_directory;
	int gzipped; /* set to 1 if the content is gzipped in which case we need a content-encoding: gzip header */
	uint64_t size;
	time_t last_modified;
	FILE *fp;
	const char *membuf; /* Non-NULL if file data is in memory */
};

#define STRUCT_FILE_INITIALIZER { (uint64_t)0, (time_t)0, NULL, NULL, 0, 0 }

/* Option record passed in an array of option records when a context is created */
struct lh_opt_t {
	/* name of the option used when creating a context */
	const char *name;
	/* value of the option */
	const char *value;
};

/* This structure needs to be passed to http_start(),
 * to let `httpie` know which callbacks to invoke. */
struct lh_clb_t {
	int (*begin_request)(http_ini_t *ctx, http_t *conn);
	void (*end_request)(http_ini_t *ctx, const http_t *conn, int reply_status_code);
	int (*log_message)(http_ini_t *ctx, const http_t *conn, const char *message);
	int (*log_access)(http_ini_t *ctx, const http_t *conn, const char *message);
	void (*connection_close)(http_ini_t *ctx, const http_t *conn);
	const char *(*open_file)(http_ini_t *ctx, const http_t *conn, const char *path, size_t *data_len);
	int (*http_error)(http_ini_t *ctx, http_t *, int status);
	void (*init_context)(http_ini_t *ctx);
	void (*init_thread)(http_ini_t *ctx, int thread_type);
	void (*exit_context)(http_ini_t *ctx);
};

struct http_ini_s {
	/* Should we stop event loop */
	volatile enum http_status_t status;
	/* HTTP_TYPE_SERVER or HTTP_TYPE_CLIENT */
	enum http_type_t http_type;
	enum http_dbg debug_level;
	unsigned int num_listening_sockets;

	bool allow_sendfile_call;
	bool decode_url;
	bool enable_directory_listing;
	bool enable_keep_alive;
	bool ssl_short_trust;
	bool ssl_verify_paths;
	bool ssl_verify_peer;
	bool tcp_nodelay;

	int	num_threads;
	int	request_timeout;
	int	ssi_include_depth;
	int	ssl_protocol_version;
	int	ssl_verify_depth;
	int	static_file_max_age;
	int	websocket_timeout;

	/* User-defined data */
	void *user_data;
	/* User-defined callback function */
	struct lh_clb_t callbacks;

	struct http_socket *listening_sockets;
	/* Server start time, used for authentication */
	time_t start_time;
	/* Used nonces, used for authentication */
	unsigned long nonce_count;
	/* Mask for all nonce values */
	uint64_t auth_nonce_mask;
	/* Protects nonce_count */
	atomic_spinlock nonce_mutex;
	/* What operating system is running */
	char *systemName;
	/* linked list of uri handlers */
	struct httplib_handler_info *handlers;

	char *access_control_allow_origin;
	char *access_control_list;
	char *access_log_file;
	char *authentication_domain;
	char *cgi_environment;
	char *cgi_interpreter;
	char *cgi_pattern;
	char *document_root;
	char *error_log_file;
	char *error_pages;
	char *extra_mime_types;
	char *global_auth_file;
	char *hide_file_pattern;
	char *index_files;
	char *listening_ports;
	char *protect_uri;
	char *put_delete_auth_file;
	char *run_as_user;
	char *ssi_pattern;
	char *ssl_ca_file;
	char *ssl_ca_path;
	char *ssl_certificate;
	char *ssl_cipher_list;
	char *throttle;
	char *url_rewrite_patterns;
	char *websocket_root;
};

struct http_s {
	data_types type;
	/* This parser ~instance~ state,
	either `RESPONSE` or `REQUEST` behaviour. */
	http_parser_type action;
	/* The current response status */
	http_status status;
	/* The requested status code */
	http_status code;
	enum http_dbg debug_level;
	/* Connected file descriptor/socket */
	fds_t fd;
	/* Connected ip address */
	char addr[16];
	/* Total bytes sent to client */
	int64_t num_bytes_sent;
	/* Content-Length header value */
	int64_t content_len;
	/* How many bytes of content have been read */
	int64_t	consumed_content;
	/* Transfer-Encoding is chunked: 0=no, 1=yes: data available, 2: all data read */
	int is_chunked;
	int enable_keep_alive;
	/* Buffer for received data */
	char *buf;
	char *error_log_file;
	/* Buffer size */
	int buf_size;
	/* Size of the request + headers in a buffer */
	int request_len;
	/* Total size of data in a buffer */
	int data_len;
	/* true, if connection must be closed */
	int must_close;
	/* Is Multipart `form_data` in header response? */
	int is_multipart;
	/* Unread data from the last chunk */
	size_t chunk_remainder;
	string document_root;
	/* The protocol version */
	double version;
	string hostname;
	/* The unchanged data from server */
	string raw;
	/* The current response body */
	string body;
	/* The requested uri */
	string uri;
	/* The multi-part `boundary` name */
	string boundary;
	/* Array of multi-part `disposition` names */
	array_t names;
	/* Array of set-cookie `session` names */
	array_t cookies;
	/* Parser, `request/response` staging allocations,
	WILL be freed at exit, and before `parse_http` execution. */
	array_t garbage;
	/* The current headers
	and `response` headers to send */
	hash_http_t *headers;
	/* The request params */
	hash_http_t *parameters;
	/* The multi-part dispositions, `form_data_t` */
	hash_http_t *dispositions;
	/* The set-cookie sessions, `cookie_t` */
	hash_http_t *sessions;
	/* The protocol */
	char protocol[16];
	/* The requested method */
	char method[32];
	/* The requested status message */
	char message[64];
	/* The requested path */
	char path[128];
	char variable[256];
};

void http_snprintf(http_t *conn, bool *truncated, char *buf, size_t buflen, const char *fmt, ...);
struct tm *http_gmtime_r(const time_t *clk, struct tm *result);

/* Convert time_t to a string. According to RFC2616, Sec 14.18, this must be
 * included in all responses other than 100, 101, 5xx. */
void http_gmt_time_str(char *buf, size_t buf_len, time_t *t);

#endif /* _HTTPIE_INTERNAL_H */