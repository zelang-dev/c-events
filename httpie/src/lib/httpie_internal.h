#ifndef _HTTPIE_INTERNAL_H
#define _HTTPIE_INTERNAL_H

#include <httpie.h>
#undef in
#ifdef _WIN32
#	include "zlib.h"
#else
#	include <zlib.h>
#endif
#define in ,

#define PASSWORDS_FILE_NAME	".htpasswd"
#define PROXY_CONNECTION 	"proxy-connection"
#define CONNECTION 			"connection"
#define CONTENT_LENGTH 		"content-length"
#define TRANSFER_ENCODING 	"transfer-encoding"
#define UPGRADE 			"upgrade"
#define CHUNKED 			"chunked"
#define KEEP_ALIVE 			"keep-alive"
#define CLOSE 				"close"

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

enum route_type_t {
	REQUEST_HANDLER,
	WEBSOCKET_HANDLER,
	AUTH_HANDLER
};

/* Enum const for all options must be in sync with
 * static struct ini_option config_options[]
 * This is tested in the unit test (test/private.c)
 * "Private Config Options"
 */
enum {
	/* Once for each server */
	LISTENING_PORTS,
	NUM_THREADS,
	PRESPAWN_THREADS,
	RUN_AS_USER,
	CONFIG_TCP_NODELAY, /* Prepended CONFIG_ to avoid conflict with the
						 * socket option typedef TCP_NODELAY. */
	MAX_REQUEST_SIZE,
	LINGER_TIMEOUT,
	CONNECTION_QUEUE_SIZE,
	LISTEN_BACKLOG_SIZE,
	ALLOW_SENDFILE_CALL,
	THROTTLE,
	ENABLE_KEEP_ALIVE,
	REQUEST_TIMEOUT,
	KEEP_ALIVE_TIMEOUT,
	WEBSOCKET_TIMEOUT,
	ENABLE_WEBSOCKET_PING_PONG,
	DECODE_URL,
	DECODE_QUERY_STRING,
	ENABLE_HTTP2,

	/* Once for each domain */
	DOCUMENT_ROOT,
	FALLBACK_DOCUMENT_ROOT,

	ACCESS_LOG_FILE,
	ERROR_LOG_FILE,

	CGI_EXTENSIONS,
	CGI_ENVIRONMENT,
	CGI_INTERPRETER,
	CGI_INTERPRETER_ARGS,
	CGI_BUFFERING,

	CGI2_EXTENSIONS,
	CGI2_ENVIRONMENT,
	CGI2_INTERPRETER,
	CGI2_INTERPRETER_ARGS,
	CGI2_BUFFERING,

	PUT_DELETE_PASSWORDS_FILE, /* must follow CGI_* */
	PROTECT_URI,
	AUTHENTICATION_DOMAIN,
	ENABLE_AUTH_DOMAIN_CHECK,
	SSI_EXTENSIONS,
	ENABLE_DIRECTORY_LISTING,
	ENABLE_WEBDAV,
	GLOBAL_PASSWORDS_FILE,
	INDEX_FILES,
	ACCESS_CONTROL_LIST,
	EXTRA_MIME_TYPES,
	SSL_CERTIFICATE,
	SSL_CERTIFICATE_CHAIN,
	URL_REWRITE_PATTERN,
	HIDE_FILES,
	SSL_DO_VERIFY_PEER,
	SSL_CACHE_TIMEOUT,
	SSL_CA_PATH,
	SSL_CA_FILE,
	SSL_VERIFY_DEPTH,
	SSL_DEFAULT_VERIFY_PATHS,
	SSL_CIPHER_LIST,
	SSL_PROTOCOL_VERSION,
	SSL_SHORT_TRUST,
	WEBSOCKET_ROOT,
	FALLBACK_WEBSOCKET_ROOT,
	REPLACE_ASTERISK_WITH_ORIGIN,
	ACCESS_CONTROL_ALLOW_ORIGIN,
	ACCESS_CONTROL_ALLOW_METHODS,
	ACCESS_CONTROL_ALLOW_HEADERS,
	ACCESS_CONTROL_EXPOSE_HEADERS,
	ACCESS_CONTROL_ALLOW_CREDENTIALS,
	ERROR_PAGES,
	STATIC_FILE_MAX_AGE,
	STATIC_FILE_CACHE_CONTROL,
	STRICT_HTTPS_MAX_AGE,
	ADDITIONAL_HEADER,
	ALLOW_INDEX_SCRIPT_SUB_RES,

	NUM_OPTIONS
};

/* Configuration types */
enum {
	INI_TYPE_UNKNOWN = 0x0,
	INI_TYPE_NUMBER = 0x1,
	INI_TYPE_STRING = 0x2,
	INI_TYPE_FILE = 0x3,
	INI_TYPE_DIRECTORY = 0x4,
	INI_TYPE_BOOLEAN = 0x5,
	INI_TYPE_EXT_PATTERN = 0x6,
	INI_TYPE_STRING_LIST = 0x7,
	INI_TYPE_STRING_MULTILINE = 0x8,
	INI_TYPE_YES_NO_OPTIONAL = 0x9
};

/* Describes a string (chunk of memory). */
struct vec {
	string_t ptr;
	size_t len;
};

struct http_cb_info {
	/* Name/Pattern of the URI. */
	char *uri;
	size_t uri_len;

	/* handler type */
	int handler_type;

	/* Handler for http/https or authorization requests. */
	route_cb handler;

	/* Handler for ws/wss (websocket) requests. */
	ws_connect_cb connect_handler;
	ws_ready_cb ready_handler;
	ws_data_cb data_handler;
	ws_close_cb close_handler;

	/* Handler for authorization requests */
	auth_cb auth_handler;

	/* User supplied argument for the handler function. */
	void_t cbdata;

	/* next handler in a linked list */
	struct http_cb_info *next;
};

struct server_socket_s {
	/* Listening socket */
	fds_t sock;
	/* Local socket address */
	union usa lsa;
	/* Remote socket address */
	union usa rsa;
	/* Is port SSL-ed */
	bool has_ssl;
	/* Is port supposed to redirect everything to SSL port	*/
	bool has_redir;
	/* 0: invalid, 1: valid, 2: free */
	unsigned char in_use;
	/* Shouldn't cause us to exit if we can't bind to it */
	unsigned char is_optional;
};

struct file {
	int is_directory;
	int gzipped; /* set to 1 if the content is gzipped in which case we need a content-encoding: gzip header */
	uint64_t size;
	time_t last_modified;
	FILE *fp;
	string_t membuf; /* Non-NULL if file data is in memory */
};

#define STRUCT_FILE_INITIALIZER {0, 0, (uint64_t)0, (time_t)0, NULL, NULL}

/* `httpie` server `ini` context options, an array of records passed in when a context is created */
struct ini_option {
	/* name of the option used when creating a context */
	string_t name;
	int type;
	/* value of the option */
	string_t default_value;
};

/* This structure needs to be passed to http_start(),
 * to let `httpie` know which callbacks to invoke. */
struct http_clb_s {
	log_message_cb log_message;
	log_access_cb log_access;
	open_file_cb open_file;
	http_error_cb http_error;
	init_context_cb init_context;
};

struct ini_domain_s {
	 /* tls context */
	tls_s *tls_ctx;
	/* `httpie` configuration parameters */
	char *config[NUM_OPTIONS];
	int64_t ssl_cert_last_mtime;

	/* Server nonce */
	/* Mask for all nonce values */
	uint64_t auth_nonce_mask;
	/* Used nonces, used for authentication */
	unsigned long nonce_count;
	/* Protects nonce_count */
	atomic_spinlock nonce_mutex;

	/* Linked list of domains */
	struct ini_domain_s *next;
	struct http_cb_info *handlers; /* linked list of uri handlers */
};

struct http_ini_s {
	/* Should we stop event loop */
	volatile enum http_status_t status;
	/* HTTP_TYPE_SERVER or HTTP_TYPE_CLIENT */
	enum http_type_t http_type;
	enum http_dbg debug_level;
	unsigned int num_listening_sockets;
	/* Memory related */
	/* The max request size */
	unsigned int max_request_size;
	/* Server start time, used for authentication */
	time_t start_time;
	/* Server nonce */
	/* Protects ssl_ctx, handlers,
	 * ssl_cert_last_mtime, nonce_count, and
	 * next (linked list) */
	atomic_spinlock nonce_mutex;
	string error_log_file;
	string document_root;
	/* What operating system is running */
	string systemName;
	/* User-defined data */
	void *user_data;
	/* User-defined callback function */
	http_clb_t callbacks;
	http_socket *listening_sockets;
	/* linked list of uri handlers */
	struct http_cb_info *handlers;

	/* Part 2 - Logical domain:
	 * This holds hostname, TLS certificate, document root, ...
	 * set for a domain hosted at the server.
	 * There may be multiple domains hosted at one physical server.
	 * The default domain "host" is the first element of a list of domains. */
	struct ini_domain_s host;
};

typedef struct httpie_s {
	http_protocol_type proto;
	/* Total bytes sent to client */
	int64_t num_bytes_sent;
	/* Content-Length header value */
	int64_t content_len;
	/* How many bytes of content have been read */
	int64_t	consumed_content;
	/* Buffer size */
	int buf_size;
	/* Size of the request + headers in a buffer */
	int request_len;
	/* Total size of data in a buffer */
	int data_len;
	/* true, if connection must be closed */
	int must_close;
	/* 1 if gzip encoding is accepted */
	int accept_gzip;
	/* Transfer-Encoding is chunked:
	 * 0 = not chunked,
	 * 1 = chunked, not yet, or some data read,
	 * 2 = chunked, has error,
	 * 3 = chunked, all data read except trailer,
	 * 4 = chunked, all data read */
	int is_chunked;
	int enable_keep_alive;
	/* Port at client side */
	int remote_port;
	/* 1 if in read_websocket */
	int in_websocket_handling;
	/* Parameters for websocket data compression according to rfc7692 */
	int websocket_deflate_server_max_windows_bits;
	int websocket_deflate_client_max_windows_bits;
	int websocket_deflate_server_no_context_takeover;
	int websocket_deflate_client_no_context_takeover;
	int websocket_deflate_initialized;
	int websocket_deflate_flush;
	/* Unread data from the last chunk */
	size_t chunk_remainder;
	/* websocket subprotocol, accepted during handshake */
	string_t acceptedWebSocketSubprotocol;
	/* Buffer for received data */
	string buf;
	z_stream websocket_deflate_state;
	z_stream websocket_inflate_state;
	/* Client's IP address. */
	char remote_addr[48];
} httpie_t;

struct http_s {
	data_types type;
	/* This parser ~instance~ state,
	either `RESPONSE` or `REQUEST` behaviour. */
	http_parser_type action;
	/* The current response status */
	http_status status;
	/* The requested status code */
	http_status code;
	/* Connected file descriptor/socket */
	fds_t fd;
	/* Connected client */
	http_socket	client;
	/* Is Multipart `form_data` in header response? */
	int is_multipart;
	/* The protocol version */
	double version;
	/* The raw headers and body junction position from server */
	size_t raw_pos;
	/* The unchanged data from server */
	string raw;
	string hostname;
	/* The current request body */
	string body;
	string uri;
	/* The requested uri */
	string url_to;
	/* The requested path */
	string path;
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
	http_ini_t *ctx;
	struct ini_domain_s *domain;
	/* The protocol */
	char protocol[16];
	/* The requested method */
	char method[32];
	/* The requested status message */
	char message[64];
	char variable[256];
	httpie_t req;
};

/* Used to process new incoming connections to the server. */
http_t *http_accept(const http_socket *listener, http_ini_t *ctx);

/*
 * Sets the global password file option for a context.
 * The function returns false when an error occurs and
 * true when successful. */
bool http_set_gpass_option(http_ini_t *ctx);

/*
 * Runs on systems which support it
 * the context in the security environment of a specific user. The function can
 * be called for Windows, but it doesn't do anything because Windows doesn't
 * support the run-as options as available under *nix systems.
 *
 * False is returned in case a problem is detected, true otherwise.  */
bool http_set_uid_option(http_ini_t *ctx);

/* Sets the ACL option for a context. */
bool http_set_acl_option(http_ini_t *ctx);

/* A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x". */
string_t http_next_option(string_t list, struct vec *val, struct vec *eq_val);
int http_parse_match_net(const struct vec *vec, const union usa *sa, int no_strict);

/* Processes a request from a remote client. */
bool http_get_request(http_ini_t *ctx, http_t *conn, int *err);

/*
 * Set the port options for a context.
 * The function returns the total number of ports opened,
 * or 0 if no ports have been opened. */
int http_set_ports_option(http_ini_t *ctx);
void http_set_close_on_exec(fds_t sock);

string http_error_string(int error_code, string buf, size_t buf_len);

/* Perform case-insensitive match of string against pattern */
int http_match_prefix(string_t pattern, size_t pattern_len, string_t str);

/*
 * Returns true, if a file must be hidden from browsing by the remote client.
 * A used provided list of file patterns to hide is used.
 * Password files are always hidden, independent of the patterns defined by the user. */
bool http_must_hide_file(http_ini_t *ctx, string_t path);

void http_snprintf(http_t *conn, bool *truncated, string buf, size_t buflen, string_t fmt, ...);
struct tm *http_gmtime_r(const time_t *clk, struct tm *result);

/* Do cleanup work when an error occurred initializing a context. */
http_ini_t *http_abort_start(http_ini_t *ctx, string_t fmt, ...);
void http_close_listening_sockets(http_ini_t *ctx);

/* Convert time_t to a string. According to RFC2616, Sec 14.18, this must be
 * included in all responses other than 100, 101, 5xx. */
void http_gmt_time_str(char *buf, size_t buf_len, time_t *t);
int http_inet_pton(int af, const char *src, void *dst, size_t dstlen, int resolve_src);

/* Sets callback handlers to uri's. */
void http_set_handler(http_ini_t *ctx, string_t uri, enum route_type_t handler_type, bool is_delete_request,
	route_cb handler,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	auth_cb auth_handler,
	void_t cbdata);

/* Does the heavy lifting in writing data over a websocket connectin to a remote peer. */
int http_websocket_write_exec(http_t *conn, websocket_type opcode,
	string_t data, size_t data_len, uint32_t masking_key);

void http_websocket_deflate_send(http_t *conn);
void http_websocket_deflate_negotiate(http_t *conn);
int http_websocket_deflate_init(http_t *conn, int server);
void http_websocket_request(http_ini_t *ctx, http_t *conn, int is_callback_resource,
	ws_connect_cb ws_connect_handler, ws_ready_cb ws_ready_handler, ws_data_cb ws_data_handler, ws_close_cb ws_close_handler, void *cbData);

void sockaddr_to_str(char *buf, size_t len, const union usa *usa);
unsigned short sockaddr_in_port(union usa *s);
int http_switch_domain(http_t *conn);

#endif /* _HTTPIE_INTERNAL_H */