#ifndef _HTTPI_INTERNAL_H
#define _HTTPI_INTERNAL_H

#include <httpi.h>

#ifdef USE_DEBUG
#	define debug_info(...) cerr(__VA_ARGS__)
#else
#	define debug_info(...)
#endif

#define get_array_size(array) (sizeof(array) / sizeof(array[0]))

/* For a detailed description of these *_PATH_MAX defines, see
 * https://github.com/civetweb/civetweb/issues/937. */

/* UTF8_PATH_MAX is a char buffer size for 259 BMP characters in UTF-8 plus
 * null termination, rounded up to the next 4 bytes boundary */
#define UTF8_PATH_MAX (3 * 260)
/* UTF16_PATH_MAX is the 16-bit wchar_t buffer size required for 259 BMP
 * characters plus termination. (Note: wchar_t is 16 bit on Windows) */
#define UTF16_PATH_MAX (260)

#define USA_IN_PORT_UNSAFE(s)                                                  \
	(((s)->sa.sa_family == AF_INET6) ? (s)->sin6.sin6_port : (s)->sin.sin_port)
#define IP_ADDR_STR_LEN (50) /* IPv6 hex string is 46 chars */

#define CGI_ENVIRONMENT_SIZE	(4096)
#define MAX_CGI_ENVIR_VARS		(256)
#define BUF_LEN				(8192)

/* Do not try to compress files smaller than this limit. */
#if !defined(FILE_COMPRESSION_SIZE_LIMIT)
#define FILE_COMPRESSION_SIZE_LIMIT (1024) /* in bytes */
#endif

#if !defined(UDS_SERVER_NAME)
#define UDS_SERVER_NAME "*"
#endif

#if !defined(NUM_WEBDAV_LOCKS)
#define NUM_WEBDAV_LOCKS 10
#endif

#if !defined(LOCK_DURATION_S)
#define LOCK_DURATION_S 60
#endif

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

struct form_data_s {
	size_t bodysize;
	string body;
	string filename;
	string disposition;
	string type;
	string encoding;
};

/*
 * enum HTTP_STATUS_...
 *
 * A context can be in several states. It can be running, it can be in the
 * process of terminating and it can be terminated. */
enum http_status_t {
	HTTP_STATUS_RUNNING,
	HTTP_STATUS_STOPPING,
	HTTP_STATUS_TERMINATED,
	HTTP_STATUS_STARTING
};

enum http_type_t {
	HTTP_INI_INVALID,
	HTTP_INI_SERVER,
	HTTP_INI_CLIENT,
	HTTP_INI_WEBSOCKET
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
typedef enum {
	MAX_FD,
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
/*
	CGI2_EXTENSIONS,
	CGI2_ENVIRONMENT,
	CGI2_INTERPRETER,
	CGI2_INTERPRETER_ARGS,
	CGI2_BUFFERING,
*/
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
	QUICKJS_SCRIPT_EXTENSIONS,
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
} ini_options_type;

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

struct http_server_port {
	/* 1 = IPv4, 2 = IPv6, 3 = both */
	int protocol;
	/* port number */
	int port;
	/* https port: 0 = no, 1 = yes */
	int is_ssl;
	/* redirect all requests: 0 = no, 1 = yes */
	int is_redirect;
	/* optional: 0 = no, 1 = yes */
	int is_optional;
	/* bound: 0 = no, 1 = yes, relevant for optional ports */
	int is_bound;
	int _reserved3;
	int _reserved4;
};

struct h2_header {
	string_t name;  /* HTTP header name */
	string_t value; /* HTTP header value */
};

struct http2_s {
	uint32_t stream_id;
	uint32_t dyn_table_size;
	h2_header_t dyn_table[HTTP2_DYN_TABLE_SIZE];
};

/* Describes a string (chunk of memory). */
struct vec {
	string_t ptr;
	size_t len;

	/* According to RFC 1035, hostnames are restricted to 255 characters
	 * in total (63 between two dots). */
	char hostname[256];
};

struct ws_subprotocols_s {
	int nb_subprotocols;
	string_t *subprotocols;
};

struct http_cb_info {
	/* handler type */
	int handler_type;
	size_t uri_len;
	/* Name/Pattern of the URI. */
	char *uri;
	/* User supplied argument for the handler function. */
	void_t cbdata;

	/* Handler for http/https or authorization requests. */
	route_cb handler;

	/* Handler for ws/wss (websocket) requests. */
	ws_connect_cb connect_handler;
	ws_ready_cb ready_handler;
	ws_data_cb data_handler;
	ws_close_cb close_handler;

	/* Handler for authorization requests */
	auth_cb auth_handler;

	/* accepted subprotocols for ws/wss requests. */
	struct ws_subprotocols_s *subprotocols;

	/* next handler in a linked list */
	struct http_cb_info *next;
};

/* Record of a port a server/client is listening on
 * Describes listening socket, or socket which was accept()-ed by the `main`
 * thread and queued for future handling by the worker `task` thread `pool`. */
struct server_socket_s {
	/* Listening/accepted socket */
	fds_t sock;
	/* The protocol supported by the port: 1 = IPv4, 2 = IPv6, 3 = both */
	int protocol;
	/* The port number the server is listening on */
	int port;
	/* 0: invalid, 1: valid, 2: free */
	unsigned char in_use;
	/* Shouldn't cause us to exit if we can't bind to it */
	unsigned char is_optional;
	/* Is port SSL-ed */
	bool has_ssl;
	/* Is port supposed to redirect everything to SSL port	*/
	bool has_redir;
	/* Local socket address */
	u_saddr_t lsa;
	/* Remote socket address */
	u_saddr_t rsa;
	tasks_t *task;
};

struct file {
	int is_directory;
	int gzipped; /* set to 1 if the content is gzipped in which case we need a content-encoding: gzip header */
	uint64_t size;
	time_t last_modified;
	FILE *fp;
	promise *pf;
	string_t membuf; /* Non-NULL if file data is in memory */
};

#define STRUCT_FILE_INITIALIZER {0, 0, (uint64_t)0, (time_t)0, NULL, NULL, NULL}

/* `HttPi` server `ini` context options, an array of records passed in when a context is created */
struct ini_option {
	/* name of the option used when creating a context */
	string_t name;
	int type;
	/* value of the option */
	string_t default_value;
};

struct error_data {
	unsigned code;           /* error code (number) */
	unsigned code_sub;       /* error sub code (number) */
	string text;              /* buffer for error text */
	size_t text_buffer_size; /* size of buffer of "text" */
};

/*
 * This structure contains callback functions for handling form fields.
 * It is used as an argument to `http_handle_form_request`. */
struct form_data_handler_s {
	/* This callback function is called, if a new field has been found.
	 * The return value of this callback is used to define how the field
	 * should be processed.
	 *
	 * Parameters:
	 *   key: Name of the field ("name" property of the HTML input field).
	 *   filename: Name of a file to upload, at the client computer.
	 *             Only set for input fields of type "file", otherwise NULL.
	 *   path: Output parameter: File name (incl. path) to store the file
	 *         at the server computer. Only used if MG_FORM_FIELD_STORAGE_STORE
	 *         is returned by this callback. Existing files will be
	 *         overwritten.
	 *   pathlen: Length of the buffer for path.
	 *   user_data: Value of the member user_data of `form_data_handler_t`
	 *
	 * Return value:
	 *   The callback must return the intended storage for this field
	 *   (See FORM_FIELD_STORAGE_*).
	 */
	int (*field_found)(string_t key, string_t filename, char *path, size_t pathlen, void_t user_data);

	/* If the "field_found" callback returned FORM_FIELD_STORAGE_GET,
	 * this callback will receive the field data.
	 *
	 * Parameters:
	 *   key: Name of the field ("name" property of the HTML input field).
	 *   value: Value of the input field.
	 *   user_data: Value of the member user_data of `form_data_handler_t`
	 *
	 * Return value:
	 *   The return code determines how the server should continue processing
	 *   the current request (See FORM_FIELD_HANDLE_*).
	 */
	int (*field_get)(string_t key, string_t value, size_t valuelen, void_t user_data);

	/* If the "field_found" callback returned FORM_FIELD_STORAGE_STORE,
	 * the data will be stored into a file. If the file has been written
	 * successfully, this callback will be called. This callback will
	 * not be called for only partially uploaded files. The
	 * http_handle_form_request function will either store the file completely
	 * and call this callback, or it will remove any partial content and
	 * not call this callback function.
	 *
	 * Parameters:
	 *   path: Path of the file stored at the server.
	 *   file_size: Size of the stored file in bytes.
	 *   user_data: Value of the member user_data of `form_data_handler_t`
	 *
	 * Return value:
	 *   The return code determines how the server should continue processing
	 *   the current request (See FORM_FIELD_HANDLE_*).
	 */
	int (*field_store)(string_t path, int64_t file_size, void_t user_data);
	void *user_data;
};

/* Return values definition for the "field_found" callback in `http_form_data_handler`. */
enum {
	/* Skip this field (neither get nor store it). Continue with the next field. */
	FORM_FIELD_STORAGE_SKIP = 0x00,
	/* Get the field value. */
	FORM_FIELD_STORAGE_GET = 0x01,
	/* Store the field value into a file. */
	FORM_FIELD_STORAGE_STORE = 0x02,
	/* Stop parsing this request. Skip the remaining fields */
	FORM_FIELD_STORAGE_ABORT = 0x10
};

/* Return values for "field_get" and "field_store" */
enum {
	/* Only "field_get": If there is more data in this field, get the next
	 * chunk. Otherwise: handle the next field. */
	FORM_FIELD_HANDLE_GET = 0x1,
	/* Handle the next field */
	FORM_FIELD_HANDLE_NEXT = 0x8,
	/* Stop parsing this request */
	FORM_FIELD_HANDLE_ABORT = 0x10
};

struct ini_domain_s {
	int64_t ssl_cert_last_mtime;
	/* Server nonce */
	/* Mask for all nonce values */
	uint64_t auth_nonce_mask;
	/* Used nonces, used for authentication */
	unsigned long nonce_count;
	 /* tls context */
	tls_s *tls_ctx;
	/* Linked list of domains */
	struct ini_domain_s *next;
	 /* linked list of uri handlers */
	struct http_cb_info *handlers;
	/* `HttPi` configuration parameters */
	char *config[NUM_OPTIONS];
	/* Protects nonce_count */
	atomic_spinlock nonce_mutex;
};

struct twebdav_lock {
	uint64_t locktime;
	char token[33];
	char path[UTF8_PATH_MAX * 2];
	char user[UTF8_PATH_MAX * 2];
};

struct http_ini_s {
	data_types type;
	/* Should we stop event loop */
	volatile enum http_status_t status;
	/* HTTP_INI_SERVER, HTTP_INI_CLIENT, or HTTP_INI_WEBSOCKET */
	enum http_type_t http_type;
	enum http_dbg debug_level;
	int enable_keep_alive;
	/* Memory related */
	/* The max request size */
	unsigned int max_request_size;
	unsigned int request_timeout;
	/* The thread worker task IDs */
	uint32_t worker_taskid;
	string error_log_file;
	string document_root;
	/* What operating system is running */
	string_t systemName;
	/* Server start time, used for authentication */
	time_t start_time;
	/* User-defined data */
	void *user_data;
	/* User-defined callback function */
	http_clb_t callbacks;
	//array_t options;
	/* Array of `http_socket` listening sockets */
	array_t server_sockets;
	/* linked list of uri handlers */
	struct http_cb_info *handlers;
	/* Part 2 - Logical domain:
	 * This holds hostname, TLS certificate, document root, ...
	 * set for a domain hosted at the server.
	 * There may be multiple domains hosted at one physical server.
	 * The default domain "host" is the first element of a list of domains. */
	struct ini_domain_s host;
	/* WebDAV lock structures */
	struct twebdav_lock webdav_lock[NUM_WEBDAV_LOCKS];
	/* Server nonce */
	/* Protects ssl_ctx, handlers,
	 * ssl_cert_last_mtime, nonce_count, and
	 * next (linked list) */
	atomic_spinlock nonce_mutex;
};

struct httpi_ws_s {
	data_types type;
	volatile bool is_data_ready;
	ws_data_cb data_handler;
	ws_close_cb close_handler;
	void_t callback_data;
};

struct httpi_s {
	http_protocol_type proto;
	/* Total bytes sent to client */
	int64_t num_bytes_sent;
	/* Content-Length header value */
	int64_t content_len;
	/* How many bytes of content have been read */
	int64_t	consumed_content;
	/* 0: nothing sent,
	 * 1: header partially sent,
	 * 2: header fully sent */
	int state;
	/* 1 if in handler for user defined error pages */
	int in_error_handler;
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
	 * 2 = chunked, all data read,
	 * 3 = chunked, has error */
	int is_chunked;
	/* Port at client side */
	int remote_port;
	/* Port at server side (one of the listening ports) */
	int server_port;
	/* 1 if in read_websocket */
	int in_websocket_handling;
	/* Parameters for websocket data compression according to rfc7692 */
	int websocket_deflate_server_max_windows_bits;
	int websocket_deflate_client_max_windows_bits;
	int websocket_deflate_server_no_context_takeover;
	int websocket_deflate_client_no_context_takeover;
	int websocket_deflate_initialized;
	int websocket_deflate_flush;
	/* Number of requests handled by this connection */
	int handled_requests;
	/* Throttling, bytes/sec. <= 0 means no throttle */
	int throttle;
	/* Bytes sent this second */
	int last_throttle_bytes;
	/* Last time throttled data was sent */
	time_t last_throttle_time;
	/* Time (since system start) when the request was received */
	uint64_t req_time;
	/* Time (wall clock) when connection was established */
	time_t conn_birth_time;
	/* Unread data from the last chunk */
	size_t chunk_remainder;
	/* User data pointer passed to `httpi_setup()` */
	void_t user_data;
	/* Connection-specific user data */
	void_t conn_data;
	/* E.g. "1.0", "1.1" */
	string_t http_version;
	/* Authenticated user, or NULL if no auth used */
	string_t remote_user;
	/* URL-decoded URI (relative).
	Can be NULL if request_uri is not a resource at the server host */
	string_t local_uri;
	/* URL part after '?', not including '?', or NULL */
	string_t query_string;
	/* websocket subprotocol, accepted during handshake */
	string_t acceptedWebSocketSubprotocol;
	/* Buffer for received data */
	string buf;
	z_stream websocket_deflate_state;
	z_stream websocket_inflate_state;
	/* Client's IP address. */
	char remote_addr[48];
	/* Used to ensure atomic transmissions
	 * for websockets */
	atomic_flag mutex;
};

struct http_s {
	data_types type;
	/* This parser ~instance~ state,
	either `RESPONSE` or `REQUEST` behaviour. */
	http_parser_type action;
	/* The response status */
	http_status status;
	/* The status code */
	http_status code;
	/* Is Multipart `form_data` in header request? */
	int is_multipart;
	/* header has `4` = `\r\n\r\n`, or `2` = `\n\n` in request? */
	int is_valid;
	/* Number of HTTP headers */
	int num_headers;
	/* The protocol version */
	double version;
	/* Length (in bytes) of the request body,
	 * can be -1 if no length was given. */
	long long content_length;
	/* The raw headers and body junction position from server */
	size_t raw_pos;
	/* The unchanged data from server */
	string raw;
	string hostname;
	/* The current body */
	string body;
	string uri;
	/* The requested uri */
	string url_to;
	/* The requested path */
	string path;
	string_t query_string;
	/* The multi-part `boundary` name */
	string boundary;
	/* Array of multi-part `disposition` names */
	array_t names;
	/* Array of set-cookie `session` names */
	array_t cookies;
	/* Parser, `request/response` staging allocations,
	WILL be freed at exit, and before `parse_http` execution. */
	array_t garbage;
	/* Connected client */
	http_socket	*client;
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
	httpi_t req;
	httpi_ws_t ws;
	http2_t http2;
	/* The protocol */
	char protocol[16];
	/* The requested method */
	char method[32];
	/* The response status message */
	char message[64];
	char variable[256];
};

/*
 * This structure helps to create an environment for the spawned CGI program.
 * Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
 * last element must be NULL.
 * However, on Windows there is a requirement that all these VARIABLE=VALUE\0
 * strings must reside in a contiguous buffer. The end of the buffer is
 * marked by two '\0' characters.
 * We satisfy both worlds: we create an envp array (which is vars), all
 * entries are actually pointers inside buf.  */
struct cgi_environment {
	http_t *conn;
	/* Data block */
	char *buf;      /* Environment buffer */
	size_t buflen;  /* Space available in buf */
	size_t bufused; /* Space taken in buf */
					/* Index block */
	char **var;     /* char **envp */
	size_t varlen;  /* Number of variables available in var */
	size_t varused; /* Number of variables stored in var */
};

/* Parsed Authorization header */
struct auth_header {
	char *user;
	int type;             /* 1 = basic, 2 = digest */
	char *plain_password; /* Basic only */
	char *uri, *cnonce, *response, *qop, *nc, *nonce; /* Digest only */
};

struct read_auth_file_struct {
	http_t *conn;
	struct auth_header auth_header;
	string_t domain;
	char buf[256 + 256 + 40];
	string_t f_user;
	string_t f_domain;
	string_t f_ha1;
};

/* Directory entry */
struct de {
	char *file_name;
	struct file file;
};

struct dir_scan_data {
	struct de *entries;
	size_t num_entries;
	size_t arr_size;
};

bool http_fopen(http_ini_t *ctx, const http_t *conn,
	string_t path, string_t mode, struct file *filep);

/* Used to process new incoming connections to the server. */
http_t *http_accept(http_socket *listener, http_ini_t *ctx);

/*
 * Closed a file associated with a filep structure.
 * If the function succeeds, the value 0 is returned.
 * Otherwise the return value is EOF and errno is set. */
int http_fclose(struct file *filep);

/*
 * Creates a directory mentioned in a PUT
 * request including all intermediate subdirectories. The following values can
 * be returned:
 * Return  0  if the path itself is a directory.
 * Return  1  if the path leads to a file.
 * Return -1  for if the path is too long.
 * Return -2  if path can not be created. */
int http_put_dir(http_ini_t *ctx, http_t *conn, string_t path);

/*
 * Removes an invalid file and throws
 * an error message if this does not succeed. */
void http_remove_bad_file(http_ini_t *ctx, http_t *conn, string_t path);

/* Used to construct an etag which can be used to identify a file on a specific moment. */
void http_construct_etag(http_t *ctx, string buf, size_t buf_len, const struct file *filep);

/*
 * Return true, if a resource has not been modified since a given datetime
 * and a 304 response should therefore be sufficient. */
bool http_is_not_modified(http_ini_t *ctx, http_t *conn, const struct file *filep);

int http_stat(http_t *conn, string_t path, struct file *filep);

/*
 * This is the heart of the `HttPi's` logic.
 * This function is called when the request is read, parsed and validated,
 * and `HttPi` must decide what action to take:
 *
 * Serve a file, or a directory, or call embedded function, etcetera. */
void http_handle_request(http_t *conn);

/* Send len bytes from the opened file to the client. */
void http_send_file_data(http_t *conn, struct file *filep,
	int64_t offset, int64_t len, int no_buffering);

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
int http_get_option_index(string_t name);

/* A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x". */
string_t http_next_option(string_t list, struct vec *val, struct vec *eq_val);
int http_parse_match_net(const struct vec *vec, const u_saddr_t *sa, int no_strict);

/* Processes a request/response from a remote client. */
int get_request_response(http_t *conn, char *ebuf, size_t ebuf_len, int *err);

/* Keep reading the input `conn` until \r\n\r\n appears in the
 * buffer (which marks the end of HTTP request). Buffer buf may already
 * have some data. The length of the data is stored in nread.
 * Upon every read operation, increase nread by the number of bytes read. */
int read_message(http_t *conn, char *buf, int bufsiz, int *nread);

int get_message(http_t *conn, char *ebuf, size_t ebuf_len, int *err);

/*
 * Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n */
int get_http_header_len(string_t buf, int buflen);

/*
 * Set the port options for a context.
 * The function returns the total number of ports opened,
 * or 0 if no ports have been opened. */
int http_set_ports_option(http_ini_t *ctx);
string_t http_get_default_option(ini_options_type name);
void http_set_close_on_exec(fds_t sock);
bool http_is_file_opened(struct file *filep);
int is_valid_port(unsigned long port);

/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer. */
int alloc_vprintf(string *out_buf, string prealloc_buf, size_t prealloc_size, string_t fmt, va_list ap);
int alloc_printf(string *out_buf, string buf, size_t size, string_t fmt, ...);
/* Return null terminated string `buf` of given maximum length. */
void http_vsnprintf(int *truncated, string buf, size_t buflen, string_t fmt, va_list ap);

/* Perform case-insensitive match of string against pattern
 *
 * Parameters:
 * `pat`: Pattern string.
 * `pattern_len`: Pattern length to search for match.
 * `str`: String to search for match patterns.
 *
 * Return:
 * - `Number` of characters matched.
 * -	`-1` if no valid match was found.
 *
 * Note: `0` characters might be a valid match for some patterns.
 *
 * `Pattern` match starts at the beginning of the string, so essentially
 * patterns are prefix patterns.
 *
 * Syntax is as follows:
 *
 * - `**` 	Matches everything
 * - `*`	Matches everything but the slash character ('/')
 * - `?` 	Matches any character but the slash character ('/')
 * - `$` 	Matches the end of the string
 * - `|` 	Matches if pattern on the left side or the right side matches.*/
int http_match_prefix(string_t pattern, size_t pattern_len, string_t str);
ptrdiff_t http_match_prefix_strlen(string_t pattern, string_t str);
/* HTTP 1.1 assumes keep alive if "Connection:" header is not set
 * This function must tolerate situations when connection info is not
 * set up, for example if request parsing failed. */
int should_keep_alive(http_t *conn);

/* Send all current and obsolete cache opt-out directives. */
void http_no_cache_header(http_t *conn);
void http_domain_header(http_t *conn);
void http_static_cache_header(http_t *conn);
void http_cors_header(http_t *conn);

int http_server(http_ini_t *ctx);

/*
 * Returns true, if a file must be hidden from browsing by the remote client.
 * A used provided list of file patterns to hide is used.
 * Password files are always hidden, independent of the patterns defined by the user. */
bool http_must_hide_file(http_ini_t *ctx, string_t path);

struct tm *http_gmtime_r(const time_t *clk, struct tm *result);

/* Do cleanup work when an error occurred initializing a context. */
http_ini_t *http_abort_start(http_ini_t *ctx, string_t fmt, ...);
void http_close_listening_sockets(http_ini_t *ctx);

/* Used to process a new incoming connection on a socket. */
void http_process_connection(http_ini_t *ctx, http_t *conn);

/* Check if the uri is valid.
 * return `URI_TYPE_UNKNOWN` for invalid uri,
 * return `URI_TYPE_ASTERISK` for *,
 * return `URI_TYPE_RELATIVE` for relative uri,
 * return `URI_TYPE_ABS_NOPORT` for absolute uri without port,
 * return `URI_TYPE_ABS_PORT` for absolute uri with port */
enum uri_type_t http_get_uri_type(string_t uri);

/* Return NULL or the relative uri at the current server */
string_t http_get_rel_url_at_current_server(string_t uri, http_t *conn);

/* Convert time_t to a string. According to RFC2616, Sec 14.18, this must be
 * included in all responses other than 100, 101, 5xx. */
void http_gmt_time_str(char *buf, size_t buf_len, time_t *t);

/* Sets callback handlers to uri's. */
void http_set_handler(http_ini_t *ctx,
	string_t uri, enum route_type_t handler_type,
	bool is_delete_request, route_cb handler,
	struct ws_subprotocols_s *subprotocols,
	ws_connect_cb connect_handler, ws_ready_cb ready_handler,
	ws_data_cb data_handler, ws_close_cb close_handler,
	auth_cb auth_handler, void_t cbdata);

http_t *http_connect_impl(const struct client_options *client_options,
	int use_ssl, struct error_data *error);

/**
 * Checks the request headers to see if the connection is a valid websocket protocol.
 * A websocket protocol has the following HTTP headers:
 *
 * Connection: Upgrade
 * Upgrade: Websocket */
bool http_is_websocket(http_t *conn);

/* Does the heavy lifting in writing data over a websocket connectin to a remote peer. */
int http_websocket_write_exec(http_t *conn, websocket_type opcode,
	string_t data, size_t data_len, uint32_t masking_key);

void http_websocket_deflate_response(http_t *conn);
void http_websocket_deflate_negotiate(http_t *conn);
int http_websocket_deflate_init(http_t *conn, int server);
/* Processes a websocket request on a connection. */
void http_websocket_request(http_ini_t *ctx, http_t *conn, int is_callback_resource, struct ws_subprotocols_s *subprotocols,
	ws_connect_cb ws_connect_handler, ws_ready_cb ws_ready_handler, ws_data_cb ws_data_handler, ws_close_cb ws_close_handler, void_t cbData);

/* Make first character uppercase in string/word, remainder lowercase,
a word is represented by separator character provided. */
string word_toupper(string str, char sep);

/* Return True if we should reply 304 Not Modified. */
int is_not_modified(http_t *conn, const struct file *filestat);
void handle_not_modified_static_file_request(http_t *conn, struct file *filep);
void handle_static_file_request(http_t *conn, string_t path, struct file *filep,
	string_t mime_type, string_t additional_headers);
void handle_file_based_request(http_t *conn, string_t path, struct file *file);
/* Returns true, if a file defined by a specific path is located in memory. */
bool http_is_file_in_memory(http_ini_t *ctx, http_t *conn, string_t path, struct file *filep);
void handle_directory_request(http_t *conn, string_t dir);

/* Valid listening port specification is: [ip_address:]port[s]
 * Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
 * Examples for IPv6: [::]:80, [::1]:80,
 *   [2001:0db8:7654:3210:FEDC:BA98:7654:3210]:443s
 *   see https://tools.ietf.org/html/rfc3513#section-2.2
 * In order to bind to both, IPv4 and IPv6, you can either add
 * both ports using 8080,[::]:8080, or the short form +8080.
 * Both forms differ in detail: 8080,[::]:8080 create two sockets,
 * one only accepting IPv4 the other only IPv6. +8080 creates
 * one socket accepting IPv4 and IPv6. Depending on the IPv6
 * environment, they might work differently, or might not work
 * at all - it must be tested what options work best in the
 * relevant network environment. */
int parse_port_string(const struct vec *vec, http_socket *so, int *ip_version);

/* Construct fake connection structure. Used for logging, if connection
 * is not applicable at the moment of logging. */
http_t *fake_conn(http_t *fc, http_ini_t *ctx);
/* Use to mask data when writing data over a websocket client connection. */
void mask_data(string_t _in, size_t in_len, uint32_t masking_key, string out);

/* Read from IO channel - opened file descriptor, socket.
 * Return value:
 *  >=0 .. number of bytes successfully read
 *   -1 .. timeout, error */
int _read_inner(http_t *conn, void *buf, size_t len);
/*
 * Parse UTC date-time string, and return the corresponding time_t value.
 * This function is used in the if-modified-since calculations */
time_t parse_date_str(string_t datetime);
/* Internal function. Assumes conn is valid */
void send_authorization_request(http_t *conn, string_t realm);
/* Return 1 if request is authorised, 0 otherwise. */
int check_authorization(http_t *conn, string_t path);
/* Authorize against the opened passwords file. Return 1 if authorized. */
int authorize(http_t *conn, struct file *filep, string_t realm);
int remove_directory(http_t *conn, string_t dir);
int fs_scan_directory(http_t *conn, string_t dir, void *data, int (*cb)(struct de *, void *));
void qjs_exec_script(http_t *conn, string_t script_name);

int is_authorized_for_put(http_t *conn);
void http_compressed_data(http_t *conn, struct file *filep);
unsigned short sockaddr_in_port(u_saddr_t *s);
int http_switch_domain(http_t *conn);
string_t http_fgets(char *buf, size_t size, struct file *filep, char **p);
void discard_unread_request_data(http_t *conn);
/* Pre-process URIs according to RFC + protect against directory disclosure
 * attacks by removing '..', excessive '/' and '\' characters */
void remove_double_dots_slashes(char *inout);
int set_throttle(string_t spec, uint32_t remote_ip, string_t uri);
void close_socket_gracefully(http_t *conn);
void close_connection(http_t *conn);

/* Used to free the resources associated with a context. */
void http_free_ini(http_ini_t *ctx);
void_t free_ex(void_t memory);

/* Get system information. It can be printed or stored by the caller.
 * Return the size of available information. */
int http_get_system_info(char *buffer, int buflen);

/* Get context information. It can be printed or stored by the caller.
 * Return the size of available information. */
int http_get_context_info(const http_ini_t *ctx, char *buffer, int buflen);

int http2_send_response_headers(http_t *conn);
void http2_must_use_http1(http_t *conn);
void http2_data_frame_head(http_t *conn, uint32_t frame_size, int is_final);
void process_new_http2_connection(http_t *conn);
#endif /* _HTTPI_INTERNAL_H */