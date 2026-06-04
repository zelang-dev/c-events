#ifndef _HTTPI_H_
#define _HTTPI_H_

#define HTTPI_VERSION "0.1.0"
#define HTTPI_VERSION_MAJOR (0)
#define HTTPI_VERSION_MINOR (1)
#define HTTPI_VERSION_PATCH (0)

#include <map.h>
#include <json.h>
#include <https.h>
#include <quickjs.h>
#include <quickjs-libc.h>

#ifndef HTTPI_THREAD
#	if defined(_WIN32)
#		define HTTPI_THREAD			unsigned __stdcall
#		define HTTPI_THREAD_TYPE		unsigned
#		define HTTPI_THREAD_CALLING_CONV	__stdcall
#		define HTTPI_THREAD_RETNULL		0
#	else  /* _WIN32 */
#		define HTTPI_THREAD			void *
#		define HTTPI_THREAD_TYPE		void *
#		define HTTPI_THREAD_CALLING_CONV
#		define HTTPI_THREAD_RETNULL		NULL
# 		define ZLIB_INSECURE 1
#		include <pwd.h>
#	endif  /* _WIN32 */
#endif  /* HTTPI_THREAD */

#undef in
#include <zlib.h>
#define in ,

#define ERROR_STRING_LEN ARRAY_SIZE

/* HTTP server context */
typedef struct http_ini_s http_ini_t;
typedef struct ini_option options_ini_t;
typedef struct http2_s http2_t;
typedef struct h2_header h2_header_t;
typedef struct form_data_handler_s form_data_handler_t;
typedef struct http_server_port http_server_port_t;
typedef struct httpi_s httpi_t;
typedef struct httpi_ws_s httpi_ws_t;

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

struct client_options {
	string_t host;
	int port;
	string_t client_cert;
	string_t server_cert;
};

#if !defined(HTTP2_DYN_TABLE_SIZE)
#	define HTTP2_DYN_TABLE_SIZE (256)
#endif

#define server_opts(str_opts) ((const options_ini_t **)(str_opts))

/* Record of a port a server/client is listening on
 * Describes listening socket, or socket which was accept()-ed by the `main`
 * thread and queued for future handling by the worker `task` thread `pool`. */
typedef server_socket http_socket;

typedef int	(*route_cb)(http_t *conn, void_t cbdata);
typedef int	(*auth_cb)(http_t *conn, void_t cbdata);
typedef int	(*ws_connect_cb)(http_t *conn, void_t cbdata);
typedef void (*ws_ready_cb)(http_t *conn, void_t cbdata);
typedef int	(*ws_data_cb)(http_t *conn, int, string buffer, size_t buflen, void_t cbdata);
typedef void (*ws_close_cb)(http_t *conn, void_t cbdata);
typedef void (*http_main_cb)(http_ini_t *);

/* Called when `HttPi` has received new HTTP request.
 * If the callback returns one, it must process the request
 * by sending valid HTTP headers and a body. `HttPi` will not do
 * any further processing. Otherwise it must return zero.
 *
 * Note the "request_cb" function is called
 * before an authorization check. If an authorization check is
 * required, use a request_handler instead.
 *
 * Return value:
 * - 0: `HttPi` will process the request itself. In this case,
 * the callback must not send any data to the client.
 * - 1-999: callback already processed the request. `HttPi` will
 * not send any data after the callback returned. The
 * return code is stored as a HTTP status code for the access log. */
typedef int(*request_cb)(http_t *conn);

/* Called when `HttPi` is about to log a message. If callback returns
 * non-zero, `HttPi` does not log anything. */
typedef int (*log_msg_cb)(const http_t *conn, string_t message);

/* Called when `HttPi` is about to log access. If callback returns
 * non-zero, `HttPi` does not log anything. */
typedef int(*log_access_cb)(const http_t *conn, string_t message);

/* Called when `HttPi` tries to open a file. Used to intercept file open
 * calls, and serve file data from memory instead.
 *
 * Parameters:
 * - path:     Full path to the file to open.
 * - data_len: Placeholder for the file size, if file is served from memory.
 *
 * Return value:
 * - NULL: do not serve file from memory, proceed with normal file open.
 * - non-NULL: pointer to the file contents in memory. data_len must be
 * initialized with the size of the memory block. */
typedef string_t(*file_open_cb)(http_t *conn, string_t path, size_t *data_len);

/* Called when `HttPi` is about to send HTTP error to the client.
 * Implementing this callback allows to create custom error pages.
 *
 * Parameters:
 * - status: HTTP error status code.
 *
 * Return value:
 * - 1: run `HttPi` error handler.
 * - 0: callback already handled the error. */
typedef int (*http_error_cb)(http_t *, int status);

/* Called when `httpi` has uploaded a file to a temporary directory as a
 * result of `http_upload()` call.
 *
 * Parameters:
 * - conn: `http_t` handle.
 * - file_name: full path name to the uploaded file. */
typedef void(*upload_form_cb)(http_t *, string_t file_name);

/* This structure needs to be passed to httpi_setup(),
 * to let `HttPi` know which callbacks to invoke. */
typedef struct http_clb_s {
	/* handle everything callback*/
	request_cb handler;
	log_msg_cb log_message;
	log_access_cb log_access;
	file_open_cb open_file;
	http_error_cb http_error;
	upload_form_cb upload;
} http_clb_t;

struct init_data {
	/* callback function pointer */
	const http_clb_t *callbacks;
	/* data */
	void_t user_data;
	string_t *configuration_options;
};

#ifdef __cplusplus
extern "C"
{
#endif

/* Get the list of ports that `HttPi` is listening on.
   The parameter `size` is the size of the ports array in elements.
   The caller is responsibility to allocate the required memory.
   This function returns the number of `http_server_port_t ` elements
   filled in, or <0 in case of an error. */
C_API int http_server_ports(http_ini_t *ctx, int size, http_server_port_t *ports);

/* Send contents of the entire file together with HTTP headers.
 *
 *  Parameters:
 * - `conn`: Current connection information.
 * - `path`: Full path to the file to send.
 * - `mime_type`: Content-Type for file. `NULL` will cause the type to be
 * looked up by the file extension.
 * - `additional_headers`: Additional custom header fields appended to the header.
 * Each header should start with an X-, to ensure it is not included twice.
 * `NULL` does not append anything. */
C_API void http_file(http_t *conn, string_t path, string_t mime_type, string_t additional_headers);

/* Send data to the client using printf() semantics.
   Works exactly like `http_write()`, but allows to do message formatting. */
C_API int http_printf(http_t *conn, string_t fmt, ...);

/* Get a formatted link corresponding to the current request
*
* Parameters:
* - conn: current connection information.
* - buf: string buffer (out)
* - buflen: length of the string buffer
*
*   Returns:
* - `< 0`: error
* - `>= 0`: ok */
C_API int http_get_request_link(http_t *conn, string buf, size_t buflen);

/* Read data from the remote end, return number of bytes read.
 *
 * Return:
 * - 0     connection has been closed by peer. No more data could be read.
 * - < 0   read error. No more data could be read from the connection.
 * - > 0   number of bytes read into the buffer. */
C_API int http_read(http_t *conn, void_t buf, size_t len);
C_API string http_read_until(http_t *conn, int *size);

/* Send contents of the file without HTTP headers.
 * The code must send a valid HTTP response header before using this function.
 *
 * Parameters:
 * -  conn: Current connection information.
 * -  path: Full path to the file to send.
 *
 * Return:
 * -  < 0  On Error */
C_API int http_file_body(http_t *conn, string_t path);

/* Send HTTP error reply. */
C_API int http_error(http_t *conn, int status, string_t fmt, ...);

/* Send data `buf` to the client.
 *
 * Return:
 * - `0` when the connection has been closed
 * - `-1` on error
 * - `>0` number of bytes written on success */
C_API int http_write(http_t *conn, const_t buf, size_t len);

/* Send "HTTP 200 OK" response header.
 * After calling this function, use `http_write` or `http_chunk` to send the
 * response body.
 *
 * Parameters:
 * - conn: Current connection handle.
 * - mime_type: Set Content-Type for the following content.
 * - content_length: Size of the following content, if content_length >= 0.
 * Will set transfer-encoding to chunked, if set to -1.
 *
 * Return:
 * - `< 0`: Error */
C_API int http_ok(http_t *conn, string_t mime_type, long long content_length);

/* Send a 30x redirect `target_url` response.
 *
 * `redirect code` types (status codes):
 *
 * Status | Perm/Temp | Method              | Version
 *   301  | permanent | POST->GET undefined | HTTP/1.0
 *   302  | temporary | POST->GET undefined | HTTP/1.0
 *   303  | temporary | always use GET      | HTTP/1.1
 *   307  | temporary | always keep method  | HTTP/1.1
 *   308  | permanent | always keep method  | HTTP/1.1 */
int http_redirect(http_t *conn, string_t target_url, int redirect_code);

/* URL-encode input buffer into destination buffer.
   returns the length of the resulting buffer or -1
   is the buffer is too small. */
C_API int http_url_encode(string_t src, string dst, size_t dst_len);

/* URL-decode input buffer into destination buffer.
   0-terminate the destination buffer.
   form-url-encoded data differs from URI encoding in a way that it
   uses '+' as character for space, see RFC 1866 section 8.2.1
   http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
   Return: length of the decoded data, or -1 if dst buffer is too small. */
C_API int http_url_decode(string_t src, int src_len, string dst, int dst_len, int is_form_url_encoded);

/* Return builtin mime type for the given file name.
   For unrecognized extensions, "text/plain" is returned. */
C_API string_t http_builtin_mime_type(string_t path);

/* Send a part of the message body, if chunked transfer encoding is set.
 * Only use this function after sending a complete HTTP request or response
 * header with "Transfer-Encoding: chunked" set. */
C_API int http_chunk(http_t *conn, string_t chunk, unsigned int chunk_len);

/* Transfer-Encoding is chunked:
 * - 0 = not chunked,
 * 1 = chunked, not yet read, or some data read,
 * 2 = chunked, all data read,
 * 3 = chunked, has error */
C_API int http_chunk_state(http_t *conn);

/* Initialize a new HTTP response
 * Parameters:
 * - conn: Current connection handle.
 * - status: HTTP status code (e.g., 200 for "OK").
 * Return:
 * -  `0`: ok
 * - `-1`: parameter error
 * - `-2`: invalid connection type
 * - `-3`: invalid connection status
 * - `-4`: network error */
C_API int http_response_start(http_t *conn, int status);

/* Add a new HTTP response header line
 *
 * Parameters:
 * - conn: Current connection handle.
 * - header: Header name.
 * - value: Header value.
 * - value_len: Length of header value, excluding the terminating zero.
 * Use -1 for "strlen(value)".
 *
 * Return:
 * -  `0`: ok
 * - `-1`: parameter error
 * - `-2`: invalid connection type
 * - `-3`: invalid connection status
 * - `-4`: too many headers
 * - `-5`: out of memory */
C_API int http_response_add(http_t *conn, string_t header, string_t value, int value_len);

/* Send http response
 *
 * Parameters:
 * - conn: Current connection handle.
 *
 * Return:
 * -  `0`: ok
 * - `-1`: parameter error
 * - `-2`: invalid connection type
 * - `-3`: invalid connection status
 * - `-4`: network send failed */
C_API int http_response_send(http_t *conn);

/* Add a complete header string (key + value).
 *
 * Parameters:
 * - conn: Current connection handle.
 * - additional_headers: Header line(s) in the form "name: value\r\n".
 *
 * Return:
 * - `>=0`: no error, number of header lines added
 * - `-1`: parameter error
 * - `-2`: invalid connection type
 * - `-3`: invalid connection status
 * - `-4`: out of memory */
C_API int http_response_multi(http_t *conn, string_t additional_headers);

/*
 * Returns a string to be used in the header which suggests the connection to
 * be either closed, or kept alive for further requests. */
C_API string_t http_suggest_connection_header(http_t *conn);

/* Wait for a response from the server
 *
 *  Parameters:
 * - conn: connection
 * - ebuf, ebuf_len: error message placeholder.
 * - timeout: time to wait for a response in milliseconds (if < 0 then wait forever)
 *
 *  Return:
 * - On success, >= 0
 * - On error/timeout, < 0 */
C_API int http_get_response(http_t *conn, string ebuf, size_t ebuf_len, int timeout);

/* Close the connection opened by `http_download()` or `http_connect()`. */
C_API void http_close_connection(http_t *conn);

/* Connect to a TCP server as a client (can be used to connect to a HTTP server)
 *
 *  Parameters:
 * - host: host to connect to, i.e. "www.wikipedia.org" or "192.168.1.1" or "localhost"
 * - port: server port
 * - use_ssl: make a secure connection to server
 * - error_buffer, error_buffer_size: buffer for an error message
 *
 *  Return:
 * - On success, valid `http_t` object.
 * - On error, NULL. Se error_buffer for details. */
C_API http_t *http_connect(string_t host, int port,
	int use_ssl, string error_buffer, size_t error_buffer_size);

/* Download data from the remote web server.
 *
 * - host: host name to connect to, e.g. "foo.com", or "10.12.40.1".
 * - port: port number, e.g. 80.
 * - use_ssl: whether to use SSL connection.
 * - request_fmt,...: HTTP request.
 *
 *  Return:
 * - On success, valid pointer to the new connection, suitable for `http_read()`.
 * - On error, NULL. `task_erred_str()` contains error message.
 *
 *  Example:
 *
 ```c
 	 http_t *conn = http_download("google.com", 80, 0,"%s",
 						"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n");
 ```
 * `http_download` is equivalent to calling `http_connect` followed by
 * `http_printf` and `http_get_response`. Using these three functions directly may
 *  allow more control as compared to using `http_download`. */
C_API http_t *http_download(string_t host, int port, int use_ssl, string_t fmt, ...);

/* File upload functionality.
 * Each uploaded file gets saved into a temporary file and event is sent.
 * Return number of uploaded files. */
C_API int http_upload(http_t *conn, string_t destination_dir);

/*
 * Prints a formatted error message to the opened
 * error log stream. It first tries to use a user supplied error handler. If
 * that doesn't work, the alternative is to write to an error log file. */
C_API void http_log(enum http_dbg debug_level, http_t *conn, string_t fmt, ...);

/* Public function to check http digest authentication header */
C_API int http_check_digest_access_authentication(http_t *conn, string_t realm, string_t filename);

/* Interface function. Parameters are provided by the user, so do
 * at least some basic checks. */
int http_send_digest_access_authentication_request(http_t *conn, string_t realm);

/* Return stringified MD5 hash for list of strings. Buffer must be 33 bytes. */
C_API string http_md5(char buf[33], ...);

/* Same as `http_modify_passwords_file`, but instead of the plain-text
 * password, the HA1 hash is specified. The plain-text password is
 * not made known to `HttPi`.
 *
 * The HA1 hash is the MD5 checksum of a "user:realm:password" string
 * in lower-case hex format. For example, if the user name is "myuser",
 * the realm is "myrealm", and the password is "secret", then the HA1 is
 * e67fd3248b58975c3e89ff18ecb75e2f. */
C_API int http_modify_passwords_file_ha1(string_t fname, string_t domain, string_t user, string_t ha1);

/* Add, edit or delete the entry in the passwords file.
 *
 * This function allows an application to manipulate .htpasswd files on the
 * fly by adding, deleting and changing user records. This is one of the
 * several ways of implementing authentication on the server side. For another,
 * cookie-based way please refer to the examples/chat in the source tree.
 *
 * Parameter:
 * - fname: Path and name of a file storing multiple passwords
 * - domain: HTTP authentication realm (authentication domain) name
 * - user: User name
 * - pass: If `password` is not NULL, entry modified or added.
 * If `password` is NULL, entry is deleted.
 *
 *  Return:
 * - `1`: on success
 * - `0`: on error. */
C_API int http_modify_passwords_file(string_t fname, string_t domain, string_t user, string_t pass);

/* Sends a list of allowed options a client can use to connect to the server. */
C_API void http_options(http_t *conn);
C_API bool http_get_random(uint64_t *out);

/* Return array of `ini_option`, representing all valid `server` configuration
   options. The array is terminated by a NULL name option. */
C_API const options_ini_t *http_get_valid_options(void);

/*
 * Processes the user supplied options and adds
 * them to the central option list of the `server` context.
 *
 * Sets the options to reasonable default values, if not supplied.
 *
 * When successful, the function returns false. Otherwise true is returned,
 * and the function already performed a cleanup. */
C_API bool http_ini_options(http_ini_t *ctx, string_t *options);
/*
 * Returns the content of an option for a given context.
 * If an error occurs, NULL is returned. If the option is valid
 * but there is no context associated with it,
 * the return value is an empty string. */
C_API string_t http_get_option(http_ini_t *ctx, string_t name);

C_API bool http_set_ini_option(http_ini_t *ctx, string_t option, string_t value);

/* Add an additional domain to an already running web server. */
C_API int http_add_domain(http_ini_t *ctx, string_t *options);

/*
 * Stores in incoming body for future processing.
 * The function returns the number of bytes actually read,
 * or a negative number to indicate a failure. */
C_API int64_t http_store_body(http_ini_t *ctx, http_t *conn, string_t path);

C_API http_clb_t http_callbacks(request_cb handler, log_msg_cb message, log_access_cb log,
	file_open_cb file, http_error_cb error, upload_form_cb form);

/* Use to stop an instance of a `HttPi` server completely and return all its resources. */
C_API void http_stop(http_ini_t *ctx);

/* Sets a `request/route` handler for a specific uri in a server context. */
C_API void http_route(http_ini_t *ctx, string_t uri, route_cb handler, void_t cbdata);

/* Sets callback functions for the processing of events from a websocket. */
C_API void http_websocket_route(http_ini_t *ctx, string_t uri,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	void_t cbdata);

/* Writes data over a websocket connection. */
C_API int http_websocket_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen);
C_API int http_websocket_continuation(http_t *conn, string_t data, size_t dataLen);
C_API int http_websocket_text(http_t *conn, string_t data, size_t dataLen);
C_API int http_websocket_binary(http_t *conn, const_t data, size_t dataLen);
C_API int http_websocket_ping(http_t *conn, string_t data, size_t dataLen);
C_API int http_websocket_pong(http_t *conn, string_t data, size_t dataLen);
C_API int http_websocket_close(http_t *conn, string_t data, size_t dataLen);
C_API void http_websocket_wait(http_t *conn);

/*
 * Use to write as a client to a websocket server. The function returns -1 if an error occurs,
 * otherwise the amount of bytes written. */
C_API int http_websocket_client_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen);

/* Connect to a websocket as a client.
 *
 *  Parameters:
 * - host: host to connect to, i.e. "echo.websocket.org" or "192.168.1.1" or "localhost"
 * - port: server port
 * - use_ssl: make a secure connection to server
 * - path: server path you are trying to connect to, i.e. if connection to localhost/app, path should be "/app"
 * - origin: value of the `Origin:` HTTP header
 * - data_func: callback that should be used when data is received from the server
 * - close_func: callback that should be used when close is received from the server
 * - user_data: user supplied argument
 *
 *  Return:
 * - On success, valid `http_t` object.
 * - On error, NULL. See `task_erred_str()` for details. */
C_API http_t *http_websocket_connect(string_t host, int port, int use_ssl, string_t path, string_t origin,
	ws_data_cb data_func, ws_close_cb close_func, void_t user_data);

C_API http_t *http_websocket_connect_extensions(string_t host, int port, int use_ssl,
	string_t path, string_t origin, string_t extensions, ws_data_cb data_func, ws_close_cb close_func, void_t user_data);

C_API http_t *http_websocket_connect_secure(struct client_options *client_options,
	string_t path, string_t origin, ws_data_cb data_func, ws_close_cb close_func, void_t user_data);

C_API http_t *http_websocket_connect_secure_extensions(struct client_options *client_options,
	string_t path, string_t origin, string_t extensions, ws_data_cb data_func, ws_close_cb close_func, void_t user_data);

C_API void http_user_data_set(const http_t *const_conn, void_t data);
C_API void_t http_user_data(const http_t *conn);
C_API httpi_t *http_request_info(const http_t *conn);

/* The main `setup` entry point for the `HttPi` server. */
C_API http_ini_t *httpi_setup(int max_fd, http_clb_t *callbacks,
	void_t user_data, const options_ini_t **options);

/* Create/execute the `main task` ~coroutine~ `entry/start` point for `HttPi` server.
 *
 * - This will also create additional `tasks` base on number of
 * ~Server~ sockets created for `accept/listen` handling.
 * - All `accepted` connections, will create a coroutine `task` handled in
 * separate ~thread pool~ aka `Green Thread` for immediately execution. */
C_API void httpi_start(http_ini_t *ctx, http_main_cb start);

C_API string_t httpi_version(void);
C_API http_ini_t *httpi_context(http_t *conn);
C_API void_t httpi_user_data(http_ini_t *ctx);
C_API void_t httpi_user_context_data(http_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* _HTTPI_H_ */
