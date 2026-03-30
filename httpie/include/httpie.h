#ifndef _HTTPIE_H_
#define _HTTPIE_H_

#include <map.h>
#include <json.h>
#include <https.h>

#define _POSIX_THREAD_SAFE_FUNCTIONS 1
#define ERROR_STRING_LEN ARRAY_SIZE

/* HTTP server context */
typedef struct http_ini_s http_ini_t;
typedef struct ini_option options_ini_t;
typedef struct http2_s http2_t;
typedef struct h2_header h2_header_t;

#if !defined(HTTP2_DYN_TABLE_SIZE)
#	define HTTP2_DYN_TABLE_SIZE (256)
#endif

/* This structure needs to be passed to http_start(),
 * to let `httpie` know which callbacks to invoke. */
typedef struct http_clb_s http_clb_t;

/* Describes listening socket, or socket which was accept()-ed by the master
 * thread and queued for future handling by the worker thread. */
typedef server_socket http_socket;

typedef int	(*route_cb)(http_t *conn, void_t cbdata);
typedef int	(*auth_cb)(http_t *conn, void_t cbdata);
typedef int	(*ws_connect_cb)(http_t *conn, void_t cbdata);
typedef void (*ws_ready_cb)(http_t *conn, void_t cbdata);
typedef int	(*ws_data_cb)(http_t *conn, int, string buffer, size_t buflen, void_t cbdata);
typedef void (*ws_close_cb)(http_t *conn, void_t cbdata);

/* Called when `httpie` has received new HTTP request.
 * If the callback returns one, it must process the request
 * by sending valid HTTP headers and a body. `httpie` will not do
 * any further processing. Otherwise it must return zero.
 *
 * Note the "request_cb" function is called
 * before an authorization check. If an authorization check is
 * required, use a request_handler instead.
 *
 * Return value:
 * - 0: `httpie` will process the request itself. In this case,
 * the callback must not send any data to the client.
 * - 1-999: callback already processed the request. `httpie` will
 * not send any data after the callback returned. The
 * return code is stored as a HTTP status code for the access log. */
typedef int(*request_cb)(http_t *conn);

/* Called when `httpie` is about to log a message. If callback returns
 * non-zero, `httpie` does not log anything. */
typedef int (*log_message_cb)(const http_t *conn, string_t message);

/* Called when `httpie` is about to log access. If callback returns
 * non-zero, `httpie` does not log anything. */
typedef int(*log_access_cb)(const http_t *conn, string_t message);

/* Called when `httpie` tries to open a file. Used to intercept file open
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
typedef string_t(*open_file_cb)(http_t *conn, string_t path, size_t *data_len);

/* Called when `httpie` is about to send HTTP error to the client.
 * Implementing this callback allows to create custom error pages.
 *
 * Parameters:
 * - status: HTTP error status code.
 *
 * Return value:
 * - 1: run `httpie` error handler.
 * - 0: callback already handled the error. */
typedef int (*http_error_cb)(http_t *, int status);

/* Called after `httpie` context has been created,
 * before requests are processed.
 *
 * Parameters:
 * - ctx: `httpie` handle */
typedef void (*init_context_cb)(const http_ini_t *ctx);

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Keeps reading the input into buffer buf,
 * until \r\n\r\n appears in the buffer which marks the end
 * of the HTTP request. The buffer buf may already have some data. The length
 * of the data is stored in nread. Upon every read operation the value of nread
 * is incremented by the number of bytes read. */
C_API int http_read_request(http_t *conn, string buf, int bufsiz, int *nread);

/* Forwards body data to the client.
The function returns true if successful, and false otherwise. */
C_API bool http_forward_body(http_t *conn, FILE *fp);

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
C_API void http_file(http_t *conn, const char *path, const char *mime_type,
	const char *additional_headers);

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
C_API int http_get_request_link(http_t *conn, char *buf, size_t buflen);

/* Read data from the remote end, return number of bytes read.
 *
 * Return:
 * - 0     connection has been closed by peer. No more data could be read.
 * - < 0   read error. No more data could be read from the connection.
 * - > 0   number of bytes read into the buffer. */
C_API int http_read(http_t *conn, void_t buf, size_t len);

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


/* Send data to the client.
 *
 * Return:
 * - `0` when the connection has been closed
 * - `-1` on error
 * - `>0` number of bytes written on success */
C_API int http_write(http_t *conn, const void *buf, size_t len);

/* Send "HTTP 200 OK" response header.
 * After calling this function, use mg_write or mg_send_chunk to send the
 * response body.
 *
 * Parameters:
 *   conn: Current connection handle.
 *   mime_type: Set Content-Type for the following content.
 *   content_length: Size of the following content, if content_length >= 0.
 *                   Will set transfer-encoding to chunked, if set to -1.
 * Return:
 *   < 0   Error */
C_API int http_ok(http_t *conn, string_t mime_type, long long content_length);

/* Send a 30x redirect response.
 *
 * Redirect types (status codes):
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
C_API int http_url_encode(const char *src, char *dst, size_t dst_len);

/* URL-decode input buffer into destination buffer.
   0-terminate the destination buffer.
   form-url-encoded data differs from URI encoding in a way that it
   uses '+' as character for space, see RFC 1866 section 8.2.1
   http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
   Return: length of the decoded data, or -1 if dst buffer is too small. */
C_API int http_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded);

/* Return builtin mime type for the given file name.
   For unrecognized extensions, "text/plain" is returned. */
C_API const char *http_get_builtin_mime_type(const char *path);

/* Send a part of the message body, if chunked transfer encoding is set.
 * Only use this function after sending a complete HTTP request or response
 * header with "Transfer-Encoding: chunked" set. */
C_API int http_chunk(http_t *conn, string_t chunk, unsigned int chunk_len);

/* Initialize a new HTTP response
 * Parameters:
 *   conn: Current connection handle.
 *   status: HTTP status code (e.g., 200 for "OK").
 * Return:
 *   0:    ok
 *  -1:    parameter error
 *  -2:    invalid connection type
 *  -3:    invalid connection status
 *  -4:    network error */
C_API int http_response_start(http_t *conn, int status);

/* Add a new HTTP response header line
 * Parameters:
 *   conn: Current connection handle.
 *   header: Header name.
 *   value: Header value.
 *   value_len: Length of header value, excluding the terminating zero.
 *              Use -1 for "strlen(value)".
 * Return:
 *    0:    ok
 *   -1:    parameter error
 *   -2:    invalid connection type
 *   -3:    invalid connection status
 *   -4:    too many headers
 *   -5:    out of memory */
C_API int http_response_add(http_t *conn, string_t header, string_t value, int value_len);

/* Send http response
 * Parameters:
 *   conn: Current connection handle.
 * Return:
 *   0:    ok
 *  -1:    parameter error
 *  -2:    invalid connection type
 *  -3:    invalid connection status
 *  -4:    network send failed */
C_API int http_response_send(http_t *conn);

/* Add a complete header string (key + value).
 * Parameters:
 *   conn: Current connection handle.
 *   additional_headers: Header line(s) in the form "name: value\r\n".
 * Return:
 *  >=0:   no error, number of header lines added
 *  -1:    parameter error
 *  -2:    invalid connection type
 *  -3:    invalid connection status
 *  -4:    out of memory */
C_API int http_response_multi(http_t *conn, string additional_headers);

/*
 * Returns a string to be used in the header which suggests the connection to
 * be either closed, or kept alive for further requests. */
C_API string_t http_suggest_connection_header(http_t *conn);

/*
 * Prints a formatted error message to the opened
 * error log stream. It first tries to use a user supplied error handler. If
 * that doesn't work, the alternative is to write to an error log file. */
C_API void http_logger(enum http_dbg debug_level, http_t *conn, string_t fmt, ...);

/* Sends a list of allowed options a client can use to connect to the server. */
C_API void http_options(http_t *conn);
C_API bool http_get_random(uint64_t *out);

/* Used to free the resources associated with a context. */
C_API void http_free_ini(http_ini_t *ctx);
C_API void_t http_free_ex(void_t memory);

/*
 * Processes the user supplied options and adds
 * them to the central option list of the `server` context.
 *
 * Sets the options to reasonable default values, if not supplied.
 *
 * When successful, the function returns false. Otherwise true is returned,
 * and the function already performed a cleanup. */
C_API bool http_init_options(http_ini_t *ctx, string_t *options);

/* The main `setup` entry point for the `httpie` server. */
C_API http_ini_t *http_start(int max_fd, http_clb_t *callbacks, void *user_data, const options_ini_t *options);

/*
 * Stores in incoming body for future processing.
 * The function returns the number of bytes actually read,
 * or a negative number to indicate a failure. */
C_API int64_t http_store_body(http_ini_t *ctx, http_t *conn, string_t path);

C_API http_clb_t http_callbacks(request_cb begin, log_message_cb message, log_access_cb log,
	open_file_cb file, http_error_cb error, init_context_cb init);

/* Use to stop an instance of a `httpie` server completely and return all its resources. */
C_API void http_stop(http_ini_t *ctx);

/*
 * Returns the content of an option for a given context.
 * If an error occurs, NULL is returned. If the option is valid
 * but there is no context associated with it,
 * the return value is an empty string. */
C_API string_t http_get_option(http_ini_t *ctx, string_t name);

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

/*
 * Use to write as a client to a websocket server. The function returns -1 if an error occurs,
 * otherwise the amount of bytes written. */
C_API int http_websocket_client_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen);

#ifdef __cplusplus
}
#endif

#endif /* _HTTPIE_H_ */
