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

/* Called when `httpie` is about to log a message. If callback returns
 * non-zero, `httpie` does not log anything. */
typedef int (*log_message_cb)(const http_t *conn, string_t message);

/* Called when `httpie` is about to log access. If callback returns
 * non-zero, `httpie` does not log anything. */
typedef int(*log_access_cb)(const http_t *conn, string_t message);

/* Called when `httpie` tries to open a file. Used to intercept file open
 * calls, and serve file data from memory instead.
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
 * Parameters:
 * - status: HTTP error status code.
 *
 * Return value:
 * - 1: run `httpie` error handler.
 * - 0: callback already handled the error. */
typedef int (*http_error_cb)(http_t *, int status);

/* Called after `httpie` context has been created,
 * before requests are processed.
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

/*
 * Returns true if the connection
 * should be kept alive and false if it should be closed.
 *
 * HTTP 1.1 assumes keep alive if "Connection:" header is not set This function
 * must tolerate situations when connection info is not set up, for example if
 * request parsing failed. */
C_API bool http_should_keep_alive(http_t *conn);
C_API int http_printf(http_t *conn, string_t fmt, ...);
C_API int http_printf_no_cache(http_t *conn);
C_API int http_read(http_t *conn, void_t buf, size_t len);
C_API void http_error(http_t *conn, int status, string_t fmt, ...);

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

C_API http_clb_t http_callbacks(log_message_cb message, log_access_cb log,
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
C_API void http_websocket_route(http_ini_t *ctx, const char *uri,
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
