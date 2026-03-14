#ifndef _HTTPIE_H_
#define _HTTPIE_H_

#include <map.h>
#include <json.h>
#include <https.h>

#define _POSIX_THREAD_SAFE_FUNCTIONS 1
#define ERROR_STRING_LEN ARRAY_SIZE

/* HTTP server context */
typedef struct http_ini_s http_ini_t;

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
C_API int http_read_request(http_t *conn, char *buf, int bufsiz, int *nread);

/* Processes a request from a remote client. */
C_API bool http_get_request(http_t *conn, int *err);

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
C_API int http_printf(http_t *conn, const char *fmt, ...);
C_API int http_printf_no_cache(http_t *conn);
C_API int http_read(http_t *conn, void *buf, size_t len);
C_API void http_error(http_t *conn, int status, const char *fmt, ...);

/*
 * Returns a string to be used in the header which suggests the connection to
 * be either closed, or kept alive for further requests. */
C_API const char *http_suggest_connection_header(http_t *conn);

/*
 * Prints a formatted error message to the opened
 * error log stream. It first tries to use a user supplied error handler. If
 * that doesn't work, the alternative is to write to an error log file. */
C_API void http_logger(enum http_dbg debug_level, http_t *conn, const char *fmt, ...);

/* Sends a list of allowed options a client can use to connect to the server. */
C_API void http_options(http_t *conn);
C_API bool http_get_random(uint64_t *out);

/* Do cleanup work when an error occurred initializing a context. */
C_API http_ini_t *http_abort_start(http_ini_t *ctx, const char *fmt, ...);

/* Returns all the from the heap allocated space to store config options back to the heap. */
C_API void http_free_config_options(http_ini_t *ctx);
C_API void *http_free_ex(void *memory);

/* Used to free the resources associated with a context. */
C_API void http_free_context(http_ini_t *ctx);

/* Sets the options of a newly created context to reasonable default values.
 * When successful, the function returns false. Otherwise true is returned,
 * and the function already performed a cleanup. */
C_API bool http_init_options(http_ini_t *ctx);

/*
 * The main entry point for the `httpie` server. The function starts all threads and when finished returns the
 * context to the running server for future reference. */
C_API http_ini_t *http_start(const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options);

/*
 * Processes the user supplied options and adds
 * them to the central option list of the context. If en error occurs, the
 * function returns true, otherwise FALSE is returned. In case of an error all
 * cleanup is already done before returning and an error message has been
 * generated. */
bool http_process_options(http_ini_t *ctx, const struct lh_opt_t *options);

/*
 * Sets the global password file option for a context.
 * The function returns false when an error occurs and
 * true when successful. */
bool http_set_gpass_option(http_ini_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _HTTPIE_H_ */
