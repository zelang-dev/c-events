#include "httpie_internal.h"

unsigned short sockaddr_in_port(union usa *s) {
	if (s->sa.sa_family == AF_INET)
		return s->sin.sin_port;
#if defined(USE_IPV6)
	if (s->sa.sa_family == AF_INET6)
		return s->sin6.sin6_port;
#endif
	return 0;
}

void sockaddr_to_str(char *buf, size_t len, const union usa *usa) {
	buf[0] = '\0';

	if (!usa) {
		return;
	}

	if (usa->sa.sa_family == AF_INET) {
		getnameinfo(&usa->sa, sizeof(usa->sin), buf, (unsigned)len, NULL, 0, NI_NUMERICHOST);
	} else if (usa->sa.sa_family == AF_INET6) {
		getnameinfo(&usa->sa, sizeof(usa->sin6), buf, (unsigned)len, NULL, 0, NI_NUMERICHOST);
	} else if (usa->sa.sa_family == AF_UNIX) {
		/* TODO: Define a remote address for unix domain sockets.
		* This code will always return "localhost", identical to http+tcp:*/
		getnameinfo(&usa->sa, sizeof(usa->sun), buf, (unsigned)len, NULL, 0, NI_NUMERICHOST);
	}
}

/* Return null terminated string `buf` of given maximum length. */
void http_vsnprintf(http_t *conn, bool *truncated, string buf, size_t buflen, string_t fmt, va_list ap) {
	int n;
	bool ok;

	if (is_empty(buf) || buflen < 1) return;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
/* Using fmt as a non-literal is intended here, since it is mostly called
 * indirectly by http_snprintf */
#endif
	n = (int)vsnprintf(buf, buflen, fmt, ap);
	ok = (n >= 0) && ((size_t)n < buflen);

#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if (ok) {
		if (!is_empty(truncated))
			*truncated = false;
	} else {
		if (!is_empty(truncated))
			*truncated = true;
		n = (int)buflen - 1;
	}
	buf[n] = '\0';
}

void http_snprintf(http_t *conn, bool *truncated, string buf, size_t buflen, string_t fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	http_vsnprintf(conn, truncated, buf, buflen, fmt, ap);
	va_end(ap);
}

FORCEINLINE int http_printf_no_cache(http_t *conn) {
	/*
	 * Send all current and obsolete cache opt-out directives.
	 */
	return http_printf(conn,
		"Cache-Control: no-cache, no-store, "
		"must-revalidate, private, max-age=0\r\n"
		"Pragma: no-cache\r\n"
		"Expires: 0\r\n");
}

void http_error(http_t *conn, int status, string_t fmt, ...) {
	char buf[Kb(8)];
	va_list ap;
	int has_body;
	char date[64];
	time_t curtime;
	string_t status_text;

	if (is_empty(conn)) return;

	curtime = time(NULL);
	status_text = http_status_str(status);

	/*
	* No custom error page. Send default error page.
	*/
	http_gmt_time_str(date, sizeof(date), &curtime);

	/*
	 * Errors 1xx, 204 and 304 MUST NOT send a body
	 */
	has_body = (status > 199 && status != 204 && status != 304);
	conn->req.must_close = true;
	http_printf(conn, "HTTP/1.1 %d %s\r\n", status, status_text);
	http_printf_no_cache(conn);
	if (has_body)
		http_printf(conn, "%s", "Content-Type: text/plain; charset=utf-8\r\n");

	http_printf(conn, "Date: %s\r\n" "Connection: close\r\n\r\n", date);

	/*
	 * Errors 1xx, 204 and 304 MUST NOT send a body
	 */
	if (has_body) {
		http_printf(conn, "Error %d: %s\n", status, status_text);
		if (!is_empty(fmt)) {
			va_start(ap, fmt);
			http_vsnprintf(conn, NULL, buf, sizeof(buf), fmt, ap);
			va_end(ap);
			tls_writer(conn->fd, buf, 0);
		}
	} else {
		/* No body allowed. Close the connection. */
	}
}

static void http_cors_header(http_t *conn) {
	const char *origin_hdr = http_get_header(conn, "Origin");
	const char *cors_orig_cfg =
		conn->ctx->host.config[ACCESS_CONTROL_ALLOW_ORIGIN];
	const char *cors_cred_cfg =
		conn->ctx->host.config[ACCESS_CONTROL_ALLOW_CREDENTIALS];
	const char *cors_hdr_cfg =
		conn->ctx->host.config[ACCESS_CONTROL_ALLOW_HEADERS];
	const char *cors_exphdr_cfg =
		conn->ctx->host.config[ACCESS_CONTROL_EXPOSE_HEADERS];
	const char *cors_meth_cfg =
		conn->ctx->host.config[ACCESS_CONTROL_ALLOW_METHODS];
	const char *cors_repl_asterisk_with_orig_cfg =
		conn->ctx->host.config[REPLACE_ASTERISK_WITH_ORIGIN];

	if (cors_orig_cfg && *cors_orig_cfg && origin_hdr && *origin_hdr
		&& cors_repl_asterisk_with_orig_cfg
		&& *cors_repl_asterisk_with_orig_cfg) {
		int cors_repl_asterisk_with_orig =
			str_is_case(cors_repl_asterisk_with_orig_cfg, "yes");

		/* Cross-origin resource sharing (CORS), see
		 * http://www.html5rocks.com/en/tutorials/cors/,
		 * http://www.html5rocks.com/static/images/cors_server_flowchart.png
		 * CORS preflight is not supported for files. */
		if (cors_repl_asterisk_with_orig && cors_orig_cfg[0] == '*') {
			mg_response_header_add(conn,
				"Access-Control-Allow-Origin",
				origin_hdr,
				-1);
		} else {
			mg_response_header_add(conn,
				"Access-Control-Allow-Origin",
				cors_orig_cfg,
				-1);
		}
	}

	if (cors_cred_cfg && *cors_cred_cfg && origin_hdr && *origin_hdr) {
		/* Cross-origin resource sharing (CORS), see
		 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
		 */
		mg_response_header_add(conn,
			"Access-Control-Allow-Credentials",
			cors_cred_cfg,
			-1);
	}

	if (cors_hdr_cfg && *cors_hdr_cfg) {
		mg_response_header_add(conn,
			"Access-Control-Allow-Headers",
			cors_hdr_cfg,
			-1);
	}

	if (cors_exphdr_cfg && *cors_exphdr_cfg) {
		mg_response_header_add(conn,
			"Access-Control-Expose-Headers",
			cors_exphdr_cfg,
			-1);
	}

	if (cors_meth_cfg && *cors_meth_cfg) {
		mg_response_header_add(conn,
			"Access-Control-Allow-Methods",
			cors_meth_cfg,
			-1);
	}
}

/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer.
 */
static int alloc_vprintf(string *out_buf, string prealloc_buf, size_t prealloc_size, string_t fmt, va_list ap) {
	va_list ap_copy;
	int len;

	va_copy(ap_copy, ap);
	len = vsnprintf(NULL, 0, fmt, ap_copy);
	va_end(ap_copy);
	if ((size_t)(len) >= prealloc_size) {
		/*
		 * The pre-allocated buffer not large enough.
		 * Allocate a new buffer.
		 */
		*out_buf = malloc((size_t)(len)+1);
		if (is_empty(*out_buf)) {
			/*
			 * Allocation failed. Return -1 as "out of memory" error.
			 */
			return -1;
		}

		/*
		 * Buffer allocation successful. Store the string there.
		 */
		va_copy(ap_copy, ap);
		vsnprintf(*out_buf, (size_t)(len)+1, fmt, ap_copy);
		va_end(ap_copy);
	} else {
		/*
		 * The pre-allocated buffer is large enough.
		 * Use it to store the string and return the address.
		 */
		va_copy(ap_copy, ap);
		vsnprintf(prealloc_buf, prealloc_size, fmt, ap_copy);
		va_end(ap_copy);

		*out_buf = prealloc_buf;
	}

	return len;
}

static int http_vprintf(http_t *conn, string_t fmt, va_list ap) {
	char mem[Kb(8)];
	string buf;
	int len;

	buf = NULL;
	if ((len = alloc_vprintf(&buf, mem, sizeof(mem), fmt, ap)) > 0)
		len = tls_writer(conn->fd, buf, (size_t)len);

	if (buf != mem) {
		free(buf);
		buf = NULL;
	}

	return len;

}

int http_printf(http_t *conn, string_t fmt, ...) {
	va_list ap;
	int result;

	va_start(ap, fmt);
	result = http_vprintf(conn, fmt, ap);
	va_end(ap);

	return result;
}

/* Used to construct an etag which can be used to identify a file on a specific moment. */
void http_construct_etag(http_t *ctx, string buf, size_t buf_len, const struct file *filep) {
	if (filep != NULL && buf != NULL && buf_len > 0) {
		http_snprintf(ctx, NULL, buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long)filep->last_modified, filep->size);
	}
}

static int http_read_inner(http_t *conn, void *buffie, size_t len) {
	int64_t n;
	int64_t buffered_len;
	int64_t nread;
	/* since the return value is * int, we may not read more * bytes */
	int64_t len64 = (int64_t)((len > INT_MAX) ? INT_MAX : len);
	string_t body;
	string buf;

	if (is_empty(conn))
		return 0;

	buf = buffie;
	/*
	 * If Content-Length is not set for a PUT or POST request, read until
	 * socket is closed
	 */
	if (conn->req.consumed_content == 0 && conn->req.content_len == -1) {
		conn->req.content_len = INT64_MAX;
		conn->req.must_close = true;
	}

	nread = 0;
	if (conn->req.consumed_content < conn->req.content_len) {
		/*
		 * Adjust number of bytes to read.
		 */
		int64_t left_to_read = conn->req.content_len - conn->req.consumed_content;
		if (left_to_read < len64) {
			/*
			 * Do not read more than the total content length of the request.
			 */
			len64 = left_to_read;
		}

		/*
		 * Return buffered data
		 */
		buffered_len = (int64_t)(conn->req.data_len) - (int64_t)conn->req.request_len - conn->req.consumed_content;
		if (buffered_len > 0) {
			if (len64 < buffered_len)
				buffered_len = len64;

			body = conn->req.buf + conn->req.request_len + conn->req.consumed_content;
			memcpy(buf, body, (size_t)buffered_len);
			len64 -= buffered_len;
			conn->req.consumed_content += buffered_len;
			nread += buffered_len;
			buf += buffered_len;
		}

		/*
		 * We have returned all buffered data. Read new data from the remote
		 * socket.
		 */
		n = tls_reader(conn->fd, buf, (size_t)len64);

		if (n >= 0) nread += n;
		else
			nread = (nread > 0) ? nread : n;
	}

	return (int)nread;
}

static FORCEINLINE char http_getc(http_t *conn) {
	char c;

	if (is_empty(conn))
		return 0;

	conn->req.content_len++;
	if (http_read_inner(conn, &c, 1) <= 0)
		return '\0';

	return c;
}

int http_read(http_t *conn, void_t buf, size_t len) {
	if (len > INT_MAX)
		len = INT_MAX;

	if (is_empty(conn))
		return 0;

	if (conn->req.is_chunked) {
		size_t all_read;
		all_read = 0;
		while (len > 0) {
			/*
			 * No more data left to read
			 */
			if (conn->req.is_chunked == 2)
				return 0;

			if (conn->req.chunk_remainder) {
				/* copy from the remainder of the last received chunk */
				long read_ret;
				size_t read_now = ((conn->req.chunk_remainder > len) ? (len) : (conn->req.chunk_remainder));
				conn->req.content_len += (int)read_now;

				read_ret = http_read_inner(conn, (string)buf + all_read, read_now);
				all_read += (size_t)read_ret;

				conn->req.chunk_remainder -= read_now;
				len -= read_now;
				if (conn->req.chunk_remainder == 0) {
					/*
					 * the rest of the data in the current chunk has been read
					 */
					if (http_getc(conn) != '\r' || http_getc(conn) != '\n') {
						/*
						 * Protocol violation
						 */
						return -1;
					}
				}
			} else {
				/*
				 * fetch a new chunk
				 */
				int i;
				char lenbuf[64];
				string end;
				unsigned long chunkSize;

				i = 0;
				end = NULL;
				chunkSize = 0;
				for (i = 0; i < ((int)sizeof(lenbuf) - 1); i++) {
					lenbuf[i] = http_getc(conn);
					if (i > 0 && lenbuf[i] == '\r' && lenbuf[i - 1] != '\r')
						continue;

					if (i > 1 && lenbuf[i] == '\n' && lenbuf[i - 1] == '\r') {
						lenbuf[i + 1] = 0;
						chunkSize = strtoul(lenbuf, &end, 16);
						/*
						 * regular end of content
						 */
						if (chunkSize == 0)
							conn->req.is_chunked = 2;
						break;
					}

					/*
					 * illegal character for chunk length
					 */
					if (!isalnum(lenbuf[i]))
						return -1;
				}

				/*
				 * chunksize not set correctly
				 */
				if (is_empty(end) || *end != '\r')
					return -1;

				if (chunkSize == 0)
					break;

				conn->req.chunk_remainder = chunkSize;
			}
		}

		return (int)all_read;
	}

	return http_read_inner(conn, buf, len);
}

bool http_forward_body(http_t *conn, FILE *fp) {
	string_t expect;
	string_t body;
	char buf[Kb(8)];
	int to_read;
	int nread;
	bool success;
	int64_t buffered_len;
	double timeout;

	if (is_empty(conn)) return false;

	success = false;
	expect = http_get_header(conn, "Expect");

	if (is_empty(fp)) {
		http_error(conn, 500, "%s", "Error: NULL File");
		return false;
	}

	if (conn->req.content_len == -1 && !conn->req.is_chunked) {
		/*
		 * Content length is not specified by the client.
		 */
		http_error(conn, 411, "%s", "Error: Client did not specify content length");
	} else if (!is_empty(expect) && str_is(expect, "100-continue")) {
		/*
		 * Client sent an "Expect: xyz" header and xyz is not 100-continue.
		 */
		http_error(conn, 417, "Error: Can not fulfill expectation %s", expect);
	} else {
		if (!is_empty(expect)) {
			http_printf(conn, "%s", "HTTP/1.1 100 Continue\r\n\r\n");
			conn->status = 100;
		} else
			conn->status = 200;

		buffered_len = (int64_t)(conn->req.data_len) - (int64_t)conn->req.request_len - conn->req.consumed_content;
		if (buffered_len < 0 || conn->req.consumed_content != 0) {
			http_error(conn, 500, "%s", "Error: Size mismatch");
			return false;
		}

		if (buffered_len > 0) {
			if ((int64_t)buffered_len > conn->req.content_len)
				buffered_len = (int)conn->req.content_len;

			body = conn->req.buf + conn->req.request_len + conn->req.consumed_content;
			tls_writer(conn->fd, (string)body, (int64_t)buffered_len);
			conn->req.consumed_content += buffered_len;
		}

		nread = 0;
		while (conn->req.consumed_content < conn->req.content_len) {
			to_read = sizeof(buf);
			if ((int64_t)to_read > conn->req.content_len - conn->req.consumed_content) to_read = (int)(conn->req.content_len - conn->req.consumed_content);

			nread = tls_reader(conn->fd, buf, to_read);
			if (nread <= 0 || tls_writer(conn->fd, buf, nread) != nread) break;
			conn->req.consumed_content += nread;
		}

		if (conn->req.consumed_content == conn->req.content_len)
			success = (nread >= 0);

		/*
		 * Each error code path in this function must send an error
		 */
		if (!success) {
			/*
			 * NOTE: Maybe some data has already been sent. */
			/* TODO (low): If some data has been sent, a correct error
			 * reply can no longer be sent, so just close the connection
			 */
			http_error(conn, 500, "%s", "");
		}
	}

	return success;
}

bool http_should_keep_alive(http_t *conn) {
	string_t http_version;
	string_t header;

	if (is_empty(conn)) return false;

	http_version = conn->protocol;
	header = http_get_header(conn, "Connection");

	if (conn->req.must_close) return false;
	if (conn->status == 401) return false;
	if (!conn->req.enable_keep_alive) return false;
	if (!is_empty(header) && !http_has_flag(conn, "Connection", "keep-alive")) return false;
	if (is_empty(header) && !str_is_empty(http_version) && str_is(http_version, "1.1")) return false;

	return true;
}

FORCEINLINE string_t http_suggest_connection_header(http_t *conn) {
	return http_should_keep_alive(conn) ? "keep-alive" : "close";
}

void http_options(http_t *conn) {
	char date[64];
	time_t curtime;

	if (is_empty(conn)) return;
	if (is_empty(conn->ctx->document_root)) return;

	curtime = time(NULL);
	conn->status = 200;
	conn->req.must_close = true;

	http_gmt_time_str(date, sizeof(date), &curtime);
	http_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Date: %s\r\n"
		/* TODO: "Cache-Control" (?) */
		"Connection: %s\r\n"
		"Allow: GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS, "
		"PROPFIND, MKCOL\r\n"
		"DAV: 1\r\n\r\n",
		date,
		http_suggest_connection_header(conn));
}

static string_t logger_level_str(enum http_dbg debug_level) {
	string_t level;
	switch (debug_level) {
		case DEBUG_NONE:
			level = " ";
			break;
		case DEBUG_CRASH:
			level = " [FATAL] ";
			break;
		case DEBUG_ERROR:
			level = " [ERROR] ";
			break;
		case DEBUG_WARNING:
			level = " [WARN] ";
			break;
		case DEBUG_INFO:
			level = " [INFO] ";
			break;
		default:
			level = " [unknown] ";
			break;
	}

	return level;
}

void http_logger(enum http_dbg debug_level, http_t *conn, string_t fmt, ...) {
	char buf[Kb(4)] = {0};
	char clientbuf[ARRAY_SIZE] = {0};
	va_list ap;
	FILE *fi;
	time_t timestamp;

	/*
	 * Check if the message is severe enough to display. This is controlled
	 * with a context specific debug level. */
	if (debug_level > conn->ctx->debug_level) return;

	/*
	 * Gather all the information from the parameters of this function and
	 * create a NULL terminated string buffer with the error message. */
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	timestamp = time(NULL);

	/*
	 * We now try to open the error log file. If this succeeds the error is
	 * appended to the file. */
	if (is_empty(conn) || is_empty(conn->ctx->error_log_file)) {
		cerr("[%010lu]%s: %s"CLR_LN, (unsigned long)timestamp, logger_level_str(debug_level), buf);
		return;
	}

	yield_task();
	snprintf(clientbuf, sizeof(clientbuf), "[%010lu]%s[client %s] %s %s: ",
		(unsigned long)timestamp, logger_level_str(debug_level), "conn->remote_addr", conn->method, conn->uri);
	string_t data = str_cat_ex(4, clientbuf, " ", buf, "\n");
	if (!is_empty(data)) {
		async_fprintf((string_t)conn->ctx->error_log_file, "a+", data);
		str_free((void_t)data);
	}
}

/*
 * Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n */
static int http_get_request_len(string_t buf, int buflen) {
	string_t s;
	string_t e;
	int len;

	len = 0;
	s = buf;
	e = s + buflen - 1;
	while (len <= 0 && s < e) {
		/*
		 * Control characters are not allowed but >=128 is.
		 */
		if (!isprint(*(const unsigned char *)s) && *s != '\r' && *s != '\n' && *(const unsigned char *)s < 128)
			return -1;

		if (s[0] == '\n' && s[1] == '\n')
			len = (int)(s - buf) + 2;
		else if (s[0] == '\n' && &s[1] < e && s[1] == '\r' && s[2] == '\n')
			len = (int)(s - buf) + 3;

		s++;
	}

	return len;
}

int http_read_request(http_t *conn, string buf, int bufsiz, int *nread) {
	int request_len;
	int n;

	if (is_empty(conn))
		return 0;

	n = 0;
	request_len = http_get_request_len(buf, *nread);
	while (*nread < bufsiz && request_len == 0 &&
		((n = tls_reader(conn->fd, buf + *nread, bufsiz - *nread)) > 0)) {

		*nread += n;
		if (*nread > bufsiz) return -2;

		request_len = http_get_request_len(buf, *nread);
	}

	return (request_len <= 0 && n <= 0) ? -1 : request_len;
}

FORCEINLINE uint32_t http_get_remote_ip(const http_t *conn) {
	if (conn == NULL)
		return 0;

	return ntohl(*(const uint32_t *)&conn->client.rsa.sin.sin_addr);
}

bool http_get_request(http_ini_t *ctx, http_t *conn, int *err) {
	string_t cl;
	uint32_t remote_ip;
	char remote_ip_str[16];

	if (is_empty(err)) return false;

	*err = 0;
	if (is_empty(conn)) {
		http_logger(DEBUG_ERROR, conn, "%s: internal error", __func__);
		*err = 500;
		return false;
	}

	conn->req.request_len = http_read_request(conn, conn->req.buf, conn->req.buf_size, &conn->req.data_len);
	remote_ip = http_get_remote_ip(conn);
	snprintf(remote_ip_str, 16, "%d.%d.%d.%d", (remote_ip >> 24), (remote_ip >> 16) & 0xff, (remote_ip >> 8) & 0xff, remote_ip & 0xff);

	if (conn->req.request_len >= 0 && conn->req.data_len < conn->req.request_len) {
		http_logger(DEBUG_ERROR, conn, "%s: %s invalid request size", __func__, remote_ip_str);
		*err = 500;
		return false;
	}

	if (conn->req.request_len == 0 && conn->req.data_len == conn->req.buf_size) {
		http_logger(DEBUG_ERROR, conn, "%s: %s request too large",
			__func__, remote_ip_str);
		*err = 413;
		return false;
	} else if (conn->req.request_len <= 0) {
		if (conn->req.data_len > 0) {
			http_logger(DEBUG_ERROR, conn, "%s: %s client sent malformed request",
				__func__, remote_ip_str);
			*err = 400;
		} else {
			/* Server did not send anything -> just close the connection */
			conn->req.must_close = true;
			http_logger(DEBUG_WARNING, conn, "%s: %s client did not send a request",
				__func__, remote_ip_str);
			*err = 0;
		}
		return false;
	} else if (parse_http(HTTP_REQUEST, conn, conn->req.buf) <= 0) {
		http_logger(DEBUG_ERROR, conn, "%s: %s bad request", __func__, remote_ip_str);
		*err = 400;
		return false;
	} else {
		if (!http_switch_domain(conn)) {
			http_logger(DEBUG_ERROR, conn, "%s: Bad request: Host mismatch", __func__);
			*err = 400;
			return false;
		}

		/* Message is a valid request or response */
		if (((cl = http_get_header(conn, "Accept-Encoding")) != NULL)
			&& str_has(cl, "gzip")) {
			conn->req.accept_gzip = 1;
		}

		/* Message is a valid request or response */
		if ((cl = http_get_header(conn, "Content-Length")) != NULL) {
			/* Request/response has content length set */
			string endptr = NULL;
			conn->req.content_len = strtoll(cl, &endptr, 10);
			if (endptr == cl) {
				http_logger(DEBUG_ERROR, conn, "%s: %s bad request", __func__, remote_ip_str);
				*err = 411;
				return false;
			}
		} else if ((cl = http_get_header(conn, "Transfer-Encoding")) != NULL
			&& str_is_case(cl, "chunked")) {
			conn->req.is_chunked = 1;
		} else if (str_is_case(conn->method, "POST") || str_is_case(conn->method, "PUT")) {
			/* POST or PUT request without content length set */
			conn->req.content_len = -1;
		} else if (str_has(conn->protocol, "HTTP/")) {
			/* Response without content length set */
			conn->req.content_len = -1;
		} else {
			/* Other request */
			conn->req.content_len = 0;
		}
	}

	return true;
}

/* Returns true, if a file defined by a specific path is located in memory. */
bool http_is_file_in_memory(http_ini_t *ctx, http_t *conn, string_t path, struct file *filep) {
	size_t size;

	if (ctx == NULL || conn == NULL || filep == NULL)
		return false;

	size = 0;
	if (ctx->callbacks.open_file) {
		filep->membuf = ctx->callbacks.open_file(conn, path, &size);
		/*
		 * NOTE: override filep->size only on success. Otherwise, it might
		 * break constructs like if (!http_stat() || !http_fopen()) ...
		 */
		if (!is_empty(filep->membuf))
			filep->size = size;
	}

	return !is_empty(filep->membuf);
}

int http_stat(http_ini_t *ctx, http_t *conn, string_t path, struct file *filep) {
	struct stat st;

	if (is_empty(filep))
		return 0;

	memset(filep, 0, sizeof(*filep));
	if (!is_empty(conn) && ctx != NULL && http_is_file_in_memory(ctx, conn, path, filep))
		return 1;

	if (fs_stat(path, &st) == 0) {
		filep->size = (uint64_t)(st.st_size);
		filep->last_modified = st.st_mtime;
		filep->is_directory = S_ISDIR(st.st_mode);
		return 1;
	}

	return 0;
}

bool http_is_file_opened(const struct file *filep) {
	return (filep != NULL && (filep->membuf != NULL || filep->fp != NULL));
}

bool http_fopen(http_ini_t *ctx, const http_t *conn, const char *path, const char *mode, struct file *filep) {
	struct stat st;

	if (ctx == NULL || filep == NULL)
		return false;

	memset(filep, 0, sizeof(*filep));
	if (fs_stat(path, &st) == 0)
		filep->size = (uint64_t)st.st_size;

	if (!http_is_file_in_memory(ctx, (http_t *)conn, path, filep)) {
		filep->fp = async_fopen(path, mode);
	}

	return http_is_file_opened(filep);
}

FORCEINLINE bool http_get_random(uint64_t *out) {
	unsigned char buf[sizeof(uint64_t)];
	uint64_t i, value = 0;
	if (is_empty(out) || RAND_bytes(buf, (int)sizeof(buf)) != 1)
		return false;

	for (i = 0; i < (uint64_t)sizeof(uint64_t); i++)
		value = (value << 8) | buf[i];

	*out = value;
	return true;
}

FORCEINLINE void_t http_free_ex(void_t memory) {
	if (!is_empty(memory) && is_ptr_usable(memory))
		free(memory);

	return null;
}

void http_set_handler(http_ini_t *ctx, string_t uri, enum route_type_t handler_type, bool is_delete_request,
	route_cb handler,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	auth_cb auth_handler,
	void_t cbdata) {
	struct http_cb_info *tmp_rh;
	struct http_cb_info **lastref;
	size_t urilen;

	if (uri == NULL)
		return;

	urilen = strlen(uri);
	if (handler_type == WEBSOCKET_HANDLER) {
		if (handler != NULL) return;
		if (!is_delete_request && connect_handler == NULL && ready_handler == NULL && data_handler == NULL && close_handler == NULL) return;
		if (auth_handler != NULL) return;
	} else if (handler_type == REQUEST_HANDLER) {
		if (connect_handler != NULL || ready_handler != NULL || data_handler != NULL || close_handler != NULL) return;
		if (!is_delete_request && handler == NULL) return;
		if (auth_handler != NULL) return;
	} else { /* AUTH_HANDLER */
		if (handler != NULL) return;
		if (connect_handler != NULL || ready_handler != NULL || data_handler != NULL || close_handler != NULL) return;
		if (!is_delete_request && auth_handler == NULL) return;
	}

	if (ctx == NULL)
		return;
	atomic_lock(&ctx->host.nonce_mutex);

	/*
	 * first try to find an existing handler
	 */
	lastref = &ctx->handlers;
	for (tmp_rh = ctx->handlers; tmp_rh != NULL; tmp_rh = tmp_rh->next) {
		if (tmp_rh->handler_type == handler_type) {
			if (urilen == tmp_rh->uri_len && !strcmp(tmp_rh->uri, uri)) {
				if (!is_delete_request) {
					/*
					 * update existing handler
					 */
					if (handler_type == REQUEST_HANDLER) {
						tmp_rh->handler = handler;
					} else if (handler_type == WEBSOCKET_HANDLER) {
						tmp_rh->connect_handler = connect_handler;
						tmp_rh->ready_handler = ready_handler;
						tmp_rh->data_handler = data_handler;
						tmp_rh->close_handler = close_handler;
					} else { /* AUTH_HANDLER */
						tmp_rh->auth_handler = auth_handler;
					}

					tmp_rh->cbdata = cbdata;
				} else {
					/*
					 * remove existing handler
					 */
					*lastref = tmp_rh->next;
					tmp_rh->uri = http_free_ex(tmp_rh->uri);
					tmp_rh = http_free_ex(tmp_rh);
				}

				atomic_unlock(&ctx->host.nonce_mutex);
				return;
			}
		}
		lastref = &tmp_rh->next;
	}

	if (is_delete_request) {
		/*
		 * no handler to set, this was a remove request to a non-existing
		 * handler
		 */
		atomic_unlock(&ctx->host.nonce_mutex);
		return;
	}

	tmp_rh = calloc(sizeof(struct http_cb_info), 1);
	if (tmp_rh == NULL) {
		atomic_unlock(&ctx->host.nonce_mutex);
		http_logger(DEBUG_ERROR, NULL, "%s: cannot create new request handler struct, OOM", __func__);
		return;
	}

	tmp_rh->uri = str_dup_ex(uri);
	if (tmp_rh->uri == NULL) {
		atomic_unlock(&ctx->host.nonce_mutex);
		tmp_rh = http_free_ex(tmp_rh);
		http_logger(DEBUG_ERROR, NULL, "%s: cannot create new request handler struct, OOM", __func__);
		return;
	}

	tmp_rh->uri_len = urilen;
	if (handler_type == REQUEST_HANDLER) {
		tmp_rh->handler = handler;
	} else if (handler_type == WEBSOCKET_HANDLER) {
		tmp_rh->connect_handler = connect_handler;
		tmp_rh->ready_handler = ready_handler;
		tmp_rh->data_handler = data_handler;
		tmp_rh->close_handler = close_handler;
	} else { /* AUTH_HANDLER */
		tmp_rh->auth_handler = auth_handler;
	}
	tmp_rh->cbdata = cbdata;
	tmp_rh->handler_type = handler_type;
	tmp_rh->next = NULL;

	*lastref = tmp_rh;
	atomic_unlock(&ctx->host.nonce_mutex);
}

FORCEINLINE void http_route(http_ini_t *ctx, string_t uri, route_cb handler, void_t cbdata) {
	http_set_handler(ctx, uri, REQUEST_HANDLER, (handler == NULL), handler,
		NULL, NULL, NULL, NULL, NULL, cbdata);
}

FORCEINLINE void http_websocket_route(http_ini_t *ctx, const char *uri,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	void_t cbdata) {
	bool is_delete_request = (connect_handler == NULL) && (ready_handler == NULL)
		&& (data_handler == NULL) && (close_handler == NULL);

	http_set_handler(ctx, uri, WEBSOCKET_HANDLER, is_delete_request, NULL,
		connect_handler, ready_handler, data_handler, close_handler, NULL, cbdata);
}
