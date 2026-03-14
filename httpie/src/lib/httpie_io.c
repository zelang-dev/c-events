#include "httpie_internal.h"

/* Return null terminated string `buf` of given maximum length. */
void http_vsnprintf(http_t *conn, bool *truncated, char *buf, size_t buflen, const char *fmt, va_list ap) {
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

void http_snprintf(http_t *conn, bool *truncated, char *buf, size_t buflen, const char *fmt, ...) {
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

void http_error(http_t *conn, int status, const char *fmt, ...) {
	char buf[Kb(8)];
	va_list ap;
	int has_body;
	char date[64];
	time_t curtime;
	const char *status_text;

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
	conn->must_close = true;
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

/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer.
 */
static int alloc_vprintf(char **out_buf, char *prealloc_buf, size_t prealloc_size, const char *fmt, va_list ap) {
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

static int http_vprintf(http_t *conn, const char *fmt, va_list ap) {
	char mem[Kb(8)];
	char *buf;
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

int http_printf(http_t *conn, const char *fmt, ...) {
	va_list ap;
	int result;

	va_start(ap, fmt);
	result = http_vprintf(conn, fmt, ap);
	va_end(ap);

	return result;
}

static int http_read_inner(http_t *conn, void *buffie, size_t len) {
	int64_t n;
	int64_t buffered_len;
	int64_t nread;
	/* since the return value is * int, we may not read more * bytes */
	int64_t len64 = (int64_t)((len > INT_MAX) ? INT_MAX : len);
	const char *body;
	char *buf;

	if (is_empty(conn))
		return 0;

	buf = buffie;
	/*
	 * If Content-Length is not set for a PUT or POST request, read until
	 * socket is closed
	 */
	if (conn->consumed_content == 0 && conn->content_len == -1) {
		conn->content_len = INT64_MAX;
		conn->must_close = true;
	}

	nread = 0;
	if (conn->consumed_content < conn->content_len) {
		/*
		 * Adjust number of bytes to read.
		 */
		int64_t left_to_read = conn->content_len - conn->consumed_content;
		if (left_to_read < len64) {
			/*
			 * Do not read more than the total content length of the request.
			 */
			len64 = left_to_read;
		}

		/*
		 * Return buffered data
		 */
		buffered_len = (int64_t)(conn->data_len) - (int64_t)conn->request_len - conn->consumed_content;
		if (buffered_len > 0) {
			if (len64 < buffered_len)
				buffered_len = len64;

			body = conn->buf + conn->request_len + conn->consumed_content;
			memcpy(buf, body, (size_t)buffered_len);
			len64 -= buffered_len;
			conn->consumed_content += buffered_len;
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

	conn->content_len++;
	if (http_read_inner(conn, &c, 1) <= 0)
		return '\0';

	return c;
}

int http_read(http_t *conn, void *buf, size_t len) {
	if (len > INT_MAX)
		len = INT_MAX;

	if (is_empty(conn))
		return 0;

	if (conn->is_chunked) {
		size_t all_read;
		all_read = 0;
		while (len > 0) {
			/*
			 * No more data left to read
			 */
			if (conn->is_chunked == 2)
				return 0;

			if (conn->chunk_remainder) {
				/* copy from the remainder of the last received chunk */
				long read_ret;
				size_t read_now = ((conn->chunk_remainder > len) ? (len) : (conn->chunk_remainder));
				conn->content_len += (int)read_now;

				read_ret = http_read_inner(conn, (char *)buf + all_read, read_now);
				all_read += (size_t)read_ret;

				conn->chunk_remainder -= read_now;
				len -= read_now;
				if (conn->chunk_remainder == 0) {
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
				char *end;
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
							conn->is_chunked = 2;
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

				conn->chunk_remainder = chunkSize;
			}
		}

		return (int)all_read;
	}

	return http_read_inner(conn, buf, len);
}

bool http_forward_body(http_t *conn, FILE *fp) {
	const char *expect;
	const char *body;
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

	if (conn->content_len == -1 && !conn->is_chunked) {
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

		buffered_len = (int64_t)(conn->data_len) - (int64_t)conn->request_len - conn->consumed_content;
		if (buffered_len < 0 || conn->consumed_content != 0) {
			http_error(conn, 500, "%s", "Error: Size mismatch");
			return false;
		}

		if (buffered_len > 0) {
			if ((int64_t)buffered_len > conn->content_len)
				buffered_len = (int)conn->content_len;

			body = conn->buf + conn->request_len + conn->consumed_content;
			tls_writer(conn->fd, (string)body, (int64_t)buffered_len);
			conn->consumed_content += buffered_len;
		}

		nread = 0;
		while (conn->consumed_content < conn->content_len) {
			to_read = sizeof(buf);
			if ((int64_t)to_read > conn->content_len - conn->consumed_content) to_read = (int)(conn->content_len - conn->consumed_content);

			nread = tls_reader(conn->fd, buf, to_read);
			if (nread <= 0 || tls_writer(conn->fd, buf, nread) != nread) break;
			conn->consumed_content += nread;
		}

		if (conn->consumed_content == conn->content_len)
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
	const char *http_version;
	const char *header;

	if (is_empty(conn)) return false;

	http_version = conn->protocol;
	header = http_get_header(conn, "Connection");

	if (conn->must_close) return false;
	if (conn->status == 401) return false;
	if (!conn->enable_keep_alive) return false;
	if (!is_empty(header) && !http_has_flag(conn, "Connection", "keep-alive")) return false;
	if (is_empty(header) && !str_is_empty(http_version) && str_is(http_version, "1.1")) return false;

	return true;
}

FORCEINLINE const char *http_suggest_connection_header(http_t *conn) {
	return http_should_keep_alive(conn) ? "keep-alive" : "close";
}

void http_options(http_t *conn) {
	char date[64];
	time_t curtime;

	if (is_empty(conn)) return;
	if (is_empty(conn->document_root)) return;

	curtime = time(NULL);
	conn->status = 200;
	conn->must_close = true;

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

void http_logger(enum http_dbg debug_level, http_t *conn, const char *fmt, ...) {
	char buf[Kb(8)];
	char clientbuf[ARRAY_SIZE];
	va_list ap;
	FILE *fi;
	time_t timestamp;

	/*
	 * Check if we have a context. Without a context there is no callback
	 * and also other important information like the path to the error file
	 * is missing. No need to continue if that information cannot be
	 * retrieved.
	 */
	//if (is_empty(conn)) return;

	/*
	 * Check if the message is severe enough to display. This is controlled
	 * with a context specific debug level.
	 */
	if (debug_level > conn->debug_level) return;

	/*
	 * We now try to open the error log file. If this succeeds the error is
	 * appended to the file. On failure there is no way to log the message
	 * without disrupting the user's flow of control so we just return and
	 * logging anything. This is IMHO better than printing to stderr which
	 * may not even be available on all platforms (Windows etc).
	 */
	if (is_empty(conn->error_log_file)) return;

	/*
	 * Gather all the information from the parameters of this function and
	 * create a NULL terminated string buffer with the error message.
	 */
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = 0;

	timestamp = time(NULL);
	if (is_empty(conn))
		snprintf(clientbuf, sizeof(clientbuf), "[%010lu] [error] : ", (unsigned long)timestamp);
	else
		snprintf(clientbuf, sizeof(clientbuf), "[%010lu] [error] [client %s] %s %s: ",
			(unsigned long)timestamp, conn->addr, conn->method, conn->uri);

	if ((fi = fopen(conn->error_log_file, "a+")) != NULL) {
		flockfile(fi);
		fprintf(fi, "%s %s", clientbuf, buf);
		fputc('\n', fi);
		fflush(fi);
		funlockfile(fi);

		fclose(fi);
	}
}

/*
 * Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n
 */
static int http_get_request_len(const char *buf, int buflen) {
	const char *s;
	const char *e;
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

int http_read_request(http_t *conn, char *buf, int bufsiz, int *nread) {
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

bool http_get_request(http_t *conn, int *err) {
	const char *cl;
	uint32_t remote_ip;
	char remote_ip_str[16];

	if (is_empty(err)) return false;

	*err = 0;
	if (is_empty(conn)) {
		http_logger(DEBUG_ERROR, conn, "%s: internal error", __func__);
		*err = 500;
		return false;
	}

	conn->request_len = http_read_request(conn, conn->buf, conn->buf_size, &conn->data_len);
	remote_ip = XX_httplib_get_remote_ip(conn);
	snprintf(remote_ip_str, 16, "%d.%d.%d.%d", (remote_ip >> 24), (remote_ip >> 16) & 0xff, (remote_ip >> 8) & 0xff, remote_ip & 0xff);

	if (conn->request_len >= 0 && conn->data_len < conn->request_len) {
		http_logger(DEBUG_ERROR, conn, "%s: %s invalid request size", __func__, remote_ip_str);
		*err = 500;
		return false;
	}

	if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
		http_logger(DEBUG_ERROR, conn, "%s: %s request too large", __func__, remote_ip_str);
		*err = 413;
		return false;
	} else if (conn->request_len <= 0) {
		if (conn->data_len > 0) {
			http_logger(DEBUG_ERROR, conn, "%s: %s client sent malformed request", __func__, remote_ip_str);
			*err = 400;
		} else {
			/*
			 * Server did not send anything -> just close the connection
			 */
			conn->must_close = true;
			http_logger(DEBUG_WARNING, conn, "%s: %s client did not send a request", __func__, remote_ip_str);
			*err = 0;
		}
		return false;
	} else if (parse_http(HTTP_REQUEST, conn, conn->buf) <= 0) {
		http_logger(DEBUG_ERROR, conn, "%s: %s bad request", __func__, remote_ip_str);
		*err = 400;
		return false;
	} else {
		/*
		 * Message is a valid request or response
		 */
		if ((cl = http_get_header(conn, "Content-Length")) != NULL) {
			/*
			 * Request/response has content length set
			 */
			char *endptr = NULL;
			conn->content_len = strtoll(cl, &endptr, 10);
			if (endptr == cl) {
				http_logger(DEBUG_ERROR, conn, "%s: %s bad request", __func__, remote_ip_str);
				*err = 411;
				return false;
			}
		} else if ((cl = http_get_header(conn, "Transfer-Encoding")) != NULL && str_is(cl, "chunked")) {
			conn->is_chunked = 1;
		} else if (!str_is(conn->method, "POST") || !str_is(conn->method, "PUT")) {
			/*
			 * POST or PUT request without content length set
			 */
			conn->content_len = -1;
		} else if (str_has(conn->protocol, "HTTP/")) {
			/*
			 * Response without content length set
			 */
			conn->content_len = -1;
		} else {
			/*
			 * Other request
			 */
			conn->content_len = 0;
		}
	}

	return true;
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

FORCEINLINE void *http_free_ex(void *memory) {
	if (!is_empty(memory) && is_ptr_usable(memory))
		free(memory);

	return null;
}

void http_free_config_options(http_ini_t *ctx) {
	if (is_empty(ctx))
		return;

	ctx->access_control_allow_origin = http_free_ex(ctx->access_control_allow_origin);
	ctx->access_control_list = http_free_ex(ctx->access_control_list);
	ctx->access_log_file = http_free_ex(ctx->access_log_file);
	ctx->authentication_domain = http_free_ex(ctx->authentication_domain);
	ctx->cgi_environment = http_free_ex(ctx->cgi_environment);
	ctx->cgi_interpreter = http_free_ex(ctx->cgi_interpreter);
	ctx->cgi_pattern = http_free_ex(ctx->cgi_pattern);
	ctx->document_root = http_free_ex(ctx->document_root);
	ctx->error_log_file = http_free_ex(ctx->error_log_file);
	ctx->error_pages = http_free_ex(ctx->error_pages);
	ctx->extra_mime_types = http_free_ex(ctx->extra_mime_types);
	ctx->global_auth_file = http_free_ex(ctx->global_auth_file);
	ctx->hide_file_pattern = http_free_ex(ctx->hide_file_pattern);
	ctx->index_files = http_free_ex(ctx->index_files);
	ctx->listening_ports = http_free_ex(ctx->listening_ports);
	ctx->protect_uri = http_free_ex(ctx->protect_uri);
	ctx->put_delete_auth_file = http_free_ex(ctx->put_delete_auth_file);
	ctx->run_as_user = http_free_ex(ctx->run_as_user);
	ctx->ssi_pattern = http_free_ex(ctx->ssi_pattern);
	ctx->ssl_ca_file = http_free_ex(ctx->ssl_ca_file);
	ctx->ssl_ca_path = http_free_ex(ctx->ssl_ca_path);
	ctx->ssl_certificate = http_free_ex(ctx->ssl_certificate);
	ctx->ssl_cipher_list = http_free_ex(ctx->ssl_cipher_list);
	ctx->throttle = http_free_ex(ctx->throttle);
	ctx->url_rewrite_patterns = http_free_ex(ctx->url_rewrite_patterns);
	ctx->websocket_root = http_free_ex(ctx->websocket_root);
}

bool http_init_options(http_ini_t *ctx) {
	if (ctx == NULL) return true;

	ctx->access_control_allow_origin = NULL;
	ctx->access_control_list = NULL;
	ctx->access_log_file = NULL;
	ctx->allow_sendfile_call = true;
	ctx->authentication_domain = NULL;
	ctx->cgi_environment = NULL;
	ctx->cgi_interpreter = NULL;
	ctx->cgi_pattern = NULL;
	ctx->debug_level = DEBUG_WARNING;
	ctx->decode_url = true;
	ctx->document_root = NULL;
	ctx->enable_directory_listing = true;
	ctx->enable_keep_alive = false;
	ctx->error_log_file = NULL;
	ctx->error_pages = NULL;
	ctx->extra_mime_types = NULL;
	ctx->global_auth_file = NULL;
	ctx->hide_file_pattern = NULL;
	ctx->index_files = NULL;
	ctx->listening_ports = NULL;
	ctx->num_threads = 50;
	ctx->protect_uri = NULL;
	ctx->put_delete_auth_file = NULL;
	ctx->request_timeout = 30000;
	ctx->run_as_user = NULL;
	ctx->ssi_include_depth = 10;
	ctx->ssi_pattern = NULL;
	ctx->ssl_ca_file = NULL;
	ctx->ssl_ca_path = NULL;
	ctx->ssl_certificate = NULL;
	ctx->ssl_cipher_list = NULL;
	ctx->ssl_protocol_version = 0;
	ctx->ssl_short_trust = false;
	ctx->ssl_verify_depth = 9;
	ctx->ssl_verify_paths = true;
	ctx->ssl_verify_peer = false;
	ctx->static_file_max_age = 0;
	ctx->throttle = NULL;
	ctx->tcp_nodelay = false;
	ctx->url_rewrite_patterns = NULL;
	ctx->websocket_root = NULL;
	ctx->websocket_timeout = 30000;

	if ((ctx->access_control_allow_origin = str_dup_ex("*")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"access_control_allow_origin\"");
		return true;
	}

	if ((ctx->authentication_domain = str_dup_ex("example.com")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"authentication_domain\"");
		return true;
	}

	if ((ctx->cgi_pattern = str_dup_ex("**.cgi$|**.pl$|**.php$")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"cgi_pattern\"");
		return true;
	}

	if ((ctx->index_files = str_dup_ex("index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"index_files\"");
		return true;
	}

	if ((ctx->listening_ports = str_dup_ex("8080")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"listening_ports\"");
		return true;
	}

	if ((ctx->ssi_pattern = str_dup_ex("**.shtml$|**.shtm$")) == NULL) {
		http_abort_start(ctx, "Out of memory creating context allocating \"ssi_pattern\"");
		return true;
	}

	return false;
}
