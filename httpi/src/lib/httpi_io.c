#include "httpi_internal.h"

static const char alpn_proto_list[] = "\x02h2\x08http/1.1\x08http/1.0";
static string_t alpn_proto_order_http1[] = {alpn_proto_list + 3,
											   alpn_proto_list + 3 + 8,
											   NULL};
static string_t alpn_proto_order_http2[] = {alpn_proto_list,
											   alpn_proto_list + 3,
											   alpn_proto_list + 3 + 8,
											   NULL};

static int _stat_ex(http_t *conn, string_t path, struct file *filep) {
	struct stat st;

	if (is_empty(filep))
		return 0;

	memset(filep, 0, sizeof(*filep));
	if (!is_empty(conn) && conn->ctx != NULL && http_is_file_in_memory(conn->ctx, conn, path, filep))
		return 1;

	if (stat(path, &st) == 0) {
		filep->size = (uint64_t)(st.st_size);
		filep->last_modified = st.st_mtime;
		filep->is_directory = S_ISDIR(st.st_mode);
		return 1;
	}

	return 0;
}

static int print_dir_entry(http_t *conn, struct de *de) {
	size_t namesize, escsize, i;
	char *href, *esc, *p;
	char size[64], mod[64];
	struct tm *tm;

	/* Estimate worst case size for encoding and escaping */
	namesize = strlen(de->file_name) + 1;
	escsize = de->file_name[strcspn(de->file_name, "&<>")] ? namesize * 5 : 0;
	href = (char *)malloc(namesize * 3 + escsize);
	if (href == NULL) {
		return -1;
	}
	http_url_encode(de->file_name, href, namesize * 3);
	esc = NULL;
	if (escsize > 0) {
		/* HTML escaping needed */
		esc = href + namesize * 3;
		for (i = 0, p = esc; de->file_name[i]; i++, p += strlen(p)) {
			str_lcpy(p, de->file_name + i, 2);
			if (*p == '&') {
				strcpy(p, "&amp;");
			} else if (*p == '<') {
				strcpy(p, "&lt;");
			} else if (*p == '>') {
				strcpy(p, "&gt;");
			}
		}
	}

	if (de->file.is_directory) {
		http_snprintf(
			NULL, /* Buffer is big enough */
			size,
			sizeof(size),
			"%s",
			"[DIRECTORY]");
	} else {
		/* We use (signed) cast below because MSVC 6 compiler cannot
		 * convert unsigned __int64 to double. Sigh. */
		if (de->file.size < 1024) {
			http_snprintf(
				NULL, /* Buffer is big enough */
				size,
				sizeof(size),
				"%d",
				(int)de->file.size);
		} else if (de->file.size < 0x100000) {
			http_snprintf(
				NULL, /* Buffer is big enough */
				size,
				sizeof(size),
				"%.1fk",
				(double)de->file.size / 1024.0);
		} else if (de->file.size < 0x40000000) {
			http_snprintf(
				NULL, /* Buffer is big enough */
				size,
				sizeof(size),
				"%.1fM",
				(double)de->file.size / 1048576);
		} else {
			http_snprintf(
				NULL, /* Buffer is big enough */
				size,
				sizeof(size),
				"%.1fG",
				(double)de->file.size / 1073741824);
		}
	}

	/* Note: http_snprintf will not cause a buffer overflow above.
	 * So, string truncation checks are not required here. */
	tm = localtime(&de->file.last_modified);
	if (tm != NULL) {
		strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", tm);
	} else {
		str_lcpy(mod, "01-Jan-1970 00:00", sizeof(mod));
	}
	http_printf(conn,
		"<tr><td><a href=\"%s%s\">%s%s</a></td>"
		"<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
		href,
		de->file.is_directory ? "/" : "",
		esc ? esc : de->file_name,
		de->file.is_directory ? "/" : "",
		mod,
		size);
	free(href);
	return 0;
}


/* This function is called from send_directory() and used for
 * sorting directory entries by size, name, or modification time. */
static int compare_dir_entries(const_t p1, const_t p2, void *arg) {
	string_t query_string = (string_t)(arg != NULL ? arg : "");
	if (p1 && p2) {
		const struct de *a = (const struct de *)p1, *b = (const struct de *)p2;
		int cmp_result = 0;

		if ((query_string == NULL) || (query_string[0] == '\0')) {
			query_string = "n";
		}

		/* Sort Directories vs Files */
		if (a->file.is_directory && !b->file.is_directory) {
			return -1; /* Always put directories on top */
		} else if (!a->file.is_directory && b->file.is_directory) {
			return 1; /* Always put directories on top */
		}

		/* Sort by size or date */
		if (*query_string == 's') {
			cmp_result = (a->file.size == b->file.size)
				? 0
				: ((a->file.size > b->file.size) ? 1 : -1);
		} else if (*query_string == 'd') {
			cmp_result =
				(a->file.last_modified == b->file.last_modified)
				? 0
				: ((a->file.last_modified > b->file.last_modified) ? 1
					: -1);
		}

		/* Sort by name:
		 * if (*query_string == 'n')  ...
		 * but also sort files of same size/date by name as secondary criterion.
		 */
		if (cmp_result == 0) {
			cmp_result = strcmp(a->file_name, b->file_name);
		}

		/* For descending order, invert result */
		return (query_string[1] == 'd') ? -cmp_result : cmp_result;
	}
	return 0;
}

int remove_directory(http_t *conn, string_t dir) {
	char path[UTF8_PATH_MAX];
	struct dirent *dp;
	DIR *dirp;
	struct de de;
	int truncated;
	int ok = 1;

	if ((dirp = opendir(dir)) == NULL) {
		return 0;
	} else {

		while ((dp = readdir(dirp)) != NULL) {
			/* Do not show current dir (but show hidden files as they will
			 * also be removed) */
			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
				continue;
			}

			http_snprintf(&truncated, path, sizeof(path), "%s/%s", dir, dp->d_name);

			/* If we don't memset stat structure to zero, mtime will have
			 * garbage and strftime() will segfault later on in
			 * print_dir_entry(). memset is required only if http_stat()
			 * fails. For more details, see
			 * http://code.google.com/p/mongoose/issues/detail?id=79 */
			memset(&de.file, 0, sizeof(de.file));

			if (truncated) {
				/* Do not delete anything shorter */
				ok = 0;
				continue;
			}

			if (!_stat_ex(conn, path, &de.file)) {
				http_log(DEBUG_ERROR, null,
					"%s: _stat_ex(%s) failed: %s",
					__func__,
					path,
					ex_strerror(os_geterror()));
				ok = 0;
			}

			if (de.file.is_directory) {
				if (remove_directory(conn, path) == 0) {
					ok = 0;
				}
			} else {
				/* This will fail file is the file is in memory */
				if (unlink(path) == 0) {
					ok = 0;
				}
			}
		}
		(void)closedir(dirp);

		(void)(rmdir(dir));
	}

	return ok;
}

int scan_directory(http_t *conn, string_t dir, void *data, int (*cb)(struct de *, void *)) {
	char path[UTF8_PATH_MAX];
	struct dirent *dp;
	DIR *dirp;
	struct de de;
	int truncated;

	if ((dirp = opendir(dir)) == NULL) {
		return 0;
	} else {

		while ((dp = readdir(dirp)) != NULL) {
			/* Do not show current dir and hidden files */
			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")
				|| http_must_hide_file(conn->ctx, dp->d_name)) {
				continue;
			}

			http_snprintf(&truncated, path, sizeof(path), "%s/%s", dir, dp->d_name);

			/* If we don't memset stat structure to zero, mtime will have
			 * garbage and strftime() will segfault later on in
			 * print_dir_entry(). memset is required only if `stat()`
			 * fails. For more details, see
			 * http://code.google.com/p/mongoose/issues/detail?id=79 */
			memset(&de.file, 0, sizeof(de.file));

			if (truncated) {
				/* If the path is not complete, skip processing. */
				continue;
			}

			if (!_stat_ex(conn, path, &de.file)) {
				http_log(DEBUG_ERROR, null,
					"%s: _stat_ex(%s) failed: %s",
					__func__,
					path,
					ex_strerror(os_geterror()));
			}
			de.file_name = dp->d_name;
			if (cb(&de, data)) {
				/* stopped */
				break;
			}
		}
		(void)closedir(dirp);
	}
	return 1;
}

static int dir_scan_callback(struct de *de, void *data) {
	struct dir_scan_data *dsd = (struct dir_scan_data *)data;
	struct de *entries = dsd->entries;

	if ((entries == NULL) || (dsd->num_entries >= dsd->arr_size)) {
		/* Here "entries" is a temporary pointer and can be replaced,
		 * "dsd->entries" is the original pointer */
		entries =
			(struct de *)realloc(entries,
				dsd->arr_size * 2 * sizeof(entries[0]));
		if (entries == NULL) {
			/* stop scan */
			return 1;
		}
		dsd->entries = entries;
		dsd->arr_size *= 2;
	}

	entries[dsd->num_entries].file_name = str_dup_ex(de->file_name);
	if (entries[dsd->num_entries].file_name == NULL) {
		/* stop scan */
		return 1;
	}

	entries[dsd->num_entries].file = de->file;
	dsd->num_entries++;

	return 0;
}

static FORCEINLINE void *_scan_directory(param_t args) {
	return casting(scan_directory((http_t *)args[0].object, args[1].const_char_ptr, args[2].object, (int (*)(struct de *, void *))args[3].func));
}

int fs_scan_directory(http_t *conn, string_t dir, void *data, int (*cb)(struct de *, void *)) {
	return queue_get(queue_work(futures_pool(), _scan_directory, 4, conn, dir, data, cb)).integer;
}

void handle_directory_request(http_t *conn, string_t dir) {
	size_t i;
	int sort_direction;
	struct dir_scan_data data = {NULL, 0, 128};
	char date[64], *esc, *p;
	string_t title;
	time_t curtime = time(NULL);

	if (!conn) {
		return;
	}

	if (!fs_scan_directory(conn, dir, &data, dir_scan_callback)) {
		http_error(conn, 500, "Error: Cannot open directory\nopendir(%s): %s", dir, ex_strerror(os_geterror()));
		return;
	}

	http_gmt_time_str(date, sizeof(date), &curtime);

	esc = NULL;
	title = conn->req.local_uri;
	if (title[strcspn(title, "&<>")]) {
		/* HTML escaping needed */
		esc = (char *)malloc(strlen(title) * 5 + 1);
		if (esc) {
			for (i = 0, p = esc; title[i]; i++, p += strlen(p)) {
				str_lcpy(p, title + i, 2);
				if (*p == '&') {
					strcpy(p, "&amp;");
				} else if (*p == '<') {
					strcpy(p, "&lt;");
				} else if (*p == '>') {
					strcpy(p, "&gt;");
				}
			}
		} else {
			title = "";
		}
	}

	sort_direction = ((conn->req.query_string != NULL)
		&& (conn->req.query_string[0] != '\0')
		&& (conn->req.query_string[1] == 'd'))
		? 'a'
		: 'd';

	conn->req.must_close = 1;

	/* Create 200 OK response */
	http_response_start(conn, 200);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn, "Content-Type", "text/html; charset=utf-8", -1);

	/* Send all headers */
	http_response_send(conn);

	/* Body */
	http_printf(conn,
		"<!DOCTYPE html>"
		"<html><head><title>Index of %s</title>"
		"<style>th {text-align: left;}</style></head>"
		"<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
		"<tr><th><a href=\"?n%c\">Name</a></th>"
		"<th><a href=\"?d%c\">Modified</a></th>"
		"<th><a href=\"?s%c\">Size</a></th></tr>"
		"<tr><td colspan=\"3\"><hr></td></tr>",
		esc ? esc : title,
		esc ? esc : title,
		sort_direction,
		sort_direction,
		sort_direction);
	free(esc);

	/* Print first entry - link to a parent directory */
	http_printf(conn,
		"<tr><td><a href=\"%s\">%s</a></td>"
		"<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
		"..",
		"Parent directory",
		"-",
		"-");

/* Sort and print directory entries */
	if (data.entries != NULL) {
		memsort(data.entries,
			data.num_entries,
			sizeof(data.entries[0]),
			compare_dir_entries,
			(void *)conn->req.query_string);
		for (i = 0; i < data.num_entries; i++) {
			print_dir_entry(conn, &data.entries[i]);
			free(data.entries[i].file_name);
		}
		free(data.entries);
	}

	http_printf(conn, "%s", "</table></pre></body></html>");
	conn->status = 200;
}

unsigned short sockaddr_in_port(u_saddr_t *s) {
	if (s->sa.sa_family == AF_INET)
		return s->sin.sin_port;
	else if (s->sa.sa_family == AF_INET6)
		return s->sin6.sin6_port;

	return 0;
}

static int http_error_send(http_t *conn, int status, string_t fmt, va_list args) {
	char errmsg_buf[BUF_LEN];
	va_list ap;
	int has_body;
	char path_buf[UTF8_PATH_MAX];
	int len, i, page_handler_found, scope, truncated;
	string_t error_handler = NULL;
	struct file error_page_file = STRUCT_FILE_INITIALIZER;
	string_t error_page_file_ext, tstr;
	int handled_by_callback = 0;

	if ((conn == NULL) || (fmt == NULL)) {
		return -2;
	}

	/* Set status (for log) */
	conn->status = status;

	/* Errors 1xx, 204 and 304 MUST NOT send a body */
	has_body = ((status > 199) && (status != 204) && (status != 304));

	/* Prepare message in buf, if required */
	if (has_body
		|| (!conn->req.in_error_handler
			&& (conn->ctx->callbacks.http_error != NULL))) {
		/* Store error message in errmsg_buf */
		va_copy(ap, args);
		http_vsnprintf(NULL, errmsg_buf, sizeof(errmsg_buf), fmt, ap);
		va_end(ap);
		/* In a debug build, print all html errors */
		debug_info("Error %i - [%s]"CLR_LN, status, errmsg_buf);
	}

	/* If there is a http_error callback, call it.
	 * But don't do it recursively, if callback calls `http_error()` again.
	 */
	if (!conn->req.in_error_handler
		&& (conn->ctx->callbacks.http_error != NULL)) {
		/* Mark in_error_handler to avoid recursion and call user callback. */
		conn->req.in_error_handler = 1;
		handled_by_callback =
			(conn->ctx->callbacks.http_error(conn, status)	== 0);
		conn->req.in_error_handler = 0;
	}

	if (!handled_by_callback) {
		/* Check for recursion */
		if (conn->req.in_error_handler) {
			debug_info("Recursion when handling error %u - fall back to default"CLR_LN, status);
		} else {
			/* Send user defined error pages, if defined */
			error_handler = conn->domain->config[ERROR_PAGES];
			error_page_file_ext = conn->domain->config[INDEX_FILES];
			page_handler_found = 0;

			if (error_handler != NULL) {
				for (scope = 1; (scope <= 3) && !page_handler_found; scope++) {
					switch (scope) {
						case 1: /* Handler for specific error, e.g. 404 error */
							http_snprintf(
								&truncated,
								path_buf,
								sizeof(path_buf) - 32,
								"%serror%03u.",
								error_handler,
								status);
							break;
						case 2: /* Handler for error group, e.g., 5xx error
								 * handler
								 * for all server errors (500-599) */
							http_snprintf(
								&truncated,
								path_buf,
								sizeof(path_buf) - 32,
								"%serror%01uxx.",
								error_handler,
								status / 100);
							break;
						default: /* Handler for all errors */
							http_snprintf(
								&truncated,
								path_buf,
								sizeof(path_buf) - 32,
								"%serror.",
								error_handler);
							break;
					}

					/* String truncation in buf may only occur if
					 * error_handler is too long. This string is
					 * from the config, not from a client. */
					(void)truncated;

					/* The following code is redundant, but it should avoid
					 * false positives in static source code analyzers and
					 * vulnerability scanners.
					 */
					path_buf[sizeof(path_buf) - 32] = 0;
					len = (int)strlen(path_buf);
					if (len > (int)sizeof(path_buf) - 32) {
						len = (int)sizeof(path_buf) - 32;
					}

					/* Start with the file extension from the configuration. */
					tstr = strchr(error_page_file_ext, '.');

					while (tstr) {
						for (i = 1;
							(i < 32) && (tstr[i] != 0) && (tstr[i] != ',');
							i++) {
						   /* buffer overrun is not possible here, since
							* (i < 32) && (len < sizeof(path_buf) - 32)
							* ==> (i + len) < sizeof(path_buf) */
							path_buf[len + i - 1] = tstr[i];
						}
						/* buffer overrun is not possible here, since
						 * (i <= 32) && (len < sizeof(path_buf) - 32)
						 * ==> (i + len) <= sizeof(path_buf) */
						path_buf[len + i - 1] = 0;

						if (http_stat(conn, path_buf, &error_page_file)) {
							debug_info("Check error page %s - found"CLR_LN, path_buf);
							page_handler_found = 1;
							break;
						}
						debug_info("Check error page %s - not found"CLR_LN, path_buf);

						/* Continue with the next file extension from the
						 * configuration (if there is a next one). */
						tstr = strchr(tstr + i, '.');
					}
				}
			}

			if (page_handler_found) {
				conn->req.in_error_handler = 1;
				handle_file_based_request(conn, path_buf, &error_page_file);
				conn->req.in_error_handler = 0;
				return 0;
			}
		}

		/* No custom error page. Send default error page. */
		conn->req.must_close = 1;
		http_response_start(conn, status);
		http_no_cache_header(conn);
		http_domain_header(conn);
		http_cors_header(conn);
		if (has_body) {
			http_response_add(conn,
				"Content-Type",
				"text/plain; charset=utf-8",
				-1);
		}
		http_response_send(conn);

		/* HTTP responses 1xx, 204 and 304 MUST NOT send a body */
		if (has_body) {
			/* For other errors, send a generic error message. */
			string_t status_text = http_status_str(status);
			http_printf(conn, "Error %d: %s\n", status, status_text);
			http_write(conn, errmsg_buf, strlen(errmsg_buf));

		} else {
			/* No body allowed. Close the connection. */
			debug_info("Error %i"CLR_LN, status);
		}
	}
	return 0;
}


int http_error(http_t *conn, int status, string_t fmt, ...) {
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = http_error_send(conn, status, fmt, ap);
	va_end(ap);

	return ret;
}

void http_domain_header(http_t *conn) {
	string_t header = conn->domain->config[ADDITIONAL_HEADER];

	if (conn->domain->config[STRICT_HTTPS_MAX_AGE]) {
		long max_age = atol(conn->domain->config[STRICT_HTTPS_MAX_AGE]);
		if (max_age >= 0) {
			char val[64];
			http_snprintf(
				NULL,
				val,
				sizeof(val),
				"max-age=%lu",
				(unsigned long)max_age);
			http_response_add(conn, "Strict-Transport-Security", val, -1);
		}
	}

	// Content-Security-Policy
	if (header && header[0]) {
		http_response_multi(conn, (string)header);
	}
}

void http_cors_header(http_t *conn) {
	string_t origin_hdr = http_get_header(conn, "Origin");
	string_t cors_orig_cfg =
		conn->domain->config[ACCESS_CONTROL_ALLOW_ORIGIN];
	string_t cors_cred_cfg =
		conn->domain->config[ACCESS_CONTROL_ALLOW_CREDENTIALS];
	string_t cors_hdr_cfg =
		conn->domain->config[ACCESS_CONTROL_ALLOW_HEADERS];
	string_t cors_exphdr_cfg =
		conn->domain->config[ACCESS_CONTROL_EXPOSE_HEADERS];
	string_t cors_meth_cfg =
		conn->domain->config[ACCESS_CONTROL_ALLOW_METHODS];
	string_t cors_repl_asterisk_with_orig_cfg =
		conn->domain->config[REPLACE_ASTERISK_WITH_ORIGIN];

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
			http_response_add(conn,
				"Access-Control-Allow-Origin",
				origin_hdr,
				-1);
		} else {
			http_response_add(conn,
				"Access-Control-Allow-Origin",
				cors_orig_cfg,
				-1);
		}
	}

	if (cors_cred_cfg && *cors_cred_cfg && origin_hdr && *origin_hdr) {
		/* Cross-origin resource sharing (CORS), see
		 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
		 */
		http_response_add(conn,
			"Access-Control-Allow-Credentials",
			cors_cred_cfg,
			-1);
	}

	if (cors_hdr_cfg && *cors_hdr_cfg) {
		http_response_add(conn,
			"Access-Control-Allow-Headers",
			cors_hdr_cfg,
			-1);
	}

	if (cors_exphdr_cfg && *cors_exphdr_cfg) {
		http_response_add(conn,
			"Access-Control-Expose-Headers",
			cors_exphdr_cfg,
			-1);
	}

	if (cors_meth_cfg && *cors_meth_cfg) {
		http_response_add(conn,
			"Access-Control-Allow-Methods",
			cors_meth_cfg,
			-1);
	}
}

static int http_vprintf(http_t *conn, string_t fmt, va_list ap) {
	char mem[Kb(8)];
	string buf;
	int len;

	buf = NULL;
	if ((len = alloc_vprintf(&buf, mem, sizeof(mem), fmt, ap)) > 0)
		len = http_write(conn, (const_t)buf, (size_t)len);

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

void http_construct_etag(http_t *ctx, string buf, size_t buf_len, const struct file *filep) {
	(void)ctx;
	if (filep != NULL && buf != NULL && buf_len > 0) {
		http_snprintf(NULL, buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long)filep->last_modified, filep->size);
	}
}

string_t http_fgets(char *buf, size_t size, struct file *filep, char **p) {
	string_t eof;
	size_t len;
	string_t memend;

	if (filep == NULL)
		return NULL;

	if (filep->membuf != NULL && *p != NULL) {
		memend = (string_t)&filep->membuf[filep->size];
		/* Search for \n from p till the end of stream */
		eof = (char *)memchr(*p, '\n', (size_t)(memend - *p));

		if (eof != NULL)
			eof += 1;		/* Include \n */
		else
			eof = memend;	/* Copy remaining data */

		len = ((size_t)(eof - *p) > (size - 1)) ? (size - 1) : (size_t)(eof - *p);
		memcpy(buf, *p, len);
		buf[len] = '\0';
		*p += len;

		return (len) ? eof : NULL;
	}

	if (filep->fp != NULL)
		return promise_fgets(filep->pf, buf, (int)size, filep->fp);

	return NULL;
}

void discard_unread_request_data(http_t *conn) {
	char buf[BUF_LEN];

	while (http_read(conn, buf, sizeof(buf)) > 0)
		;
}

static FORCEINLINE int _read_all(http_t *conn, char *buf, int len) {
	int n, nread = 0;
	while ((len > 0) && conn->ctx->status == HTTP_STATUS_RUNNING) {
		n = tls_reader(socket2fd(conn->client->sock), buf + nread, len);
		if (n < 0) {
			if (nread == 0)
				nread = n; /* Propagate the error */
			break;
		} else if (n == 0) {
			break; /* No more data to read */
		} else {
			conn->req.consumed_content += n;
			nread += n;
			len -= n;
		}
	}

	return nread;
}

int _read_inner(http_t *conn, void *buf, size_t len) {
	int64_t content_len, n, buffered_len, nread;
	int64_t len64 =
		(int64_t)((len > INT_MAX) ? INT_MAX : len); /* since the return value is
													 * int, we may not read more
													 * bytes */
	string_t body;

	if (conn == NULL) {
		return 0;
	}

	/* If Content-Length is not set for a response with body data,
	 * we do not know in advance how much data should be read. */
	content_len = conn->req.content_len;
	if (content_len < 0) {
		/* The body data is completed when the connection is closed. */
		content_len = INT64_MAX;
	}

	nread = 0;
	if (conn->req.consumed_content < content_len) {
		/* Adjust number of bytes to read. */
		int64_t left_to_read = content_len - conn->req.consumed_content;
		if (left_to_read < len64) {
			/* Do not read more than the total content length of the
			 * request.
			 */
			len64 = left_to_read;
		}

		/* Return buffered data */
		buffered_len = (int64_t)(conn->req.data_len) - (int64_t)conn->req.request_len
			- conn->req.consumed_content;
		if (buffered_len > 0) {
			if (len64 < buffered_len) {
				buffered_len = len64;
			}
			body = conn->req.buf + conn->req.request_len + conn->req.consumed_content;
			memcpy(buf, body, (size_t)buffered_len);
			len64 -= buffered_len;
			conn->req.consumed_content += buffered_len;
			nread += buffered_len;
			buf = (char *)buf + buffered_len;
		}

		/* We have returned all buffered data. Read new data from the remote socket. */
		if ((n = _read_all(conn, (char *)buf, len64)) >= 0) {
			nread += n;
		} else {
			nread = ((nread > 0) ? nread : n);
		}
	}
	return (int)nread;
}

static char http_getc(http_t *conn) {
	char c;
	if (conn == NULL) {
		return 0;
	}
	conn->req.content_len++;
	if (_read_inner(conn, &c, 1) <= 0) {
		return (char)0;
	}
	return c;
}

int http_read(http_t *conn, void_t buf, size_t len) {
	if (len > INT_MAX) {
		len = INT_MAX;
	}

	if (conn == NULL) {
		return 0;
	}

	if (conn->req.is_chunked) {
		size_t all_read = 0;

		while (len > 0) {
			if (conn->req.is_chunked == 2) {
				/* No more data left to read */
				return 0;
			}

			if (conn->req.is_chunked == 3) {
				/* Has error */
				return -1;
			}

			if (conn->req.chunk_remainder) {
				/* copy from the remainder of the last received chunk */
				long read_ret;
				size_t read_now =
					((conn->req.chunk_remainder > len) ? (len)
						: (conn->req.chunk_remainder));

				conn->req.content_len += (int)read_now;
				read_ret = _read_inner(conn, (char *)buf + all_read, read_now);
				if (read_ret < 1) {
					/* read error */
					conn->req.is_chunked = 3;
					return -1;
				}

				all_read += (size_t)read_ret;
				conn->req.chunk_remainder -= (size_t)read_ret;
				len -= (size_t)read_ret;
				if (conn->req.chunk_remainder == 0) {
					/* Add data bytes in the current chunk have been read,
					 * so we are expecting \r\n now. */
					char x1 = http_getc(conn);
					char x2 = http_getc(conn);
					if ((x1 != '\r') || (x2 != '\n')) {
						/* Protocol violation */
						conn->req.is_chunked = 3;
						return -1;
					}
				}
			} else {
				/* fetch a new chunk */
				int i = 0;
				char lenbuf[64];
				char *end = 0;
				unsigned long chunkSize = 0;

				for (i = 0; i < ((int)sizeof(lenbuf) - 1); i++) {
					lenbuf[i] = http_getc(conn);
					if (i > 0 && lenbuf[i] == '\r' && lenbuf[i - 1] != '\r') {
						continue;
					}
					if (i > 1 && lenbuf[i] == '\n' && lenbuf[i - 1] == '\r') {
						lenbuf[i + 1] = 0;
						chunkSize = strtoul(lenbuf, &end, 16);
						if (chunkSize == 0) {
							/* regular end of content */
							conn->req.is_chunked = 2;
						}
						break;
					}
					if (!isxdigit(lenbuf[i])) {
						/* illegal character for chunk length */
						conn->req.is_chunked = 3;
						return -1;
					}
				}
				if ((end == NULL) || (*end != '\r')) {
					/* chunksize not set correctly */
					conn->req.is_chunked = 3;
					return -1;
				}
				if (chunkSize == 0) {
					break;
				}

				conn->req.chunk_remainder = chunkSize;
			}
		}

		return (int)all_read;
	}
	return _read_inner(conn, buf, len);
}

int http_chunk_state(http_t *conn) {
	return is_type((void_t)conn, (data_types)DATA_HTTPINFO) ? conn->req.is_chunked : false;
}

int http_chunk(http_t *conn, string_t chunk, unsigned int chunk_len) {
	char lenbuf[16];
	size_t lenbuf_len;
	int ret;
	int t;

	/* First store the length information in a text buffer. */
	sprintf(lenbuf, "%x\r\n", chunk_len);
	lenbuf_len = strlen(lenbuf);

	/* Then send length information, chunk and terminating \r\n. */
	ret = http_write(conn, lenbuf, lenbuf_len);
	if (ret != (int)lenbuf_len) {
		return -1;
	}
	t = ret;

	ret = http_write(conn, chunk, chunk_len);
	if (ret != (int)chunk_len) {
		return -1;
	}
	t += ret;

	ret = http_write(conn, "\r\n", 2);
	if (ret != 2) {
		return -1;
	}
	t += ret;

	return t;
}

FORCEINLINE int64_t _write_all(http_t *conn, string buf, int64_t len) {
	int64_t n;
	int64_t nwritten;

	if (conn == NULL)
		return -1;

	nwritten = 0;
	while (len > 0 && conn->ctx->status == HTTP_STATUS_RUNNING) {
		n = tls_writer(socket2fd(conn->client->sock), buf + nwritten, len);
		if (n < 0) {
			if (nwritten == 0) {
				nwritten = -1; /* Propagate the error */
			}
			break;
		} else if (n == 0) {
			break; /* No more data to write */
		} else {
			nwritten += n;
			len -= n;
		}
	}

	return nwritten;
}

int http_write(http_t *conn, const_t buf, size_t len) {
	int n = 0, allowed = 0, total = 0;
	time_t now = 0;
	if (conn == NULL) {
		return 0;
	}

	if (len > INT_MAX) {
		return -1;
	}

	/* Mark connection as "data sent" */
	conn->req.state = 10;
	if (conn->req.proto == PROTOCOL_HTTP2) {
	//	http2_data_frame_head(conn, len, 0);
	}

	if (conn->req.throttle > 0) {
		if ((now = time(NULL)) != conn->req.last_throttle_time) {
			conn->req.last_throttle_time = now;
			conn->req.last_throttle_bytes = 0;
		}

		allowed = conn->req.throttle - conn->req.last_throttle_bytes;
		if (allowed > (int64_t)len) {
			allowed = (int64_t)len;
		}

		if ((total = _write_all(conn, (string)buf, (int64_t)allowed)) == allowed) {
			buf = (string)buf + total;
			conn->req.last_throttle_bytes += total;
			while (total < (int64_t)len && conn->ctx->status == HTTP_STATUS_RUNNING) {
				allowed = (conn->req.throttle > ((int64_t)len - total))
					? (int64_t)len - total
					: conn->req.throttle;
				if ((n = _write_all(conn, (string)buf, (int64_t)allowed)) != allowed) {
					break;
				}

				delay(1000);
				conn->req.last_throttle_bytes = allowed;
				conn->req.last_throttle_time = time(NULL);
				buf = (string)buf + n;
				total += n;
			}
		}
	} else {
		total = _write_all(conn, (string)buf, len);
	}

	if (total > 0) {
		conn->req.num_bytes_sent += total;
	}

	return total;
}

int http_file_body(http_t *conn, string_t path) {
	struct file file = STRUCT_FILE_INITIALIZER;
	if (!http_fopen(conn->ctx, conn, path, "rb", &file)) {
		return -1;
	}

	http_set_close_on_exec(fd2socket(fileno(file.fp)));
	http_send_file_data(conn, &file, 0, INT64_MAX, 0); /* send static file */
	(void)http_fclose(&file); /* Ignore errors for readonly files */
	return 0;                      /* >= 0 for OK */
}

int http_ok(http_t *conn, string_t mime_type, long long content_length) {
	if ((mime_type == NULL) || (*mime_type == 0)) {
		/* No content type defined: default to text/html */
		mime_type = "text/html";
	}

	http_response_start(conn, 200);
	http_no_cache_header(conn);
	http_domain_header(conn);
	http_cors_header(conn);
	http_response_add(conn, "Content-Type", mime_type, -1);
	if (content_length < 0) {
		/* Size not known. Use chunked encoding (HTTP/1.x) */
		if (conn->req.proto == PROTOCOL_HTTP1) {
			/* Only HTTP/1.x defines "chunked" encoding, HTTP/2 does not*/
			http_response_add(conn, "Transfer-Encoding", "chunked", -1);
		}
	} else {
		char len[32];
		int trunc = 0;
		http_snprintf(
			&trunc,
			len,
			sizeof(len),
			"%" UINT64_FMT,
			(uint64_t)content_length);
		if (!trunc) {
			/* Since 32 bytes is enough to hold any 64 bit decimal number,
			 * !trunc is always true */
			http_response_add(conn, "Content-Length", len, -1);
		}
	}

	http_response_send(conn);
	return 0;
}

int http_redirect(http_t *conn, string_t target_url, int redirect_code) {
	/* In case redirect_code=0, use 307. */
	if (redirect_code == 0) {
		redirect_code = 307;
	}

	/* In case redirect_code is none of the above, return error. */
	if ((redirect_code != 301) && (redirect_code != 302)
		&& (redirect_code != 303) && (redirect_code != 307)
		&& (redirect_code != 308)) {
		/* Parameter error */
		return -2;
	}

	/* If target_url is not defined, redirect to "/". */
	if ((target_url == NULL) || (*target_url == 0)) {
		target_url = "/";
	}

	/* Send all required headers */
	http_response_start(conn, redirect_code);
	http_response_add(conn, "Location", target_url, -1);
	if ((redirect_code == 301) || (redirect_code == 308)) {
		/* Permanent redirect */
		http_static_cache_header(conn);
	} else {
		/* Temporary redirect */
		http_no_cache_header(conn);
	}

	http_domain_header(conn);
	http_cors_header(conn);
	http_response_add(conn, "Content-Length", "0", 1);
	http_response_send(conn);
	return 1;
}

void http_no_cache_header(http_t *conn) {
	http_response_add(conn,
		"Cache-Control",
		"no-cache, no-store, "
		"must-revalidate, private, max-age=0",
		-1);
	http_response_add(conn, "Expires", "0", -1);

	if (conn->req.proto == PROTOCOL_HTTP1) {
		/* Obsolete, but still send it for HTTP/1.0 */
		http_response_add(conn, "Pragma", "no-cache", -1);
	}
}

 void http_static_cache_header(http_t *conn) {
	int max_age;
	char val[64];
	string_t cache_control =
		conn->domain->config[STATIC_FILE_CACHE_CONTROL];

	/* If there is a full cache-control option configured,0 use it */
	if (cache_control != NULL) {
		http_response_add(conn, "Cache-Control", cache_control, -1);
		return;
	}

	/* Read the server config to check how long a file may be cached.
	 * The configuration is in seconds. */
	max_age = atoi(conn->domain->config[STATIC_FILE_MAX_AGE]);
	if (max_age <= 0) {
		/* 0 means "do not cache". All values <0 are reserved
		 * and may be used differently in the future. */
		/* If a file should not be cached, do not only send
		 * max-age=0, but also pragmas and Expires headers. */
		http_no_cache_header(conn);
		return;
	}

	/* Use "Cache-Control: max-age" instead of "Expires" header.
	 * Reason: see https://www.mnot.net/blog/2007/05/15/expires_max-age */
	/* See also https://www.mnot.net/cache_docs/ */
	/* According to RFC 2616, Section 14.21, caching times should not exceed
	 * one year. A year with 365 days corresponds to 31536000 seconds, a
	 * leap
	 * year to 31622400 seconds. For the moment, we just send whatever has
	 * been configured, still the behavior for >1 year should be considered
	 * as undefined. */
	http_snprintf(NULL, val, sizeof(val), "max-age=%lu", (unsigned long)max_age);
	http_response_add(conn, "Cache-Control", val, -1);
}

int should_keep_alive(http_t *conn) {
	if (conn != NULL) {
		string_t http_version = conn->req.http_version;
		string_t header = http_get_header(conn, "Connection");
		if (conn->req.must_close || conn->code == 401 ||
			!str_is_case(conn->ctx->host.config[ENABLE_KEEP_ALIVE], "yes") ||
			(header != NULL && !str_is_case(header, "keep-alive") != 0) ||
			(header == NULL && http_version &&
				0 != strcmp(http_version, "1.1"))) {
			return 0;
		}

		return 1;
	}

	return 0;
}

FORCEINLINE string_t http_suggest_connection_header(http_t *conn) {
	return should_keep_alive(conn) ? "keep-alive" : "close";
}

void http_options(http_t *conn) {
	if (is_empty(conn))
		return;

	/* We do not set a "Cache-Control" header here, but leave the default.
	 * Since browsers do not send an OPTIONS request, we can not test the
	 * effect anyway. */

	http_response_start(conn, 200);
	http_response_add(conn, "Content-Type", "text/html", -1);

	if (conn->req.proto == PROTOCOL_HTTP1) {
		/* Use the same as before */
		http_response_add(conn, "Allow",
			"GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS, PROPFIND, MKCOL", -1);
		http_response_add(conn, "DAV", "1", -1);
	} else {
		/* TODO: Check this later for HTTP/2 */
		http_response_add(conn, "Allow", "GET, POST", -1);
	}
	http_domain_header(conn);
	http_response_send(conn);
}

static string_t log_level_str(enum http_dbg debug_level) {
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

void http_log(enum http_dbg debug_level, http_t *conn, string_t fmt, ...) {
	char buf[Kb(4)] = {0};
	char clientbuf[ARRAY_SIZE] = {0};
	va_list ap;
	FILE *fi;
	time_t timestamp;

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
	if (is_empty(conn)
		|| ((!is_empty(conn->ctx->callbacks.log_message) && conn->ctx->callbacks.log_message(conn, buf) == 0)
			|| is_empty(conn->ctx->error_log_file))) {
		cerr("[%010lu]%s: %s"CLR_LN, (unsigned long)timestamp, log_level_str(debug_level), buf);
		return;
	}

	snprintf(clientbuf, sizeof(clientbuf), "[%010lu]%s[client %s] %s %s: ",
		(unsigned long)timestamp, log_level_str(debug_level), conn->req.remote_addr, conn->method, conn->uri);
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
int get_http_header_len(string_t buf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		/* Do an unsigned comparison in some conditions below */
		const unsigned char c = (unsigned char)buf[i];

		if ((c < 128) && ((char)c != '\r') && ((char)c != '\n')
			&& !isprint(c)) {
			/* abort scan as soon as one malformed character is found */
			return -1;
		}

		if (i < buflen - 1) {
			if ((buf[i] == '\n') && (buf[i + 1] == '\n')) {
				/* Two newline, no carriage return - not standard compliant,
				 * but it should be accepted */
				return i + 2;
			}
		}

		if (i < buflen - 3) {
			if ((buf[i] == '\r') && (buf[i + 1] == '\n') && (buf[i + 2] == '\r')
				&& (buf[i + 3] == '\n')) {
				/* Two \r\n - standard compliant */
				return i + 4;
			}
		}
	}

	return 0;
}

string http_read_until(http_t *conn, int *size) {
	char buf[Kb(4)], *data = NULL;
	int len = 0;
	*size = 0;
	while ((len = http_read(conn, buf, sizeof(buf))) > 0) {
		*size += len;
		data = realloc(data, *size);
		memcpy(data + *size - len, buf, len);
	}

	return data;
}

int read_message(http_t *conn, char *buf, int bufsiz, int *nread) {
	int request_len, n = 0;

	if (!conn) {
		return 0;
	}

	request_len = get_http_header_len(buf, *nread);
	while (request_len == 0) {
		/* Full request not yet received */
		if (conn->ctx->status != HTTP_STATUS_RUNNING) {
			/* Server is to be stopped. */
			return -1;
		}

		if (*nread >= bufsiz) {
			/* Request too long */
			return -2;
		}

		n = tls_reader(socket2fd(conn->client->sock), buf + *nread, bufsiz - *nread);
		if (n <= 0) {
			/* Receive error */
			return -1;
		}

		if (n > 0) {
			*nread += n;
			request_len = get_http_header_len(buf, *nread);
		}
	}

	return request_len;
}

int get_message(http_t *conn, char *ebuf, size_t ebuf_len, int *err) {
	if (ebuf_len > 0) {
		ebuf[0] = '\0';
	}

	*err = 0;
	if (!conn) {
		http_snprintf(
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "%s",
		            "Internal error");
		*err = 500;
		return 0;
	}

	conn->req.request_len = read_message(conn, conn->req.buf, conn->req.buf_size, &conn->req.data_len);
	if ((conn->req.request_len >= 0) && (conn->req.data_len < conn->req.request_len)) {
		http_snprintf(
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "%s",
		            "Invalid message size");
		*err = 500;
		return 0;
	}

	if ((conn->req.request_len == 0) && (conn->req.data_len == conn->req.buf_size)) {
		http_snprintf(
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "%s",
		            "Message too large");
		*err = 413;
		return 0;
	}

	if (conn->req.request_len <= 0) {
		if (conn->req.data_len > 0) {
			http_snprintf(
			            NULL, /* No truncation check for ebuf */
			            ebuf,
			            ebuf_len,
			            "%s",
			            "Malformed message");
			*err = 400;
		} else {
			/* Server did not recv anything -> just close the connection */
			conn->req.must_close = 1;
			http_snprintf(
			            NULL, /* No truncation check for ebuf */
			            ebuf,
			            ebuf_len,
			            "%s",
			            "No data received");
			*err = 0;
		}

		return 0;
	}

	return 1;
}

int get_request_response(http_t *conn, char *ebuf, size_t ebuf_len, int *err) {
	string_t cl;

	if (!get_message(conn, ebuf, ebuf_len, err)) {
		return 0;
	}

	if (parse_http(conn->action, conn, conn->req.buf) <= 0) {
		http_snprintf(
			NULL, /* No truncation check for ebuf */
			ebuf,
			ebuf_len,
			"%s",
			(conn->action == HTTP_REQUEST ? "Bad request" : "Bad response"));
		*err = 400;
		return 0;
	}

	/* Message is a valid request or response */
	if (conn->action == HTTP_REQUEST) {
		if (!http_switch_domain(conn)) {
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				ebuf,
				ebuf_len,
				"%s",
				"Bad request: Host mismatch");
			*err = 400;
			return 0;
		}

		if (((cl = http_get_header(conn, "Accept-Encoding")) != NULL)
			&& strstr(cl, "gzip")) {
			conn->req.accept_gzip = 1;
		}
	}

	if (((cl = http_get_header(conn, "Transfer-Encoding"))
		!= NULL)
		&& !str_is_case(cl, "identity")) {
		if (!str_is_case(cl, "chunked")) {
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				ebuf,
				ebuf_len,
				"%s",
				"Bad request");
			*err = 400;
			return 0;
		}
		conn->req.is_chunked = 1;
		conn->req.content_len = 0; /* not yet read */
	} else if ((cl = http_get_header(conn, "Content-Length"))
		!= NULL) {
		/* Request has content length set */
		char *endptr = NULL;
		conn->req.content_len = strtoll(cl, &endptr, 10);
		if ((endptr == cl) || (conn->req.content_len < 0)) {
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				ebuf,
				ebuf_len,
				"%s",
				"Bad request");
			*err = 411;
			return 0;
		}
		if (conn->action == HTTP_RESPONSE) {
			/* TODO: we should also consider HEAD method */
			if (conn->code == 304) {
				conn->req.content_len = 0;
			}
		}
	} else if (str_is_case(conn->method, "POST") || str_is_case(conn->method, "PUT")) {
		/* POST or PUT request without content length set */
		conn->req.content_len = -1;
	} else {
		if (conn->action == HTTP_RESPONSE) {
			/* There is no exception, see RFC7230. */
			/* TODO: we should also consider HEAD method */
			if (((conn->code >= 100)
				&& (conn->code <= 199))
				|| (conn->code == 204)
				|| (conn->code == 304)) {
				conn->req.content_len = 0;
			} else {
				conn->req.content_len = -1; /* unknown content length */
				if (conn->code >= 400)
					return 0;
			}
		} else {
			/* There is no exception, see RFC7230. */
			conn->req.content_len = 0;
		}
	}

	/* Publish the content length back to the request info. */
	conn->content_length = conn->req.content_len;
	return 1;
}

void close_socket_gracefully(http_t *conn) {
	struct linger linger;
	int error_code = 0;
	int linger_timeout = -2;
	socklen_t opt_len = sizeof(error_code);

	if (!conn || !conn->client) {
		return;
	}

	/* Send FIN to the client */
	if (!conn->client->has_ssl)
		shutdown(socket2fd(conn->client->sock), SHUT_WR);

#if defined(_WIN32)
	/* Read and discard pending incoming data. If we do not do that and
	 * close
	 * the socket, the data in the send buffer may be discarded. This
	 * behaviour is seen on Windows, when client keeps sending data
	 * when server decides to close the connection; then when client
	 * does recv() it gets no data back. */
	discard_unread_request_data(conn);
#endif

	if (conn->domain->config[LINGER_TIMEOUT]) {
		linger_timeout = atoi(conn->domain->config[LINGER_TIMEOUT]);
	}

	/* Set linger option according to configuration */
	if (linger_timeout >= 0) {
		/* Set linger option to avoid socket hanging out after close. This
		 * prevent ephemeral port exhaust problem under high QPS. */
		linger.l_onoff = 1;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4244)
#endif
#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif
		/* Data type of linger structure elements may differ,
		 * so we don't know what cast we need here.
		 * Disable type conversion warnings. */
		linger.l_linger = (linger_timeout + 999) / 1000;
#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic pop
#endif
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
	} else {
		linger.l_onoff = 0;
		linger.l_linger = 0;
	}

	if (linger_timeout < -1) {
		/* Default: don't configure any linger */
	} else {
		getsockopt(socket2fd(conn->client->sock), SOL_SOCKET, SO_ERROR, (char *)&error_code, &opt_len);
#if defined(_WIN32)
		if (error_code == WSAECONNRESET) {
#else
		if (error_code == ECONNRESET) {
#endif
			/* Socket already closed by client/peer, close socket without linger */
		} else {
			if (setsockopt(socket2fd(conn->client->sock), SOL_SOCKET, SO_LINGER, (char *)&linger, sizeof(linger)) != 0) {
				http_log(DEBUG_ERROR, conn,
					"%s: getsockopt(SOL_SOCKET SO_ERROR) failed: %s",
					__func__,
					ex_strerror(os_geterror()));
			}
		}
	}
}

void close_connection(http_t *conn) {
	if (is_empty(conn) || is_empty(conn->client)
		|| conn->client->sock == INVALID_SOCKET)
		return;

#ifdef USE_DEBUG
	delay(thrd_cpu_count() * 75);
#endif
	atomic_lock(&conn->ctx->nonce_mutex);
	/* Set close flag, so keep-alive loops will stop */
	conn->req.must_close = 1;
	if (conn->ctx->http_type == HTTP_INI_WEBSOCKET && !is_empty(conn->ws.close_handler)) {
		conn->ws.close_handler(conn, conn->ws.callback_data);
	}

	conn->req.user_data = null;
	close_socket_gracefully(conn);
	/* Now we know that our FIN is ACK-ed, safe to close */
	tls_closer(conn->client->sock);
	conn->client->sock = INVALID_SOCKET;
	atomic_unlock(&conn->ctx->nonce_mutex);
}

void http_close_connection(http_t *conn) {
	if ((conn == NULL) || conn->client == NULL) {
		return;
	}

	if (conn->ctx->http_type == HTTP_INI_SERVER) {
		if (conn->req.in_websocket_handling) {
			/* Set close flag, so the server thread can exit. */
			conn->req.must_close = 1;
			return;
		}
	}

	if (conn->ctx->http_type == HTTP_INI_WEBSOCKET) {
		/* client context: loops must end */
		conn->ctx->status = HTTP_STATUS_STOPPING;
		conn->req.must_close = 1;
	}

	close_connection(conn);
	if (conn->ctx->http_type == HTTP_INI_WEBSOCKET
		|| conn->ctx->http_type == HTTP_INI_CLIENT) {
		free(conn->client);
		conn->client = null;
		free(conn->req.buf);
		free(conn->ctx);
		free(conn);
	}
}

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

int http_put_dir(http_ini_t *ctx, http_t *conn, string_t path) {
	char buf[PATH_MAX];
	string_t s;
	string_t p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	int res;

	if (ctx == NULL)
		return -2;

	res = 1;
	s = path+2;
	p = path+2;
	while ( (p = strchr(s, '/')) != NULL ) {
		len = (size_t)(p - path);
		if (len >= sizeof(buf)) {
			/* path too long */
			res = -1;
			break;
		}

		memcpy(buf, path, len);
		buf[len] = '\0';
		/* Try to create intermediate directory */
		if (!http_stat(conn, buf, &file) && fs_mkdir(buf, 0755) != 0 ) {
			/* path does not exist and can not be created */
			res = -2;
			break;
		}

		/* Is path itself a directory? */
		if (p[1] == '\0')
			res = 0;

		s = ++p;
	}

	return res;
}

void http_remove_bad_file(http_ini_t *ctx, http_t *conn, string_t path ) {
	int r = fs_unlink(path);
	if (r != 0 && ctx != NULL && conn != NULL)
		http_log(DEBUG_ERROR, conn, "%s: Cannot remove invalid file %s", __func__, path);
}

int http_fclose(struct file *filep) {
	int retval;

	if (filep == NULL || filep->fp == NULL) {
		errno = EINVAL;
		return EOF;
	}

	retval = promise_fclose(filep->pf, filep->fp);
	filep->fp = NULL;
	filep->pf = NULL;

	return retval;
}

int http_stat(http_t *conn, string_t path, struct file *filep) {
	struct stat st;

	if (is_empty(filep))
		return 0;

	memset(filep, 0, sizeof(*filep));
	if (!is_empty(conn) && conn->ctx != NULL && http_is_file_in_memory(conn->ctx, conn, path, filep))
		return 1;

	if ((events_is_active() ? fs_stat(path, &st) : stat(path, &st)) == 0) {
		filep->size = (uint64_t)(st.st_size);
		filep->last_modified = st.st_mtime;
		filep->is_directory = S_ISDIR(st.st_mode);
		return 1;
	}

	return 0;
}

bool http_is_file_opened(struct file *filep) {
	return filep == NULL ? false : !is_empty(filep->membuf) || !is_empty(filep->fp);
}

bool http_fopen(http_ini_t *ctx, const http_t *conn, string_t path, string_t mode, struct file *filep) {
	struct stat st;
	bool found = false;

	if (ctx == NULL || filep == NULL || mode == null)
		return false;

	memset(filep, 0, sizeof(*filep));
	if (fs_stat(path, &st) == 0) {
		filep->size = (uint64_t)st.st_size;
		found = true;
	}

	if (!http_is_file_in_memory(ctx, (http_t *)conn, path, filep)) {
		if (!found && str_has(mode, "r"))
			return false;

		filep->pf = promise_fopen(path, mode);
		filep->fp = (FILE *)promise_wait(filep->pf).object;
	}

	return http_is_file_opened(filep);
}

void http_file(http_t *conn, string_t path, string_t mime_type,
	string_t additional_headers) {
	struct file file = STRUCT_FILE_INITIALIZER;

	if (!conn) {
		/* No conn */
		return;
	}

	if (http_stat(conn, path, &file)) {
		if (is_not_modified(conn, &file)) {
			/* Send 304 "Not Modified" - this must not send any body data */
			handle_not_modified_static_file_request(conn, &file);
		} else
			if (file.is_directory) {
				if (str_is_case(conn->domain->config[ENABLE_DIRECTORY_LISTING],
					"yes")) {
					handle_directory_request(conn, path);
				} else {
					http_error(conn,
						403,
						"%s",
						"Error: Directory listing denied");
				}
			} else {
				handle_static_file_request(conn, path, &file, mime_type, additional_headers);
			}
	} else {
		http_error(conn, 404, "%s", "Error: File not found");
	}
}

int64_t http_store_body(http_ini_t *ctx, http_t *conn, string_t path) {
	char buf[BUF_LEN];
	int64_t len;
	int ret;
	int n;
	struct file fi;

	if (ctx == NULL)
		return -1;

	len = 0;
	if (conn->req.consumed_content != 0) {
		http_log(DEBUG_ERROR, conn, "%s: Contents already consumed", __func__);
		return -11;
	}

	ret = http_put_dir(ctx, conn, path);
	if (ret < 0) {
		/*
		 * -1 for path too long,
		 * -2 for path can not be created. */
		return ret;
	}

	if (ret != 1) {
		/* Return 0 means, path itself is a directory. */
		return 0;
	}

	if (http_fopen(ctx, (const http_t *)conn, path, "w", &fi) == 0)
		return -12;

	ret = http_read(conn, buf, sizeof(buf));
	while (ret > 0) {
		n = (int)promise_fwrite(fi.pf, buf, 1, (size_t)ret, fi.fp);
		if (n != ret) {
			http_fclose(&fi);
			http_remove_bad_file(ctx, conn, path);
			return -13;
		}

		ret = http_read(conn, buf, sizeof(buf));
	}

	if (http_fclose(&fi) != 0) {
		http_remove_bad_file(ctx, conn, path);
		return -14;
	}

	return len;
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

int alloc_vprintf(string *out_buf, string prealloc_buf, size_t prealloc_size, string_t fmt, va_list ap) {
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

int alloc_printf(string *out_buf, string buf, size_t size, string_t fmt, ...) {
	va_list ap;
	int ret = 0;
	va_start(ap, fmt);
	ret = alloc_vprintf(out_buf, buf, size, fmt, ap);
	va_end(ap);

	return ret;
}

void_t free_ex(void_t memory) {
	if (!is_empty(memory))
		free(memory);

	return null;
}

static string_t header_val(http_t *conn, string_t header) {
	string_t header_value;
	if ((header_value = http_get_header(conn, (string)header)) == NULL) {
		return "-";
	} else {
		return header_value;
	}
}

static void http_log_access(http_t *conn) {
	const httpi_t *ri;
	struct file fi;
	char date[64], src_addr[IP_ADDR_STR_LEN];
	struct tm *tm;
	string_t referer, user_agent, log_name;;
	char log_buf[4096];

	if (!conn || !conn->ctx) {
		return;
	}

	/* Set log message to "empty" */
	log_buf[0] = 0;
	log_name = conn->domain->config[ACCESS_LOG_FILE];
	/* Log is written to a file and/or a callback. If both are not set,
	 * executing the rest of the function is pointless. */
	if ((str_is_empty(log_name)) && (conn->ctx->callbacks.log_access == NULL)) {
		return;
	}

	if (!log_buf[0]) {
		tm = localtime(&conn->req.conn_birth_time);
		if (tm != NULL) {
			strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S %z", tm);
		} else {
			str_lcpy(date, "01/Jan/1970:00:00:00 +0000", sizeof(date));
		}

		ri = &conn->req;
		async_sockaddr_str(src_addr, sizeof(src_addr), &conn->client->rsa);
		referer = header_val(conn, "Referer");
		user_agent = header_val(conn, "User-Agent");
		http_snprintf(
			NULL, /* Ignore truncation in access log */
			log_buf,
			sizeof(log_buf),
			"%s - %s [%s] \"%s %s HTTP/%s\" %d %" INT64_FMT
			" %s %s\n",
			src_addr,
			(ri->remote_user == NULL) ? "-" : ri->remote_user,
			date,
			conn->method,
			conn->url_to,
			ri->http_version,
			conn->status,
			conn->req.num_bytes_sent,
			referer,
			user_agent);
	}

	/* Here we have a log message in log_buf. Call the callback */
	if (conn->ctx->callbacks.log_access) {
		if (conn->ctx->callbacks.log_access(conn, log_buf)) {
			/* do not log if callback returns non-zero */
			return;
		}
	}

	/* Store in file */
	if (!str_is_empty(log_name)) {
		int ok = async_fprintf(log_name, "a+", log_buf);
		if (!ok) {
			cerr("Error writing log file %s", conn->domain->config[ACCESS_LOG_FILE]);
		}
	}
}

/* Is upgrade request:
 *   0 = regular HTTP/1.0 or HTTP/1.1 request
 *   1 = upgrade to websocket
 *   2 = upgrade to HTTP/2
 * -1 = upgrade to unknown protocol */
static int should_switch_to_protocol(http_t *conn) {
	string_t connection_headers;
	string_t upgrade_to;
	int should_upgrade;

	/* A websocket protocol has the following HTTP headers:
	 *
	 * Connection: Upgrade
	 * Upgrade: Websocket */
	connection_headers = http_get_header(conn, "Connection");
	should_upgrade = 0;
	if (str_is_case(connection_headers, "upgrade"))
		should_upgrade = 1;

	if (!should_upgrade) {
		return PROTOCOL_HTTP1;
	}

	upgrade_to = http_get_header(conn, "Upgrade");
	if (upgrade_to == NULL) {
		/* "Connection: Upgrade" without "Upgrade" Header --> Error */
		return -1;
	}

	/* Upgrade to ... */
	if (str_is_case(upgrade_to, "websocket")) {
		/* The headers "Host", "Sec-WebSocket-Key", "Sec-WebSocket-Protocol" and
		 * "Sec-WebSocket-Version" are also required.
		 * Don't check them here, since even an unsupported websocket protocol
		 * request still IS a websocket request (in contrast to a standard HTTP
		 * request). It will fail later in handle_websocket_request.
		 */
		return PROTOCOL_WEBSOCKET; /* Websocket */
	}
	if (str_is_case(upgrade_to, "h2")) {
		return PROTOCOL_HTTP2; /* Websocket */
	}

	/* Upgrade to another protocol */
	return -1;
}

void http_process_connection(http_ini_t *ctx, http_t *conn) {
	int keep_alive, discard_len, reqerr;
	char ebuf[100] = {0};
	string_t uri, hostend;
	enum uri_type_t uri_type;
	union {
		const_t con;
		void *var;
	} ptr;

	if (ctx == NULL || conn == NULL)
		return;

	debug_info("Start processing connection from %s"CLR_LN, conn->req.remote_addr);
	do {
		debug_info("calling get_request (%i times for this connection)"CLR_LN, conn->req.handled_requests + 1);
		if (!get_request_response(conn, ebuf, sizeof(ebuf), &reqerr)) {
			/*
			 * The request sent by the client could not be understood by
			 * the server, or it was incomplete or a timeout. Send an
			 * error message and close the connection. */
			if (reqerr > 0)
				http_error(conn, reqerr, "%s", ebuf);
		} else if (conn->req.http_version && strcmp(conn->req.http_version, "1.0") && strcmp(conn->req.http_version, "1.1")) {
			/* HTTP/2 is not allowed here */
			http_snprintf(NULL, /* No truncation check for ebuf */
				ebuf, sizeof(ebuf), "Bad HTTP version: [%s]", conn->req.http_version);
			http_error(conn, 505, "%s", ebuf);
		}

		if (ebuf[0] == '\0') {
			uri = http_get_path(conn);
			uri_type = http_get_uri_type(uri);
			switch (uri_type) {
				case URI_TYPE_ASTERISK:
					conn->req.local_uri = NULL;
					break;
				case URI_TYPE_RELATIVE:
					conn->req.local_uri = uri;
					break;
				case URI_TYPE_ABS_NOPORT:
				case URI_TYPE_ABS_PORT:
					hostend = http_get_rel_url_at_current_server(uri, conn);
					if (hostend != NULL)
						conn->req.local_uri = hostend;
					else
						conn->req.local_uri = NULL;
					break;
				default:
					http_snprintf(NULL, /* No truncation check for ebuf */
						ebuf, sizeof(ebuf), "Invalid URI");
					http_error(conn, 400, "%s", ebuf);
					conn->req.local_uri = NULL;
					break;
			}
		}

		if (ebuf[0] != '\0') {
			conn->req.proto = -1;
		} else {
			/* HTTP/1 allows protocol upgrade */
			conn->req.proto = should_switch_to_protocol(conn);
			if (conn->req.proto == PROTOCOL_HTTP2) {
				/* This will occur, if a HTTP/1.1 request should be upgraded
				 * to HTTP/2 - but not if HTTP/2 is negotiated using ALPN.
				 * Since most (all?) major browsers only support HTTP/2 using
				 * ALPN, this is hard to test and very low priority.
				 * Deactivate it (at least for now).
				 */
				conn->req.proto = PROTOCOL_HTTP1;
			}
		}

		debug_info("http: %s, error: %s"CLR_LN,
			(conn->req.http_version ? conn->req.http_version : "none"),
			(ebuf[0] ? ebuf : "none"));

		if (ebuf[0] == '\0') {
			if (conn->req.local_uri) {
				/* handle request to local server */
				http_handle_request(conn);
				debug_info("%s", "handle_request done"CLR_LN);
				http_log_access(conn);
			} else {
				/* TODO: handle non-local request (PROXY) */
				conn->req.must_close = true;
			}
		} else {
			conn->req.must_close = true;
		}

		/* http2 response complete. Free header buffer */
		//free_buffered_http2_response_header_list(conn);

		if (conn->req.remote_user != NULL) {
			ptr.con = conn->req.remote_user;
			free_ex(ptr.var);

			/*
			 * Important! When having connections with and without auth
			 * would cause double free and then crash */
			conn->req.remote_user = NULL;
		}

		/* NOTE(lsm): order is important here. should_keep_alive() call
		 * is using parsed request, which will be invalid after memmove's below.
		 * Therefore, memorize should_keep_alive() result now for later
		 * use in loop exit condition. */
		/* Enable it only if this request is completely discardable. */
		keep_alive = ctx->status == HTTP_STATUS_RUNNING
			&& should_keep_alive(conn) && (conn->req.content_len >= 0)
			&& (conn->req.request_len > 0)
			&& ((conn->req.is_chunked == 4)
				|| (!conn->req.is_chunked
					&& ((conn->req.consumed_content == conn->req.content_len)
						|| ((conn->req.request_len + conn->req.content_len) <= conn->req.data_len))))
			&& (conn->req.proto == PROTOCOL_HTTP1);

		if (keep_alive) {
			/* Discard all buffered data for this request */
			discard_len =
				((conn->req.request_len + conn->req.content_len) < conn->req.data_len)
				? (int)(conn->req.request_len + conn->req.content_len)
				: conn->req.data_len;
			conn->req.data_len -= discard_len;

			if (conn->req.data_len > 0) {
				debug_info("discard_len = %d"CLR_LN, discard_len);
				memmove(conn->req.buf, conn->req.buf + discard_len, (size_t)conn->req.data_len);
			}
		}

		if ((conn->req.data_len < 0) || (conn->req.data_len > conn->req.buf_size)) {
			debug_info("internal error: data_len = %li, buf_size = %li"CLR_LN,
				(long int)conn->req.data_len,
				(long int)conn->req.buf_size);
			break;
		}

		conn->req.handled_requests++;
	} while (keep_alive);

	debug_info("Done processing connection from %s (%f sec)"CLR_LN"\n",
		conn->req.remote_addr, difftime(time(NULL), conn->req.conn_birth_time));
}

http_t *http_connect_impl(const struct client_options *client_options,
	int use_ssl, struct error_data *error) {
	http_t *conn = NULL;
	fds_t sock;
	u_saddr_t sa, *psa;
	socklen_t len;
	unsigned max_req_size =	(unsigned)atoi(http_get_default_option(MAX_REQUEST_SIZE));

	if (is_empty(client_options->host) || (client_options->port <= 0)
		|| !is_valid_port((unsigned)client_options->port)) {
		if (error != NULL) {
			error->code = EINVAL;
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error->text,
				error->text_buffer_size,
				"%s",
				(is_empty(client_options->host) ? "NULL host" : "invalid port"));
		}

		return NULL;
	}

	if (error != NULL) {
		error->code = 0;
		error->code_sub = 0;
		if (error->text_buffer_size > 0) {
			error->text[0] = 0;
		}
	}

	if (is_empty(conn = (http_t *)calloc(1, sizeof(http_t)))) {
		if (error != NULL) {
			error->code = ENOMEM;
			error->code_sub = (unsigned)sizeof(http_t);
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error->text,
				error->text_buffer_size,
				"calloc(): %s",
				ex_strerror(os_geterror()));
		}
		return NULL;
	}

	if (is_empty(conn->ctx = (http_ini_t *)calloc(1, sizeof(http_ini_t)))) {
		free(conn);
		if (error != NULL) {
			error->code = ENOMEM;
			error->code_sub = (unsigned)sizeof(http_ini_t);
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error->text,
				error->text_buffer_size,
				"calloc(): %s",
				ex_strerror(os_geterror()));
		}
		return NULL;
	}

	if (is_empty(conn->req.buf = (char *)calloc(1, max_req_size + 1))) {
		free(conn->ctx);
		free(conn);
		if (error != NULL) {
			error->code = ENOMEM;
			error->code_sub = (unsigned)max_req_size;
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error->text,
				error->text_buffer_size,
				"calloc(): %s",
				ex_strerror(os_geterror()));
		}
		return NULL;
	}

	conn->req.buf_size = (int)max_req_size;
	conn->ctx->http_type = HTTP_INI_CLIENT;
	conn->domain = &(conn->ctx->host);
	atomic_flag_clear(&conn->ctx->nonce_mutex);
	if (use_ssl) {
		char addr[ARRAY_SIZE] = {0};
		snprintf(addr, sizeof(addr), "%s:%d", client_options->host, client_options->port);
		sock = tls_dial(addr);
	} else {
		sock = async_connect((string)client_options->host, client_options->port, 1);
	}

	if ((int)sock < 0) {
		http_snprintf(
			NULL, /* No truncation check for ebuf */
			error->text,
			error->text_buffer_size,
			"%s",
			ex_strerror(os_geterror()));
		free(conn);
		return NULL;
	}

	if (is_empty(conn->client = (http_socket *)calloc(1, sizeof(http_socket)))) {
		if (error != NULL) {
			error->code = ENOMEM;
			error->code_sub = (unsigned)sizeof(http_socket);
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error->text,
				error->text_buffer_size,
				"calloc(): %s",
				ex_strerror(os_geterror()));
		}
		tls_closer(socket2fd(sock));
		free(conn->req.buf);
		free(conn->ctx);
		free(conn);
		return NULL;
	}

	sa = *events_get_sockaddr(sock);
	conn->client->sock = sock;
	conn->client->lsa = sa;
	psa = &conn->client->rsa;
	memset(&psa->storage, 0, sizeof(psa->storage));
	len = conn->client->lsa.sa.sa_family == AF_INET6 ? sizeof(conn->client->lsa.sin6) : sizeof(conn->client->lsa.sin);
	if (getsockname(sock, &psa->sa, &len) != 0) {
		http_log(DEBUG_ERROR, conn,
			"%s: socket #%d getsockname() failed: %s", __func__, socket2fd(sock),
			ex_strerror(os_geterror()));
	}

	conn->client->has_ssl = use_ssl ? true : false;
	conn->type = (data_types)DATA_HTTPINFO;
	return conn;
}

http_t *http_connect(string_t host, int port,
	int use_ssl, string error_buffer, size_t error_buffer_size) {
	struct client_options opts;
	struct error_data error;

	memset(&error, 0, sizeof(error));
	error.text_buffer_size = error_buffer_size;
	error.text = error_buffer;

	memset(&opts, 0, sizeof(opts));
	opts.host = host;
	opts.port = port;
	return http_connect_impl(&opts, use_ssl, &error);
}

http_t *http_download(string_t host, int port, int use_ssl, string_t fmt, ...) {
	http_t *conn = null;
	va_list ap;
	int i;
	int reqerr;

	string ebuf = task_erred_str();
	size_t ebuf_len = ERR_BUF;
	ebuf[0] = '\0';

	va_start(ap, fmt);

	/* open a connection */
	conn = http_connect(host, port, use_ssl, ebuf, ebuf_len);
	if (conn != NULL) {
		i = http_vprintf(conn, fmt, ap);
		if (i <= 0) {
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				ebuf,
				ebuf_len,
				"%s",
				"Error sending request");
		} else {
			/* make sure the buffer is clear */
			conn->req.data_len = 0;
			http_get_response(conn, ebuf, ebuf_len, INFINITE);

			/* TODO: here, the URI is the http response code */
			conn->req.local_uri = conn->url_to;
		}
	}

	/* if an error occurred, close the connection */
	if ((ebuf[0] != '\0') && (conn != NULL)) {
		http_close_connection(conn);
		conn = NULL;
	}

	va_end(ap);
	return conn;
}

int http_upload(http_t *conn, string_t destination_dir) {
	char path[PATH_MAX], tmp_path[PATH_MAX], fname[1024];
	struct file fp = STRUCT_FILE_INITIALIZER;
	int bl, len = 0, num_uploaded_files = 0;
	string s, buf = null;

	/* Request looks like this:
	 *
	 * POST /upload HTTP/1.1
	 * Host: 127.0.0.1:8080
	 * Content-Length: 244894
	 * Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryRVr
	 *
	 * ------WebKitFormBoundaryRVr
	 * Content-Disposition: form-data; name="file"; filename="accum.png"
	 * Content-Type: image/png
	 *
	 * <89>PNG
	 * <PNG DATA>
	 * ------WebKitFormBoundaryRVr */

	/* Extract boundary string from the Content-Type header */
	if (http_get_header(conn, "Content-Type") == NULL || conn->boundary == NULL) {
		return num_uploaded_files;
	}

	bl = strlen(conn->boundary);
	/* Do some sanity checks for boundary lengths. */
	if (bl > 70 || bl < 4) {
		/* From RFC 2046:
		 * Boundary delimiters must not appear within the
		 * encapsulated material, and must be no longer
		 * than 70 characters, not counting the two
		 * leading hyphens. A boundary string of less than 4 bytes makes no sense either. */

		 /* Requests with long boundaries are not RFC compliant, maybe they
		  * are intended attacks to interfere with this algorithm. */
		conn->req.must_close = 1;
		return num_uploaded_files;
	}

	buf = http_read_until(conn, &len);
	/* Get headers for this part of the multipart message */
	conn->body = buf;
	conn->content_length = len;
	parse_multipart(conn);
	foreach(names in http_multi_names(conn)) {
		string name = names.char_ptr;
		if (http_multi_is_file(conn, name)) {
			fname[1023] = 0;
			snprintf(fname, sizeof(fname) - 1, "%s", http_multi_filename(conn, name));
			/* Construct destination file name. Do not allow paths to have
		 	 * slashes. */
			if ((s = strrchr(fname, '/')) == NULL &&
				(s = strrchr(fname, '\\')) == NULL) {
				s = fname;
			} else {
				s++;
			}

			/* There data is written to a temporary file first. */
			/* Different users should use a different destination_dir. */
			snprintf(path, sizeof(path) - 1, "%s%s%s", destination_dir, SYS_DIRSEP, s);
			strcpy(tmp_path, path);
			strcat(tmp_path, "~");

			/* We open the file with exclusive lock held. This guarantee us
			 * there is no other thread can save into the same file
			 * simultaneously. */
			fp.pf = promise_fopen(tmp_path, "wb");
			/* File opened in binary mode. */
			if ((fp.fp = (FILE *)promise_wait(fp.pf).object) == NULL)
				break;

			void_t data = http_multi_body(conn, name);
			size_t sdata = http_multi_length(conn, name);
			if ((int)promise_fwrite(fp.pf, data, 1, sdata - 2, fp.fp) > 0) {
				promise_fclose(fp.pf, fp.fp);
				fs_unlink(path);
				fs_rename(tmp_path, path);
				num_uploaded_files++;
				if (conn && conn->ctx && conn->ctx->callbacks.upload != NULL)
					conn->ctx->callbacks.upload(conn, path);
			} else {
				promise_fclose(fp.pf, fp.fp);
				fs_unlink(tmp_path);
			}
			fp.pf = null;
			fp.fp = null;
		}
	}

	if (fp.pf)
		promise_clean(fp.pf);

	free(buf);
	conn->body = null;
	return num_uploaded_files;
}

void http_set_handler(http_ini_t *ctx,
	string_t uri, enum route_type_t handler_type,
	bool is_delete_request, route_cb handler,
	struct ws_subprotocols_s *subprotocols,
	ws_connect_cb connect_handler, ws_ready_cb ready_handler,
	ws_data_cb data_handler, ws_close_cb close_handler,
	auth_cb auth_handler, void_t cbdata) {
	struct http_cb_info *tmp_rh, **lastref;
	size_t urilen = strlen(uri);

	if (handler_type == WEBSOCKET_HANDLER) {
		if (handler != NULL) {
			return;
		}
		if (!is_delete_request && connect_handler == NULL
		    && ready_handler == NULL
		    && data_handler == NULL
		    && close_handler == NULL) {
			return;
		}
		if (auth_handler != NULL) {
			return;
		}
	} else if (handler_type == REQUEST_HANDLER) {
		if (connect_handler != NULL || ready_handler != NULL
		    || data_handler != NULL
		    || close_handler != NULL) {
			return;
		}
		if (!is_delete_request && (handler == NULL)) {
			return;
		}
		if (auth_handler != NULL) {
			return;
		}
	} else {
		if (handler != NULL) {
			return;
		}
		if (connect_handler != NULL || ready_handler != NULL
		    || data_handler != NULL
		    || close_handler != NULL) {
			return;
		}
		if (!is_delete_request && (auth_handler == NULL)) {
			return;
		}
	}

	if (!ctx) {
		return;
	}

	atomic_lock(&ctx->nonce_mutex);

	/* first try to find an existing handler */
	lastref = &(ctx->handlers);
	for (tmp_rh = ctx->handlers; tmp_rh != NULL; tmp_rh = tmp_rh->next) {
		if (tmp_rh->handler_type == handler_type) {
			if (urilen == tmp_rh->uri_len && !strcmp(tmp_rh->uri, uri)) {
				if (!is_delete_request) {
					/* update existing handler */
					if (handler_type == REQUEST_HANDLER) {
						tmp_rh->handler = handler;
					} else if (handler_type == WEBSOCKET_HANDLER) {
						tmp_rh->subprotocols = subprotocols;
						tmp_rh->connect_handler = connect_handler;
						tmp_rh->ready_handler = ready_handler;
						tmp_rh->data_handler = data_handler;
						tmp_rh->close_handler = close_handler;
					} else { /* AUTH_HANDLER */
						tmp_rh->auth_handler = auth_handler;
					}
					tmp_rh->cbdata = cbdata;
				} else {
					/* remove existing handler */
					*lastref = tmp_rh->next;
					tmp_rh->uri = null;
					tmp_rh = null;
				}
				atomic_unlock(&ctx->nonce_mutex);
				return;
			}
		}
		lastref = &(tmp_rh->next);
	}

	if (is_delete_request) {
		/* no handler to set, this was a remove request to a non-existing
		 * handler */
		atomic_unlock(&ctx->nonce_mutex);
		return;
	}

	if (defer_free(tmp_rh = (struct http_cb_info *)calloc(1, sizeof(struct http_cb_info)))) {
		tmp_rh->uri = str_dup(uri);
		tmp_rh->uri_len = urilen;
		if (handler_type == REQUEST_HANDLER) {
			tmp_rh->handler = handler;
		} else if (handler_type == WEBSOCKET_HANDLER) {
			tmp_rh->subprotocols = subprotocols;
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
	} else {
		atomic_unlock(&ctx->nonce_mutex);
		http_log(DEBUG_ERROR, NULL, "%s: cannot create new request handler struct, OOM", __func__);
		return;
	}

	atomic_unlock(&ctx->nonce_mutex);
}

FORCEINLINE void http_route(http_ini_t *ctx, string_t uri, route_cb handler, void_t cbdata) {
	http_set_handler(ctx, uri, REQUEST_HANDLER, (handler == NULL), handler,
		NULL, NULL, NULL, NULL, NULL, NULL, cbdata);
}

FORCEINLINE void http_websocket_route(http_ini_t *ctx, string_t uri,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	void_t cbdata) {
	bool is_delete_request = (connect_handler == NULL) && (ready_handler == NULL)
		&& (data_handler == NULL) && (close_handler == NULL);

	http_set_handler(ctx, uri, WEBSOCKET_HANDLER, is_delete_request, NULL, NULL,
		connect_handler, ready_handler, data_handler, close_handler, NULL, cbdata);
}

FORCEINLINE void http_websocket_route_subprotocol(http_ini_t *ctx, string_t uri,
	struct ws_subprotocols_s *subprotocols,
	ws_connect_cb connect_handler,
	ws_ready_cb ready_handler,
	ws_data_cb data_handler,
	ws_close_cb close_handler,
	void_t cbdata) {
	bool is_delete_request = (connect_handler == NULL) && (ready_handler == NULL)
		&& (data_handler == NULL) && (close_handler == NULL);

	http_set_handler(ctx, uri, WEBSOCKET_HANDLER, is_delete_request, NULL, subprotocols,
		connect_handler, ready_handler, data_handler, close_handler, NULL, cbdata);
}
