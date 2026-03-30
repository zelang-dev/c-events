#include "httpie_internal.h"

static int is_put_or_delete_method(const http_t *conn) {
	if (conn) {
		string_t s = conn->method;
		if (s != NULL) {
			/* PUT, DELETE, MKCOL, PATCH, LOCK, UNLOCK, PROPPATCH, MOVE, COPY */
			return (!strcmp(s, "PUT") || !strcmp(s, "DELETE")
				|| !strcmp(s, "MKCOL") || !strcmp(s, "PATCH")
				|| !strcmp(s, "LOCK") || !strcmp(s, "UNLOCK")
				|| !strcmp(s, "PROPPATCH") || !strcmp(s, "MOVE")
				|| !strcmp(s, "COPY"));
		}
	}
	return 0;
}

static int is_webdav_method(const http_t *conn) {
	/* Note: Here we only have to identify the WebDav methods that need special
	 * handling in the `httpie` code - not all methods used in WebDav. In
	 * particular, methods used on directories (when using Windows Explorer as
	 * WebDav client). */
	if (conn) {
		string_t s = conn->method;
		if (s != NULL) {
			/* These are the civetweb builtin DAV methods */
			return (!strcmp(s, "PROPFIND") || !strcmp(s, "PROPPATCH")
				|| !strcmp(s, "LOCK") || !strcmp(s, "UNLOCK")
				|| !strcmp(s, "MOVE") || !strcmp(s, "COPY"));
		}
	}
	return 0;
}

#if !defined(NO_FILES)
/* in: request (must be valid) */
/* in: filename  (must be valid) */
static int extention_matches_script(http_t *conn, string_t filename) {
#if !defined(NO_CGI)
	int cgi_config_idx, inc, max;
#endif
#if defined(USE_DUKTAPE)
	if (match_prefix_strlen(conn->domain->config[DUKTAPE_SCRIPT_EXTENSIONS],
		filename)
		> 0) {
		return 1;
	}
#endif
#if !defined(NO_CGI)
	inc = CGI2_EXTENSIONS - CGI_EXTENSIONS;
	max = PUT_DELETE_PASSWORDS_FILE - CGI_EXTENSIONS;
	for (cgi_config_idx = 0; cgi_config_idx < max; cgi_config_idx += inc) {
		if ((conn->domain->config[CGI_EXTENSIONS + cgi_config_idx] != NULL)
			&& (match_prefix_strlen(
				conn->domain->config[CGI_EXTENSIONS + cgi_config_idx],
				filename)
	> 0)) {
			return 1;
		}
	}
#endif
	/* filename and conn could be unused, if all preocessor conditions
	 * are false (no script language supported). */
	(void)filename;
	(void)conn;

	return 0;
}

/* in: request (must be valid) */
/* in: filename  (must be valid) */
static int extention_matches_template_text(http_t *conn, string_t filename) {
	if (match_prefix_strlen(conn->domain->config[SSI_EXTENSIONS], filename)
		> 0) {
		return 1;
	}
	return 0;
}

/* For given directory path, substitute it to valid index file.
 * Return 1 if index file has been found, 0 if not found.
 * If the file is found, it's stats is returned in stp. */
static int substitute_index_file_aux(http_t *conn,
	char *path,
	size_t path_len,
	struct file *filestat) {
	string_t list = conn->domain->config[INDEX_FILES];
	struct vec filename_vec;
	size_t n = strlen(path);
	int found = 0;

	/* The 'path' given to us points to the directory. Remove all trailing
	 * directory separator characters from the end of the path, and
	 * then append single directory separator character. */
	while ((n > 0) && (path[n - 1] == '/')) {
		n--;
	}
	path[n] = '/';

	/* Traverse index files list. For each entry, append it to the given
	 * path and see if the file exists. If it exists, break the loop */
	while ((list = http_next_option(list, &filename_vec, NULL)) != NULL) {
		/* Ignore too long entries that may overflow path buffer */
		if ((filename_vec.len + 1) > (path_len - (n + 1))) {
			continue;
		}

		/* Prepare full path to the index file */
		str_lcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

		/* Does it exist? */
		if (http_stat(conn, path, filestat)) {
			/* Yes it does, break the loop */
			found = 1;
			break;
		}
	}

	/* If no index file exists, restore directory path */
	if (!found) {
		path[n] = '\0';
	}

	return found;
}

/* Same as above, except if the first try fails and a fallback-root is
 * configured, we'll try there also */
static int substitute_index_file(http_t *conn, char *path, size_t path_len, struct file *filestat) {
	int ret = substitute_index_file_aux(conn, path, path_len, filestat);
	if (ret == 0) {
		string_t root_prefix = conn->domain->config[DOCUMENT_ROOT];
		string_t fallback_root_prefix =
			conn->domain->config[FALLBACK_DOCUMENT_ROOT];
		if ((root_prefix) && (fallback_root_prefix)) {
			const size_t root_prefix_len = strlen(root_prefix);
			if ((strncmp(path, root_prefix, root_prefix_len) == 0)) {
				char scratch_path[UTF8_PATH_MAX]; /* separate storage, to avoid
												  side effects if we fail */
				size_t sub_path_len;

				const size_t fallback_root_prefix_len =
					strlen(fallback_root_prefix);
				string_t sub_path = path + root_prefix_len;
				while (*sub_path == '/') {
					sub_path++;
				}
				sub_path_len = strlen(sub_path);

				if (((fallback_root_prefix_len + 1 + sub_path_len + 1)
					< sizeof(scratch_path))) {
				   /* The concatenations below are all safe because we
					* pre-verified string lengths above */
					char *nul;
					strcpy(scratch_path, fallback_root_prefix);
					nul = strchr(scratch_path, '\0');
					if ((nul > scratch_path) && (*(nul - 1) != '/')) {
						*nul++ = '/';
						*nul = '\0';
					}
					strcat(scratch_path, sub_path);
					if (substitute_index_file_aux(conn,
						scratch_path,
						sizeof(scratch_path),
						filestat)) {
						str_lcpy(path, scratch_path, path_len);
						return 1;
					}
				}
			}
		}
	}
	return ret;
}
#endif

/*
 * Interprets an URI and decides what
 * type of request is involved. The function takes the following parameters:
 *
 * - ctx:				in:  The context in which to communicate
 * - conn:			in:  The request (must be valid)
 * - filename:			out: Filename
 * - filename_buf_len:		in:  Size of the filename buffer
 * - filep:			out: file structure
 * - is_found:			out: file is found (directly)
 * - is_script_resource:		out: handled by a script?
 * - is_websocket_request:	out: websocket connection?
 * - is_put_or_delete_request:	out: put/delete file? */
void http_interpret_uri(http_t *conn, /* in/out: request (must be valid) */
	char *filename,             /* out: filename */
	size_t filename_buf_len,    /* in: size of filename buffer */
	struct file *filestat, /* out: file status structure */
	int *is_found,                 /* out: file found (directly) */
	int *is_script_resource,       /* out: handled by a script? */
	int *is_websocket_request,     /* out: websocket connection? */
	int *is_put_or_delete_request, /* out: put/delete a file? */
	int *is_webdav_request,        /* out: webdav request? */
	int *is_template_text          /* out: SSI file or LSP file? */
) {
	char const *accept_encoding;

	string_t uri = conn->req.local_uri;
	string_t roots[] = {conn->domain->config[DOCUMENT_ROOT],
						   conn->domain->config[FALLBACK_DOCUMENT_ROOT],
						   NULL};
	int fileExists = 0;
	string_t rewrite;
	struct vec a, b;
	ptrdiff_t match_len;
	char gz_path[UTF8_PATH_MAX];
	int truncated;
	int i;
	char *tmp_str;
	size_t tmp_str_len, sep_pos;
	int allow_substitute_script_subresources;

	/* Step 1: Set all initially unknown outputs to zero */
	memset(filestat, 0, sizeof(*filestat));
	*filename = 0;
	*is_found = 0;
	*is_script_resource = 0;
	*is_template_text = 0;

	/* Step 2: Classify the request method */
	/* Step 2a: Check if the request attempts to modify the file system */
	*is_put_or_delete_request = is_put_or_delete_method(conn);
	/* Step 2b: Check if the request uses WebDav method that requires special
	 * handling */
	*is_webdav_request = is_webdav_method(conn);

	/* Step 3: Check if it is a websocket request, and modify the document
	 * root if required */
	*is_websocket_request = (conn->req.proto == PROTOCOL_WEBSOCKET);
	if ((*is_websocket_request) && conn->domain->config[WEBSOCKET_ROOT]) {
		roots[0] = conn->domain->config[WEBSOCKET_ROOT];
		roots[1] = conn->domain->config[FALLBACK_WEBSOCKET_ROOT];
	}

	/* Step 4: Check if gzip encoded response is allowed */
	conn->req.accept_gzip = 0;
	if ((accept_encoding = http_get_header(conn, "Accept-Encoding")) != NULL) {
		if (strstr(accept_encoding, "gzip") != NULL) {
			conn->req.accept_gzip = 1;
		}
	}

	/* Step 5: If there is no root directory, don't look for files. */
	/* Note that roots[0] == NULL is a regular use case here. This occurs,
	 * if all requests are handled by callbacks, so the WEBSOCKET_ROOT
	 * config is not required. */
	if (roots[0] == NULL) {
		/* all file related outputs have already been set to 0, just return
		 */
		return;
	}

	for (i = 0; roots[i] != NULL; i++) {
		/* Step 6: Determine the local file path from the root path and the
		 * request uri. */
		/* Using filename_buf_len - 1 because memmove() for path may shift
		 * part of the path one byte on the right. */
		truncated = 0;
		http_snprintf(conn,
			&truncated,
			filename,
			filename_buf_len - 1,
			"%s%s",
			roots[i],
			uri);

		if (truncated) {
			goto interpret_cleanup;
		}

		/* Step 7: URI rewriting */
		rewrite = conn->domain->config[URL_REWRITE_PATTERN];
		while ((rewrite = http_next_option(rewrite, &a, &b)) != NULL) {
			if ((match_len = http_match_prefix(a.ptr, a.len, uri)) > 0) {
				http_snprintf(conn,
					&truncated,
					filename,
					filename_buf_len - 1,
					"%.*s%s",
					(int)b.len,
					b.ptr,
					uri + match_len);
				break;
			}
		}

		if (truncated) {
			goto interpret_cleanup;
		}

		/* Step 8: Check if the file exists at the server */
		/* Local file path and name, corresponding to requested URI
		 * is now stored in "filename" variable. */
		if (http_stat(conn, filename, filestat)) {
			fileExists = 1;
			break;
		}
	}

	if (fileExists) {
		int uri_len = (int)strlen(uri);
		int is_uri_end_slash = (uri_len > 0) && (uri[uri_len - 1] == '/');

		/* 8.1: File exists. */
		*is_found = 1;

		/* 8.2: Check if it is a script type. */
		if (extention_matches_script(conn, filename)) {
			/* The request addresses a CGI resource, Lua script or
			 * server-side javascript.
			 * The URI corresponds to the script itself (like
			 * /path/script.cgi), and there is no additional resource
			 * path (like /path/script.cgi/something).
			 * Requests that modify (replace or delete) a resource, like
			 * PUT and DELETE requests, should replace/delete the script
			 * file.
			 * Requests that read or write from/to a resource, like GET and
			 * POST requests, should call the script and return the
			 * generated response. */
			*is_script_resource = (!*is_put_or_delete_request);
		}

		/* 8.3: Check for SSI and LSP files */
		if (extention_matches_template_text(conn, filename)) {
			/* Same as above, but for *.lsp and *.shtml files. */
			/* A "template text" is a file delivered directly to the client,
			 * but with some text tags replaced by dynamic content.
			 * E.g. a Server Side Include (SSI) or Lua Page/Lua Server Page
			 * (LP, LSP) file. */
			*is_template_text = (!*is_put_or_delete_request);
		}

		/* 8.4: If the request target is a directory, there could be
		 * a substitute file (index.html, index.cgi, ...). */
		/* But do not substitute a directory for a WebDav request */
		if (filestat->is_directory && is_uri_end_slash
			&& (!*is_webdav_request)) {
			/* Use a local copy here, since substitute_index_file will
			 * change the content of the file status */
			struct file tmp_filestat;
			memset(&tmp_filestat, 0, sizeof(tmp_filestat));

			if (substitute_index_file(
				conn, filename, filename_buf_len, &tmp_filestat)) {
			/* Substitute file found. Copy stat to the output, then
			 * check if the file is a script file */
				*filestat = tmp_filestat;
				if (extention_matches_script(conn, filename)) {
					/* Substitute file is a script file */
					*is_script_resource = 1;
				} else if (extention_matches_template_text(conn, filename)) {
					/* Substitute file is a LSP or SSI file */
					*is_template_text = 1;
				} else {
					/* Substitute file is a regular file */
					*is_script_resource = 0;
					*is_found = (http_stat(conn, filename, filestat) ? 1 : 0);
				}
			}
			/* If there is no substitute file, the server could return
			 * a directory listing in a later step */
		}
		return;
	}

	/* Step 9: Check for zipped files: */
	/* If we can't find the actual file, look for the file
	 * with the same name but a .gz extension. If we find it,
	 * use that and set the gzipped flag in the file struct
	 * to indicate that the response need to have the content-
	 * encoding: gzip header.
	 * We can only do this if the browser declares support. */
	if (conn->req.accept_gzip) {
		http_snprintf(
			conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", filename);

		if (truncated) {
			goto interpret_cleanup;
		}

		if (http_stat(conn, gz_path, filestat)) {
			if (filestat) {
				filestat->gzipped = 1;
				*is_found = 1;
			}
			/* Currently gz files can not be scripts. */
			return;
		}
	}

	/* Step 10: Script resources may handle sub-resources */
	/* Support path for CGI scripts. */
	tmp_str_len = strlen(filename);
	tmp_str = (char *)malloc(tmp_str_len + UTF8_PATH_MAX + 1);
	if (!tmp_str) {
		/* Out of memory */
		goto interpret_cleanup;
		memcpy(tmp_str, filename, tmp_str_len + 1);

		/* Check config, if index scripts may have sub-resources */
		allow_substitute_script_subresources = str_is_case(conn->domain->config[ALLOW_INDEX_SCRIPT_SUB_RES],
			"yes");
		if (*is_webdav_request) {
			/* TO BE DEFINED: Should scripts handle special WebDAV methods lile
			 * PROPFIND for their subresources? */
			/* allow_substitute_script_subresources = 0; */
		}

		sep_pos = tmp_str_len;
		while (sep_pos > 0) {
			sep_pos--;
			if (tmp_str[sep_pos] == '/') {
				int is_script = 0, does_exist = 0;

				tmp_str[sep_pos] = 0;
				if (tmp_str[0]) {
					is_script = extention_matches_script(conn, tmp_str);
					does_exist = http_stat(conn, tmp_str, filestat);
				}

				if (does_exist && is_script) {
					filename[sep_pos] = 0;
					memmove(filename + sep_pos + 2,
						filename + sep_pos + 1,
						strlen(filename + sep_pos + 1) + 1);
					conn->path = filename + sep_pos + 1;
					filename[sep_pos + 1] = '/';
					*is_script_resource = 1;
					*is_found = 1;
					break;
				}

				if (allow_substitute_script_subresources) {
					if (substitute_index_file(
						conn, tmp_str, tmp_str_len + UTF8_PATH_MAX, filestat)) {
					/* some intermediate directory has an index file */
						if (extention_matches_script(conn, tmp_str)) {
							size_t script_name_len = strlen(tmp_str);
							/* subres_name read before this memory locatio will be
							overwritten */
							char *subres_name = filename + sep_pos;
							size_t subres_name_len = strlen(subres_name);
							//DEBUG_TRACE("Substitute script %s serving path %s", tmp_str, filename);

							/* this index file is a script */
							if ((script_name_len + subres_name_len + 2)
								>= filename_buf_len) {
								free(tmp_str);
								goto interpret_cleanup;
							}

							conn->path = filename + script_name_len + 1; /* new target */
							memmove(conn->path, subres_name, subres_name_len);
							conn->path[subres_name_len] = 0;
							memcpy(filename, tmp_str, script_name_len + 1);

							*is_script_resource = 1;
							*is_found = 1;
							break;
						} else {
							//DEBUG_TRACE("Substitute file %s serving path %s", tmp_str, filename);

							/* non-script files will not have sub-resources */
							filename[sep_pos] = 0;
							conn->path = 0;
							*is_script_resource = 0;
							*is_found = 0;
							break;
						}
					}
				}

				tmp_str[sep_pos] = '/';
			}
		}

		free(tmp_str);
		return;

	/* Reset all outputs */
	interpret_cleanup:
		memset(filestat, 0, sizeof(*filestat));
		*filename = 0;
		*is_found = 0;
		*is_script_resource = 0;
		*is_websocket_request = 0;
		*is_put_or_delete_request = 0;
	}
}

static int http_get_request_handler(http_t *conn,
	int handler_type,
	route_cb *handler,
	struct ws_subprotocols_s **subprotocols,
	ws_connect_cb *connect_handler,
	ws_ready_cb *ready_handler,
	ws_data_cb *data_handler,
	ws_close_cb *close_handler,
	auth_cb *auth_handler,
	void **cbdata,
	struct http_cb_info **handler_info) {
	const httpie_t *request_info = &conn->req;
	if (request_info) {
		string_t uri = request_info->local_uri;
		size_t urilen = strlen(uri);
		struct http_cb_info *tmp_rh;
		int step, matched;

		if (!conn || !conn->ctx || !conn->domain) {
			return 0;
		}

		atomic_lock(&conn->ctx->nonce_mutex);
		for (step = 0; step < 3; step++) {
			for (tmp_rh = conn->domain->handlers; tmp_rh != NULL;
				tmp_rh = tmp_rh->next) {
				if (tmp_rh->handler_type != handler_type) {
					continue;
				}
				if (step == 0) {
					/* first try for an exact match */
					matched = (tmp_rh->uri_len == urilen)
						&& (strcmp(tmp_rh->uri, uri) == 0);
				} else if (step == 1) {
					/* next try for a partial match, we will accept
					uri/something */
					matched =
						(tmp_rh->uri_len < urilen)
						&& (uri[tmp_rh->uri_len] == '/')
						&& (memcmp(tmp_rh->uri, uri, tmp_rh->uri_len) == 0);
				} else {
					/* finally try for pattern match */
					matched =
						http_match_prefix(tmp_rh->uri, tmp_rh->uri_len, uri) > 0;
				}
				if (matched) {
					if (handler_type == WEBSOCKET_HANDLER) {
						*subprotocols = tmp_rh->subprotocols;
						*connect_handler = tmp_rh->connect_handler;
						*ready_handler = tmp_rh->ready_handler;
						*data_handler = tmp_rh->data_handler;
						*close_handler = tmp_rh->close_handler;
					} else if (handler_type == REQUEST_HANDLER) {
						if (tmp_rh->removing) {
							/* Treat as none found */
							step = 2;
							break;
						}
						*handler = tmp_rh->handler;
						/* Acquire handler and give it back */
						tmp_rh->refcount++;
						*handler_info = tmp_rh;
					} else { /* AUTH_HANDLER */
						*auth_handler = tmp_rh->auth_handler;
					}
					*cbdata = tmp_rh->cbdata;
					atomic_unlock(&conn->ctx->nonce_mutex);
					return 1;
				}
			}
		}

		atomic_unlock(&conn->ctx->nonce_mutex);
	}
	return 0; /* none found */
}

int http_url_decode(string_t src,int src_len,char *dst,int dst_len,int is_form_url_encoded) {
	int i, j, a, b;

#define HEXTOI(x) (isdigit(x) ? (x - '0') : (x - 'W'))
	for (i = j = 0; (i < src_len) && (j < (dst_len - 1)); i++, j++) {
		if ((i < src_len - 2) && (src[i] == '%')
			&& isxdigit((unsigned char)src[i + 1])
			&& isxdigit((unsigned char)src[i + 2])) {
			a = tolower((unsigned char)src[i + 1]);
			b = tolower((unsigned char)src[i + 2]);
			dst[j] = (char)((HEXTOI(a) << 4) | HEXTOI(b));
			i += 2;
		} else if (is_form_url_encoded && (src[i] == '+')) {
			dst[j] = ' ';
		} else if ((unsigned char)src[i] <= ' ') {
			return -1; /* invalid character */
		} else {
			dst[j] = src[i];
		}
	}
#undef HEXTOI

	dst[j] = '\0'; /* Null-terminate the destination */
	return (i >= src_len) ? j : -1;
}

/* form url decoding of an entire string */
static void url_decode_in_place(char *buf) {
	int len = (int)strlen(buf);
	(void)http_url_decode(buf, len, buf, len + 1, 1);
}

int http_url_encode(string_t src, char *dst, size_t dst_len) {
	static string_t dont_escape = "._-$,;~()";
	static string_t hex = "0123456789abcdef";
	char *pos = dst;
	string_t end = dst + dst_len - 1;

	for (; ((*src != '\0') && (pos < end)); src++, pos++) {
		if (isalnum((unsigned char)*src)
			|| (strchr(dont_escape, *src) != NULL)) {
			*pos = *src;
		} else if (pos + 2 < end) {
			pos[0] = '%';
			pos[1] = hex[(unsigned char)*src >> 4];
			pos[2] = hex[(unsigned char)*src & 0xf];
			pos += 2;
		} else {
			break;
		}
	}

	*pos = '\0';
	return (*src == '\0') ? (int)(pos - dst) : -1;
}

static string_t get_proto_name(const http_t *conn) {
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	/* Depending on USE_WEBSOCKET and NO_SSL, some oft the protocols might be
	 * not supported. Clang raises an "unreachable code" warning for parts of ?:
	 * unreachable, but splitting into four different #ifdef clauses here is
	 * more complicated.
	 */
#endif

	const httpie_t *ri = &conn->req;

	string_t proto = ((conn->req.proto == PROTOCOL_WEBSOCKET)
		? (conn->client.has_ssl ? "wss" : "ws")
		: (conn->client.has_ssl ? "https" : "http"));

	return proto;

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
}

static int construct_local_link(const http_t *conn,
	char *buf,
	size_t buflen,
	string_t define_proto,
	int define_port,
	string_t define_uri) {
	if ((buflen < 1) || (buf == 0) || (conn == 0)) {
		return -1;
	} else {
		int i, j;
		int truncated = 0;
		const httpie_t *ri = &conn->req;

		string_t proto =
			(define_proto != NULL) ? define_proto : get_proto_name(conn);
		string_t uri =
			(define_uri != NULL)
			? define_uri
			: ((conn->url_to != NULL) ? conn->url_to : ri->local_uri);
		int port = (define_port > 0) ? define_port : ri->server_port;
		int default_port = 80;
		char *uri_encoded;
		size_t uri_encoded_len;

		if (uri == NULL) {
			return -1;
		}

		uri_encoded_len = strlen(uri) * 3 + 1;
		uri_encoded = (char *)malloc(uri_encoded_len);
		if (uri_encoded == NULL) {
			return -1;
		}
		http_url_encode(uri, uri_encoded, uri_encoded_len);

		/* Directory separator should be preserved. */
		for (i = j = 0; uri_encoded[i]; j++) {
			if (!strncmp(uri_encoded + i, "%2f", 3)) {
				uri_encoded[j] = '/';
				i += 3;
			} else {
				uri_encoded[j] = uri_encoded[i++];
			}
		}
		uri_encoded[j] = '\0';
		if (conn->client.lsa.sa.sa_family == AF_UNIX) {
			/* TODO: Define and document a link for UNIX domain sockets. */
			/* There seems to be no official standard for this.
			 * Common uses seem to be "httpunix://", "http.unix://" or
			 * "http+unix://" as a protocol definition string, followed by
			 * "localhost" or "127.0.0.1" or "/tmp/unix/path" or
			 * "%2Ftmp%2Funix%2Fpath" (url % encoded) or
			 * "localhost:%2Ftmp%2Funix%2Fpath" (domain socket path as port) or
			 * "" (completely skipping the server name part). In any case, the
			 * last part is the server local path. */
			string_t server_name = events_uname();
			http_snprintf(conn,
				&truncated,
				buf,
				buflen,
				"%s.unix://%s%s",
				proto,
				server_name,
				ri->local_uri);
			default_port = 0;
			free(uri_encoded);
			return 0;
		}

		if (define_proto) {
			/* If we got a protocol name, use the default port accordingly. */
			if ((0 == strcmp(define_proto, "https"))
				|| (0 == strcmp(define_proto, "wss"))) {
				default_port = 443;
			}
		} else if (conn->client.has_ssl) {
			/* If we did not get a protocol name, use TLS as default if it is
			 * already used. */
			default_port = 443;
		}

		{
			int is_ipv6 = (conn->client.lsa.sa.sa_family == AF_INET6);
			int auth_domain_check_enabled =
				conn->domain->config[ENABLE_AUTH_DOMAIN_CHECK]
				&& (str_is_case(
					conn->domain->config[ENABLE_AUTH_DOMAIN_CHECK], "yes"));

			string_t server_domain =
				conn->domain->config[AUTHENTICATION_DOMAIN];

			char portstr[16];
			char server_ip[48];

			if (port != default_port) {
				sprintf(portstr, ":%u", (unsigned)port);
			} else {
				portstr[0] = 0;
			}

			if (!auth_domain_check_enabled || !server_domain) {
				sockaddr_to_str(server_ip,
					sizeof(server_ip),
					&conn->client.lsa);
				server_domain = server_ip;
			}

			http_snprintf(conn,
				&truncated,
				buf,
				buflen,
				"%s://%s%s%s%s%s",
				proto,
				(is_ipv6 && (server_domain == server_ip)) ? "[" : "",
				server_domain,
				(is_ipv6 && (server_domain == server_ip)) ? "]" : "",
				portstr,
				uri_encoded);

			free(uri_encoded);
			if (truncated) {
				return -1;
			}
			return 0;
		}
	}
}

C_API int http_get_request_link(http_t *conn, char *buf, size_t buflen) {
	return construct_local_link((const http_t *)conn, buf, buflen, NULL, -1, NULL);
}

static void redirect_to_https_port(http_t *conn, int port) {
	char target_url[MG_BUF_LEN];
	int truncated = 0;
	string_t expect_proto =
		(conn->req.proto == PROTOCOL_WEBSOCKET) ? "wss" : "https";

	/* Use "308 Permanent Redirect" */
	int redirect_code = 308;

	/* In any case, close the current connection */
	conn->req.must_close = 1;

	/* Send host, port, uri and (if it exists) ?query_string */
	if (construct_local_link(
		(const http_t *)conn, target_url, sizeof(target_url), expect_proto, port, NULL)
		< 0) {
		truncated = 1;
	} else if (conn->req.query_string != NULL) {
		size_t slen1 = strlen(target_url);
		size_t slen2 = strlen(conn->req.query_string);
		if ((slen1 + slen2 + 2) < sizeof(target_url)) {
			target_url[slen1] = '?';
			memcpy(target_url + slen1 + 1,
				conn->req.query_string,
				slen2);
			target_url[slen1 + slen2 + 1] = 0;
		} else {
			truncated = 1;
		}
	}

	/* Check overflow in location buffer (will not occur if MG_BUF_LEN
	 * is used as buffer size) */
	if (truncated) {
		http_error(conn, 500, "%s", "Redirect URL too long");
		return;
	}

	/* Use redirect helper function */
	http_redirect(conn, target_url, redirect_code);
}


static int get_first_ssl_listener_index(const http_ini_t *ctx) {
	unsigned int i;
	int idx = -1;
	if (ctx) {
		for (i = 0; ((idx == -1) && (i < ctx->num_listening_sockets)); i++) {
			idx = ctx->listening_sockets[i].has_ssl ? ((int)(i)) : -1;
		}
	}

	return idx;
}

#undef in

/* Pre-process URIs according to RFC + protect against directory disclosure
 * attacks by removing '..', excessive '/' and '\' characters */
static void remove_dot_segments(char *inout) {
	/* Windows backend protection
	 * (https://tools.ietf.org/html/rfc3986#section-7.3): Replace backslash
	 * in URI by slash */
	char *out_end = inout;
	char *in = inout;

	if (!in) {
		/* Param error. */
		return;
	}

	while (*in) {
		if (*in == '\\') {
			*in = '/';
		}
		in++;
	}

	/* Algorithm "remove_dot_segments" from
	 * https://tools.ietf.org/html/rfc3986#section-5.2.4 */
	/* Step 1:
	 * The input buffer is initialized.
	 * The output buffer is initialized to the empty string.
	 */
	in = inout;

	/* Step 2:
	 * While the input buffer is not empty, loop as follows:
	 */
	/* Less than out_end of the inout buffer is used as output, so keep
	 * condition: out_end <= in */
	while (*in) {
		/* Step 2a:
		 * If the input buffer begins with a prefix of "../" or "./",
		 * then remove that prefix from the input buffer;
		 */
		if (str_case_equal(in, "../", 3)) {
			in += 3;
		} else if (str_case_equal(in, "./", 2)) {
			in += 2;
		}
		/* otherwise */
		/* Step 2b:
		 * if the input buffer begins with a prefix of "/./" or "/.",
		 * where "." is a complete path segment, then replace that
		 * prefix with "/" in the input buffer;
		 */
		else if (str_case_equal(in, "/./", 3)) {
			in += 2;
		} else if (!strcmp(in, "/.")) {
			in[1] = 0;
		}
		/* otherwise */
		/* Step 2c:
		 * if the input buffer begins with a prefix of "/../" or "/..",
		 * where ".." is a complete path segment, then replace that
		 * prefix with "/" in the input buffer and remove the last
		 * segment and its preceding "/" (if any) from the output
		 * buffer;
		 */
		else if (str_case_equal(in, "/../", 4)) {
			in += 3;
			if (inout != out_end) {
				/* remove last segment */
				do {
					out_end--;
				} while ((inout != out_end) && (*out_end != '/'));
			}
		} else if (!strcmp(in, "/..")) {
			in[1] = 0;
			if (inout != out_end) {
				/* remove last segment */
				do {
					out_end--;
				} while ((inout != out_end) && (*out_end != '/'));
			}
		}
		/* otherwise */
		/* Step 2d:
		 * if the input buffer consists only of "." or "..", then remove
		 * that from the input buffer;
		 */
		else if (!strcmp(in, ".") || !strcmp(in, "..")) {
			*in = 0;
		}
		/* otherwise */
		/* Step 2e:
		 * move the first path segment in the input buffer to the end of
		 * the output buffer, including the initial "/" character (if
		 * any) and any subsequent characters up to, but not including,
		 * the next "/" character or the end of the input buffer.
		 */
		else {
			do {
				*out_end = *in;
				out_end++;
				in++;
			} while ((*in != 0) && (*in != '/'));
		}
	}

	/* Step 3:
	 * Finally, the output buffer is returned as the result of
	 * remove_dot_segments.
	 */
	/* Terminate output */
	*out_end = 0;

	/* For Windows, the files/folders "x" and "x." (with a dot but without
	 * extension) are identical. Replace all "./" by "/" and remove a "." at
	 * the end. Also replace all "//" by "/". Repeat until there is no "./"
	 * or "//" anymore.
	 */
	out_end = in = inout;
	while (*in) {
		if (*in == '.') {
			/* remove . at the end or preceding of / */
			char *in_ahead = in;
			do {
				in_ahead++;
			} while (*in_ahead == '.');
			if (*in_ahead == '/') {
				in = in_ahead;
				if ((out_end != inout) && (out_end[-1] == '/')) {
					/* remove generated // */
					out_end--;
				}
			} else if (*in_ahead == 0) {
				in = in_ahead;
			} else {
				do {
					*out_end++ = '.';
					in++;
				} while (in != in_ahead);
			}
		} else if (*in == '/') {
			/* replace // by / */
			*out_end++ = '/';
			do {
				in++;
			} while (*in == '/');
		} else {
			*out_end++ = *in;
			in++;
		}
	}
	*out_end = 0;
}

/* Look at the "path" extension and figure what mime type it has.
 * Store mime type in the vector. */
static void get_mime_type(http_t *conn, string_t path, struct vec *vec) {
	struct vec ext_vec, mime_vec;
	string_t list, *ext;
	size_t path_len;

	path_len = strlen(path);

	if ((conn == NULL) || (vec == NULL)) {
		if (vec != NULL) {
			memset(vec, '\0', sizeof(struct vec));
		}
		return;
	}

	/* Scan user-defined mime types first, in case user wants to
	 * override default mime types. */
	list = conn->domain->config[EXTRA_MIME_TYPES];
	while ((list = http_next_option(list, &ext_vec, &mime_vec)) != NULL) {
		/* ext now points to the path suffix */
		ext = path + path_len - ext_vec.len;
		if (str_case_equal(ext, ext_vec.ptr, ext_vec.len)) {
			*vec = mime_vec;
			return;
		}
	}

	vec->ptr = http_get_builtin_mime_type(path);
	vec->len = strlen(vec->ptr);
}

void http_send_file_data(http_t *conn, struct file *filep,
	int64_t offset, int64_t len, int no_buffering) {
	char buf[MG_BUF_LEN];
	int to_read, num_read, num_written;
	int64_t size;

	if (!filep || !conn) {
		return;
	}

	/* Sanity check the offset */
	size = (filep->size > INT64_MAX) ? INT64_MAX : (int64_t)(filep->size);
	offset = (offset < 0) ? 0 : ((offset > size) ? size : offset);
	if (len > 0 && filep->membuf != NULL && size > 0) {
		if (len > size - offset)
			len = size - offset;

		http_write(conn, filep->membuf + offset, (size_t)len);
	} else if (len > 0 && filep->fp != NULL) {
		/* file stored on disk */
		if ((offset > 0) && (fseek(filep->fp, offset, SEEK_SET) != 0)) {
			http_logger(DEBUG_ERROR, conn, "%s: fseek() failed: %s", __func__, strerror(os_geterror()));
			http_error(conn, 500, "%s", "Error: Unable to access file at requested position.");
		} else {
			while (len > 0) {
				/* Calculate how much to read from the file into the buffer. */
				/* If no_buffering is set, we should not wait until the
				 * CGI->Server buffer is filled, but send everything
				 * immediately. In theory buffering could be turned off using
				 * setbuf(filep->fp, NULL);
				 * setvbuf(filep->fp, NULL, _IONBF, 0);
				 * but in practice this does not work. A "Linux only" solution
				 * may be to use select(). The only portable way is to read byte
				 * by byte, but this is quite inefficient from a performance
				 * point of view. */
				to_read = no_buffering ? 1 : sizeof(buf);
				if ((int64_t)to_read > len) {
					to_read = (int)len;
				}

				/* Read from file, exit the loop on error */
				if ((num_read = fs_read(fileno(filep->fp), buf, to_read)) <= 0) {
					break;
				}

				/* Send read bytes to the client, exit the loop on error */
				if ((num_written = http_write(conn, buf, (size_t)num_read))
					!= num_read) {
					break;
				}

				/* Both read and were successful, adjust counters */
				len -= num_written;
			}
		}
	}
}

static int parse_range_header(string_t header, int64_t *a, int64_t *b) {
	return sscanf(header,
		"bytes=%" INT64_FMT "-%" INT64_FMT,
		a,
		b); // NOLINT(cert-err34-c) 'sscanf' used to convert a string
			// to an integer value, but function will not report
			// conversion errors; consider using 'strtol' instead
}

void handle_static_file_request(http_t *conn, string_t path, struct file *filep,
	string_t mime_type, string_t additional_headers) {
	char lm[64], etag[64];
	char range[128]; /* large enough, so there will be no overflow */
	string_t range_hdr;
	int64_t cl, r1, r2;
	struct vec mime_vec;
	int n, truncated;
	char gz_path[UTF8_PATH_MAX];
	string_t encoding = 0;
	int is_head_request;

	/* Compression is allowed, unless there is a reason not to use
	 * compression. If the file is already compressed, too small or a
	 * "range" request was made, on the fly compression is not possible. */
	int allow_on_the_fly_compression = 1;
	if ((conn == NULL) || (conn->domain == NULL) || (filep == NULL)) {
		return;
	}

	is_head_request = !strcmp(conn->method, "HEAD");

	if (mime_type == NULL) {
		get_mime_type(conn, path, &mime_vec);
	} else {
		mime_vec.ptr = mime_type;
		mime_vec.len = strlen(mime_type);
	}

	if (filep->size > INT64_MAX) {
		http_error(conn, 500, "Error: File size is too large to send\n%" INT64_FMT, filep->size);
		return;
	}

	cl = (int64_t)filep->size;
	conn->status = 200;
	range[0] = '\0';

	/* if this file is in fact a pre-gzipped file, rewrite its filename
	 * it's important to rewrite the filename after resolving
	 * the mime type from it, to preserve the actual file's type */
	if (!conn->req.accept_gzip) {
		allow_on_the_fly_compression = 0;
	}

	/* Check if there is a range header */
	range_hdr = http_get_header(conn, "Range");

	/* For gzipped files, add *.gz */
	if (filep->gzipped) {
		http_snprintf(conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", path);
		if (truncated) {
			http_error(conn,
				500,
				"Error: Path of zipped file too long (%s)",
				path);
			return;
		}

		path = gz_path;
		encoding = "gzip";

		/* File is already compressed. No "on the fly" compression. */
		allow_on_the_fly_compression = 0;
	} else if ((conn->req.accept_gzip) && (range_hdr == NULL)
		&& (filep->size >= MG_FILE_COMPRESSION_SIZE_LIMIT)) {
		struct file file_stat;
		http_snprintf(conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", path);
		if (!truncated && http_stat(conn, gz_path, &file_stat)
			&& !file_stat.is_directory) {
			file_stat.gzipped = 1;
			filep = &file_stat;
			cl = (int64_t)filep->size;
			path = gz_path;
			encoding = "gzip";

			/* File is already compressed. No "on the fly" compression. */
			allow_on_the_fly_compression = 0;
		}
	}

	if (!http_fopen(conn->ctx, conn, path, "rb", filep)) {
		http_error(conn, 500, "Error: Cannot open file\nfopen(%s): %s",	path, strerror(os_geterror()));
		return;
	}

	http_set_close_on_exec(fd2socket(fileno(filep->fp)));
	/* If "Range" request was made: parse header, send only selected part
	 * of the file. */
	r1 = r2 = 0;
	if ((range_hdr != NULL)
		&& ((n = parse_range_header(range_hdr, &r1, &r2)) > 0) && (r1 >= 0)
		&& (r2 >= 0)) {
		/* actually, range requests don't play well with a pre-gzipped
		 * file (since the range is specified in the uncompressed space) */
		if (filep->gzipped) {
			http_error(
				conn,
				416, /* 416 = Range Not Satisfiable */
				"%s",
				"Error: Range requests in gzipped files are not supported");
			(void)http_fclose(&filep); /* ignore error on read only file */
			return;
		}
		conn->status = 206;
		cl = (n == 2) ? (((r2 > cl) ? cl : r2) - r1 + 1) : (cl - r1);
		http_snprintf(conn,
			NULL, /* range buffer is big enough */
			range,
			sizeof(range),
			"bytes "
			"%" INT64_FMT "-%" INT64_FMT "/%" INT64_FMT,
			r1,
			r1 + cl - 1,
			filep->size);

		/* Do not compress ranges. */
		allow_on_the_fly_compression = 0;
	}

	/* Do not compress small files. Small files do not benefit from file
	 * compression, but there is still some overhead. */
	if (filep->size < MG_FILE_COMPRESSION_SIZE_LIMIT) {
		/* File is below the size limit. */
		allow_on_the_fly_compression = 0;
	}

	/* Prepare Etag, and Last-Modified headers. */
	http_gmt_time_str(lm, sizeof(lm), &filep->last_modified);
	http_construct_etag(conn, etag, sizeof(etag), (const struct file *)filep);

	/* Create 2xx (200, 206) response */
	http_response_start(conn, conn->status);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_cors_header(conn);
	http_response_add(conn,	"Content-Type",	mime_vec.ptr, (int)mime_vec.len);
	http_response_add(conn, "Last-Modified", lm, -1);
	http_response_add(conn, "Etag", etag, -1);

	/* On the fly compression allowed */
	if (allow_on_the_fly_compression) {
		/* For on the fly compression, we don't know the content size in
		 * advance, so we have to use chunked encoding */
		encoding = "gzip";
		if (conn->req.proto == PROTOCOL_HTTP1) {
			/* HTTP/2 is always using "chunks" (frames) */
			http_response_add(conn, "Transfer-Encoding", "chunked", -1);
		}
	} else {
		/* Without on-the-fly compression, we know the content-length
		 * and we can use ranges (with on-the-fly compression we cannot).
		 * So we send these response headers only in this case. */
		char len[32];
		int trunc = 0;
		http_snprintf(conn, &trunc, len, sizeof(len), "%" INT64_FMT, cl);
		if (!trunc) {
			http_response_add(conn, "Content-Length", len, -1);
		}

		http_response_add(conn, "Accept-Ranges", "bytes", -1);
	}

	if (encoding) {
		http_response_add(conn, "Content-Encoding", encoding, -1);
	}
	if (range[0] != 0) {
		http_response_add(conn, "Content-Range", range, -1);
	}

	/* The code above does not add any header starting with X- to make
	 * sure no one of the additional_headers is included twice */
	if ((additional_headers != NULL) && (*additional_headers != 0)) {
		http_response_multi(conn, additional_headers);
	}

	/* Send all headers */
	http_response_send(conn);

	if (!is_head_request) {
		if (allow_on_the_fly_compression) {
			/* Compress and send */
			http_compressed_data(conn, filep);
		} else {
			/* Send file directly */
			http_send_file_data(conn, filep, r1, cl, 0); /* send static file */
		}
	}
	(void)http_fclose(&filep); /* ignore error on read only file */
}

void handle_file_based_request(http_t *conn,
	string_t path,
	struct file *file) {
	int cgi_config_idx, inc, max;

	if (!conn || !conn->domain) {
		return;
	}

#if defined(USE_DUKTAPE)
	if (match_prefix_strlen(conn->domain->config[DUKTAPE_SCRIPT_EXTENSIONS],
		path)
		> 0) {
		if (is_in_script_path(conn, path)) {
			/* Call duktape to generate the page */
			mg_exec_duktape_script(conn, path);
		} else {
			/* Script was in an illegal path */
			mg_send_http_error(conn, 403, "%s", "Forbidden");
		}
		return;
	}
#endif

	inc = CGI2_EXTENSIONS - CGI_EXTENSIONS;
	max = PUT_DELETE_PASSWORDS_FILE - CGI_EXTENSIONS;
	for (cgi_config_idx = 0; cgi_config_idx < max; cgi_config_idx += inc) {
		if (conn->domain->config[CGI_EXTENSIONS + cgi_config_idx] != NULL) {
			if (match_prefix_strlen(
				conn->domain->config[CGI_EXTENSIONS + cgi_config_idx],
				path)
	> 0) {
				if (is_in_script_path(conn, path)) {
					/* CGI scripts may support all HTTP methods */
					handle_cgi_request(conn, path, cgi_config_idx);
				} else {
					/* Script was in an illegal path */
					http_error(conn, 403, "%s", "Forbidden");
				}
				return;
			}
		}
	}

	if (match_prefix_strlen(conn->domain->config[SSI_EXTENSIONS], path) > 0) {
		if (is_in_script_path(conn, path)) {
			handle_ssi_file_request(conn, path, file);
		} else {
			/* Script was in an illegal path */
			http_error(conn, 403, "%s", "Forbidden");
		}
		return;
	}

	if ((!conn->req.in_error_handler) && is_not_modified(conn, &file)) {
		/* Send 304 "Not Modified" - this must not send any body data */
		handle_not_modified_static_file_request(conn, file);
		return;
	}

	handle_static_file_request(conn, path, file, NULL, NULL);
}

/* Return True if we should reply 304 Not Modified. */
int is_not_modified(const http_t *conn, const struct file *filestat) {
	char etag[64];
	string_t ims = http_get_header(conn, "If-Modified-Since");
	string_t inm = http_get_header(conn, "If-None-Match");
	http_construct_etag(conn, etag, sizeof(etag), filestat);

	if (inm) {
		return str_is_caste(etag, inm);
	}
	if (ims) {
		return (filestat->last_modified <= parse_date_string(ims));
	}
	return 0;
}

void handle_not_modified_static_file_request(http_t *conn, struct file *filep) {
	char lm[64], etag[64];

	if ((conn == NULL) || (filep == NULL)) {
		return;
	}

	http_gmt_time_str(lm, sizeof(lm), &filep->last_modified);
	http_construct_etag(conn, etag, sizeof(etag), (const struct file *)filep);

	/* Create 304 "not modified" response */
	http_response_start(conn, 304);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn, "Last-Modified", lm, -1);
	http_response_add(conn, "Etag", etag, -1);

	/* Send all headers */
	http_response_send(conn);
}

static void discard_unread_request_data(http_t *conn) {
	char buf[MG_BUF_LEN];
	while (http_read(conn, buf, sizeof(buf)) > 0)
		;
}

static int should_decode_url(const http_t *conn) {
	if (!conn || !conn->domain) {
		return false;
	}

	return (str_is_case(conn->domain->config[DECODE_URL], "yes"));
}


static int should_decode_query_string(const http_t *conn) {
	if (!conn || !conn->domain) {
		return false;
	}

	return (str_is_case(conn->domain->config[DECODE_QUERY_STRING], "yes"));
}

/* Decrement recount of handler. conn must not be NULL, handler_info may be NULL */
static void release_handler_ref(http_t *conn, struct http_cb_info *handler_info) {
	if (handler_info != NULL) {
		/* Use context lock for ref counter */
		atomic_lock(conn->ctx->nonce_mutex);
		handler_info->refcount--;
		atomic_unlock(conn->ctx->nonce_mutex);
	}
}

void http_handle_request(http_t *conn) {
	httpie_t *ri = &conn->req;
	char path[UTF8_PATH_MAX];
	int uri_len, ssl_index;
	int is_found = 0, is_script_resource = 0, is_websocket_request = 0,
		is_put_or_delete_request = 0, is_callback_resource = 0,
		is_template_text_file = 0, is_webdav_request = 0;
	int i;
	struct file file = STRUCT_FILE_INITIALIZER;
	route_cb callback_handler = NULL;
	struct http_cb_info *handler_info = NULL;
	struct ws_subprotocols_s *subprotocols;
	ws_connect_cb ws_connect_handler = NULL;
	ws_ready_cb ws_ready_handler = NULL;
	ws_data_cb ws_data_handler = NULL;
	ws_close_cb ws_close_handler = NULL;
	void *callback_data = NULL;
	auth_cb auth_handler = NULL;
	void *auth_callback_data = NULL;
	int handler_type;
	time_t curtime = time(NULL);
	char date[64];
	char *tmp;

	path[0] = 0;

	/* 0. Reset internal state (required for HTTP/2 proxy) */
	conn->req.state = 0;

	/* 1. get the request url */
	/* 1.1. split into url and query string */
	if ((conn->req.query_string = strchr(conn->url_to, '?'))
		!= NULL) {
		*((char *)conn->req.query_string++) = '\0';
	}

	/* 1.2. do a https redirect, if required. Do not decode URIs yet. */
	if (!conn->client.has_ssl && conn->client.has_redir) {
		ssl_index = get_first_ssl_listener_index((const http_ini_t *)conn->ctx);
		if (ssl_index >= 0) {
			int port = (int)ntohs(USA_IN_PORT_UNSAFE(
				&(conn->ctx->listening_sockets[ssl_index].lsa)));
			redirect_to_https_port(conn, port);
		} else {
			/* A http to https forward port has been specified,
			 * but no https port to forward to. */
			http_error(conn, 503, "%s", "Error: SSL forward not configured properly");
			http_logger(DEBUG_ERROR, conn, "%s", "Can not redirect to SSL, no SSL port available");
		}
		return;
	}


	/* 1.3. decode url (if config says so) */
	if (should_decode_url(conn)) {
		url_decode_in_place((char *)ri->local_uri);
	}

	/* URL decode the query-string only if explicitly set in the configuration */
	if (conn->req.query_string) {
		if (should_decode_query_string(conn)) {
			url_decode_in_place((char *)conn->req.query_string);
		}
	}

	/* 1.4. clean URIs, so a path like allowed_dir/../forbidden_file is not
	 * possible. The fact that we cleaned the URI is stored in that the
	 * pointer to ri->local_ur and ri->local_uri_raw are now different.
	 * ri->local_uri_raw still points to memory allocated in
	 * worker_thread_run(). ri->local_uri is private to the request so we
	 * don't have to use preallocated memory here. */
	tmp = str_dup_ex(ri->local_uri);
	if (!tmp) {
		/* Out of memory. We cannot do anything reasonable here. */
		return;
	}

	remove_dot_segments(tmp);
	ri->local_uri = tmp;
	/* Only compute if later code can actually use it */
	/* Cache URI length once; recompute only if the buffer changes later. */
	uri_len = (int)strlen(ri->local_uri);

	/* step 1. completed, the url is known now */
	//DEBUG_TRACE("REQUEST: %s %s", conn->method, ri->local_uri);

	/* 2. if this ip has limited speed, set it for this connection */
	//conn->throttle = set_throttle(conn->domain->config[THROTTLE], &conn->client.rsa, ri->local_uri);

	/* 3. call a "handle everything" callback, if registered */
	if (conn->ctx->callbacks.start != NULL) {
		/* Note the "start" function is called before an authorization check.
		 * If an authorization check is required, use a request_handler instead. */
		i = conn->ctx->callbacks.start(conn);
		if (i > 0) {
			/* callback already processed the request. Store the
			return value as a status code for the access log. */
			conn->status = i;
			if (!conn->req.must_close) {
				discard_unread_request_data(conn);
			}
			//DEBUG_TRACE("%s", "begin_request handled request");
			return;
		} else if (i == 0) {
			/* `httpie` should process the request */
		} else {
			/* unspecified - may change with the next version */
			//DEBUG_TRACE("%s", "done (undocumented behavior)");
			return;
		}
	}

	/* request not yet handled by a handler or redirect, so the request
	 * is processed here */

	/* 4. Check for CORS preflight requests and handle them (if configured).
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
	 */
	if (!strcmp(conn->method, "OPTIONS")) {
		/* Send a response to CORS preflights only if
		 * access_control_allow_methods is not NULL and not an empty string.
		 * In this case, scripts can still handle CORS. */
		string_t cors_meth_cfg =
			conn->domain->config[ACCESS_CONTROL_ALLOW_METHODS];
		string_t cors_orig_cfg =
			conn->domain->config[ACCESS_CONTROL_ALLOW_ORIGIN];
		string_t cors_origin = http_get_header(conn, "Origin");
		string_t cors_acrm = http_get_header(conn, "Access-Control-Request-Method");
		string_t cors_repl_asterisk_with_orig_cfg =
			conn->domain->config[REPLACE_ASTERISK_WITH_ORIGIN];

		/* Todo: check if cors_origin is in cors_orig_cfg.
		 * Or, let the client check this. */

		if ((cors_meth_cfg != NULL) && (*cors_meth_cfg != 0)
			&& (cors_orig_cfg != NULL) && (*cors_orig_cfg != 0)
			&& (cors_origin != NULL) && (cors_acrm != NULL)
			&& (cors_repl_asterisk_with_orig_cfg != NULL)
			&& (*cors_repl_asterisk_with_orig_cfg != 0)) {
			int cors_repl_asterisk_with_orig =
				str_is_case(cors_repl_asterisk_with_orig_cfg, "yes");

			/* This is a valid CORS preflight, and the server is configured
			 * to handle it automatically. */
			string_t cors_acrh = http_get_header(conn, "Access-Control-Request-Headers");
			string_t cors_cred_cfg =
				conn->domain->config[ACCESS_CONTROL_ALLOW_CREDENTIALS];
			string_t cors_exphdr_cfg =
				conn->domain->config[ACCESS_CONTROL_EXPOSE_HEADERS];

			http_gmt_time_str(date, sizeof(date), &curtime);
			http_printf(conn,
				"HTTP/1.1 200 OK\r\n"
				"Date: %s\r\n"
				"Access-Control-Allow-Origin: %s\r\n"
				"Access-Control-Allow-Methods: %s\r\n"
				"Content-Length: 0\r\n"
				"Connection: %s\r\n",
				date,
				(cors_repl_asterisk_with_orig == 0
					&& cors_orig_cfg[0] == '*')
				? cors_origin
				: cors_orig_cfg,
				((cors_meth_cfg[0] == '*') ? cors_acrm : cors_meth_cfg),
				http_suggest_connection_header(conn));

			if (cors_cred_cfg && *cors_cred_cfg) {
				http_printf(conn,
					"Access-Control-Allow-Credentials: %s\r\n",
					cors_cred_cfg);
			}

			if (cors_exphdr_cfg && *cors_exphdr_cfg) {
				http_printf(conn,
					"Access-Control-Expose-Headers: %s\r\n",
					cors_exphdr_cfg);
		}

			if (cors_acrh || (cors_cred_cfg && *cors_cred_cfg)) {
				/* CORS request is asking for additional headers */
				string_t cors_hdr_cfg =
					conn->domain->config[ACCESS_CONTROL_ALLOW_HEADERS];

				if ((cors_hdr_cfg != NULL) && (*cors_hdr_cfg != 0)) {
					/* Allow only if access_control_allow_headers is
					 * not NULL and not an empty string. If this
					 * configuration is set to *, allow everything.
					 * Otherwise this configuration must be a list
					 * of allowed HTTP header names. */
					http_printf(conn,
						"Access-Control-Allow-Headers: %s\r\n",
						((cors_hdr_cfg[0] == '*') ? cors_acrh
							: cors_hdr_cfg));
				}
			}
			http_printf(conn, "Access-Control-Max-Age: 60\r\n");
			http_printf(conn, "\r\n");
			//DEBUG_TRACE("%s", "OPTIONS done");
			return;
	}
}

	/* 5. interpret the url to find out how the request must be handled
	*/

	/* 5.1. first test, if the request targets the regular http(s)://
	* protocol namespace or the websocket ws(s):// protocol namespace.
	*/
	is_websocket_request = (conn->req.proto == PROTOCOL_WEBSOCKET);
	handler_type = is_websocket_request ? WEBSOCKET_HANDLER : REQUEST_HANDLER;
	if (is_websocket_request) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
	}

	/* 5.2. check if the request will be handled by a callback */
	if (http_get_request_handler(conn, handler_type, &callback_handler,
		&subprotocols, &ws_connect_handler, &ws_ready_handler,
		&ws_data_handler, &ws_close_handler, NULL, &callback_data, &handler_info)) {
		/* 5.2.1. A callback will handle this request. All requests
		* handled by a callback have to be considered as requests
		* to a script resource. */
		is_callback_resource = 1;
		is_script_resource = 1;
		is_put_or_delete_request = is_put_or_delete_method(conn);
		/* Never handle a C callback according to File WebDav rules,
		 * even if it is a webdav method */
		is_webdav_request = 0; /* is_civetweb_webdav_method(conn); */
	} else {
no_callback_resource:
		/* 5.2.2. No callback is responsible for this request. The URI
		 * addresses a file based resource (static content or Lua/cgi
		 * scripts in the file system). */
		is_callback_resource = 0;
		http_interpret_uri(conn,
			path,
			sizeof(path),
			&file,
			&is_found,
			&is_script_resource,
			&is_websocket_request,
			&is_put_or_delete_request,
			&is_webdav_request,
			&is_template_text_file);
	}

	/* 5.3. A webdav request (PROPFIND/PROPPATCH/LOCK/UNLOCK) */
	if (is_webdav_request) {
		/* TODO: Do we need a config option? */
		string_t webdav_enable = conn->domain->config[ENABLE_WEBDAV];
		if (webdav_enable[0] != 'y') {
			http_error(conn,
				405,
				"%s method not allowed",
				conn->method);
			//DEBUG_TRACE("%s", "webdav rejected");
			return;
		}
	}

	/* 6. authorization check */
	/* 6.1. a custom authorization handler is installed */
	if (http_get_request_handler(conn, AUTH_HANDLER, NULL, NULL, NULL, NULL,
		NULL, NULL, &auth_handler, &auth_callback_data, NULL)) {
		if (!auth_handler(conn, auth_callback_data)) {
			/* Callback handler will not be used anymore. Release it */
			release_handler_ref(conn, handler_info);
			//DEBUG_TRACE("%s", "auth handler rejected request");
			return;
		}
	} else if (is_put_or_delete_request && !is_script_resource
		&& !is_callback_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		/* 6.2. this request is a PUT/DELETE to a real file */
		/* 6.2.1. thus, the server must have real files */
		if (conn->domain->config[DOCUMENT_ROOT] == NULL
			|| conn->domain->config[PUT_DELETE_PASSWORDS_FILE] == NULL) {
			/* This code path will not be called for request handlers */
			//DEBUG_ASSERT(handler_info == NULL);

			/* This server does not have any real files, thus the
			 * PUT/DELETE methods are not valid. */
			http_error(conn,
				405,
				"%s method not allowed",
				conn->method);
			//DEBUG_TRACE("%s", "all file based put/delete requests rejected");
			return;
		}

		/* 6.2.2. Check if put authorization for static files is
		 * available.
		 */
		if (!is_authorized_for_put(conn)) {
			send_authorization_request(conn, NULL);
			//DEBUG_TRACE("%s", "file write needs authorization");
			return;
		}
	} else {
		/* 6.3. This is either a OPTIONS, GET, HEAD or POST request,
		 * or it is a PUT or DELETE request to a resource that does not
		 * correspond to a file. Check authorization. */
		if (!check_authorization(conn, path)) {
			send_authorization_request(conn, NULL);

			/* Callback handler will not be used anymore. Release it */
			release_handler_ref(conn, handler_info);
			//DEBUG_TRACE("%s", "access authorization required");
			return;
		}
	}

	/* request is authorized or does not need authorization */

	/* 7. check if there are request handlers for this uri */
	if (is_callback_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		if (!is_websocket_request) {
			i = callback_handler(conn, callback_data);

			/* Callback handler will not be used anymore. Release it */
			release_handler_ref(conn, handler_info);

			if (i > 0) {
				/* Do nothing, callback has served the request. Store
				 * then return value as status code for the log and discard
				 * all data from the client not used by the callback. */
				conn->status = i;
				if (!conn->req.must_close) {
					discard_unread_request_data(conn);
				}
			} else {
				/* The handler did NOT handle the request. */
				/* Some proper reactions would be:
				 * a) close the connections without sending anything
				 * b) send a 404 not found
				 * c) try if there is a file matching the URI
				 * It would be possible to do a, b or c in the callback
				 * implementation, and return 1 - we cannot do anything
				 * here, that is not possible in the callback.
				 *
				 * TODO: What would be the best reaction here?
				 * (Note: The reaction may change, if there is a better
				 * idea.)
				 */

				/* For the moment, use option c: We look for a proper file,
				 * but since a file request is not always a script resource,
				 * the authorization check might be different. */
				callback_handler = NULL;

				/* Here we are at a dead end:
				 * According to URI matching, a callback should be
				 * responsible for handling the request,
				 * we called it, but the callback declared itself
				 * not responsible.
				 * We use a goto here, to get out of this dead end,
				 * and continue with the default handling.
				 * A goto here is simpler and better to understand
				 * than some curious loop. */
				goto no_callback_resource;
			}
		} else {
			handle_websocket_request(conn,
				path,
				is_callback_resource,
				subprotocols,
				ws_connect_handler,
				ws_ready_handler,
				ws_data_handler,
				ws_close_handler,
				callback_data);
		}
		DEBUG_TRACE("%s", "websocket handling done");
		return;
	}

	/* 8. handle websocket requests */
	if (is_websocket_request) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		if (is_script_resource) {

			if (is_in_script_path(conn, path)) {
				/* Websocket Lua script */
				handle_websocket_request(conn,
					path,
					0 /* Lua Script */,
					NULL,
					NULL,
					NULL,
					NULL,
					NULL,
					conn->ctx->user_data);
			} else {
				/* Script was in an illegal path */
				http_error(conn, 403, "%s", "Forbidden");
			}
		} else {
			http_error(conn, 404, "%s", "Not found");
		}
		DEBUG_TRACE("%s", "websocket script done");
		return;
	} else
	/* 9b. This request is either for a static file or resource handled
	 * by a script file. Thus, a DOCUMENT_ROOT must exist. */
		if (conn->domain->config[DOCUMENT_ROOT] == NULL) {
			http_error(conn, 404, "%s", "Not Found");
			DEBUG_TRACE("%s", "no document root available");
			return;
		}

		/* 10. Request is handled by a script */
	if (is_script_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		handle_file_based_request(conn, path, &file);
		DEBUG_TRACE("%s", "script handling done");
		return;
	}

	/* Request was not handled by a callback or script. It will be
	 * handled by a server internal method. */

	/* 11. Handle put/delete/mkcol requests */
	if (is_put_or_delete_request) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		/* 11.1. PUT method */
		if (!strcmp(conn->method, "PUT")) {
			put_file(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.2. DELETE method */
		if (!strcmp(conn->method, "DELETE")) {
			delete_file(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.3. MKCOL method */
		if (!strcmp(conn->method, "MKCOL")) {
			dav_mkcol(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.4. MOVE method */
		if (!strcmp(conn->method, "MOVE")) {
			dav_move_file(conn, path, 0);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		if (!strcmp(conn->method, "COPY")) {
			dav_move_file(conn, path, 1);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.5. LOCK method */
		if (!strcmp(conn->method, "LOCK")) {
			dav_lock_file(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.6. UNLOCK method */
		if (!strcmp(conn->method, "UNLOCK")) {
			dav_unlock_file(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.7. PROPPATCH method */
		if (!strcmp(conn->method, "PROPPATCH")) {
			dav_proppatch(conn, path);
			DEBUG_TRACE("handling %s request to %s done",
				conn->method,
				path);
			return;
		}
		/* 11.8. Other methods, e.g.: PATCH
		 * This method is not supported for static resources,
		 * only for scripts (Lua, CGI) and callbacks. */
		http_error(conn,
			405,
			"%s method not allowed",
			conn->method);
		DEBUG_TRACE("method %s on %s is not supported",
			conn->method,
			path);
		return;
	}

	/* 11. File does not exist, or it was configured that it should be
	 * hidden */
	if (!is_found || (http_must_hide_file(conn->ctx, path))) {
		http_error(conn, 404, "%s", "Not found");
		DEBUG_TRACE("handling %s request to %s: file not found",
			conn->method,
			path);
		return;
	}

	/* 12. Directory uris should end with a slash */
	if (file.is_directory && (uri_len > 0)
		&& (ri->local_uri[uri_len - 1] != '/')) {


		/* Path + server root */
		size_t buflen = UTF8_PATH_MAX * 2 + 2;
		char *new_path;

		if (ri->query_string) {
			buflen += strlen(ri->query_string);
		}
		new_path = (char *)malloc(buflen);
		if (!new_path) {
			http_error(conn, 500, "out or memory");
		} else {
			http_get_request_link(conn, new_path, buflen - 1);

			size_t len = strlen(new_path);
			if (len + 1 < buflen) {
				new_path[len] = '/';
				new_path[len + 1] = '\0';
				len++;
			}

			if (ri->query_string) {
				if (len + 1 < buflen) {
					new_path[len] = '?';
					new_path[len + 1] = '\0';
					len++;
				}

				/* Append with size of space left for query string + null
				 * terminator */
				size_t max_append = buflen - len - 1;
				strncat(new_path, ri->query_string, max_append);
			}

			http_redirect(conn, new_path, 301);
			free(new_path);
		}
		DEBUG_TRACE("%s request to %s: directory redirection sent",
			conn->method,
			path);
		return;
	}

	/* 13. Handle other methods than GET/HEAD */
	/* 13.1. Handle PROPFIND */
	if (!strcmp(conn->method, "PROPFIND")) {
		handle_propfind(conn, path, &file);
		DEBUG_TRACE("handling %s request to %s done", conn->method, path);
		return;
	}
	/* 13.2. Handle OPTIONS for files */
	if (!strcmp(conn->method, "OPTIONS")) {
		/* This standard handler is only used for real files.
		 * Scripts should support the OPTIONS method themselves, to allow a
		 * maximum flexibility.
		 * Lua and CGI scripts may fully support CORS this way (including
		 * preflights). */
		send_options(conn);
		DEBUG_TRACE("handling %s request to %s done", conn->method, path);
		return;
	}
	/* 13.3. everything but GET and HEAD (e.g. POST) */
	if ((0 != strcmp(conn->method, "GET"))
		&& (0 != strcmp(conn->method, "HEAD"))) {
		http_error(conn,
			405,
			"%s method not allowed",
			conn->method);
		DEBUG_TRACE("handling %s request to %s done", conn->method, path);
		return;
	}

	/* 14. directories */
	if (file.is_directory) {
		/* Substitute files have already been handled above. */
		/* Here we can either generate and send a directory listing,
		 * or send an "access denied" error. */
		if (!mg_strcasecmp(conn->domain->config[ENABLE_DIRECTORY_LISTING],
			"yes")) {
			handle_directory_request(conn, path);
		} else {
			http_error(conn,
				403,
				"%s",
				"Error: Directory listing denied");
		}
		DEBUG_TRACE("handling %s request to %s done", conn->method, path);
		return;
	}

	/* 15. Files with search/replace patterns: LSP and SSI */
	if (is_template_text_file) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			//DEBUG_TRACE("%s", "must use HTTP/1.x");
			//return;
		}
		handle_file_based_request(conn, path, &file);
		//DEBUG_TRACE("handling %s request to %s done (template)",conn->method,path);
		return;
	}

	/* 16. Static file - maybe cached */
	if ((!conn->req.in_error_handler) && is_not_modified(conn, &file)) {
		/* Send 304 "Not Modified" - this must not send any body data */
		handle_not_modified_static_file_request(conn, &file);
		//DEBUG_TRACE("handling %s request to %s done (not modified)",conn->method,	path);
		return;
	}
	/* 17. Static file - not cached */
	handle_static_file_request(conn, path, &file, NULL, NULL);
	//DEBUG_TRACE("handling %s request to %s done (static)", conn->method, path);
}
