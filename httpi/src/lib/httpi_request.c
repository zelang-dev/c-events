#include "httpi_internal.h"
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
	 * handling in the `HttPi` code - not all methods used in WebDav. In
	 * particular, methods used on directories (when using Windows Explorer as
	 * WebDav client). */
	if (conn) {
		string_t s = conn->method;
		if (s != NULL) {
			/* These are the builtin DAV methods */
			return (!strcmp(s, "PROPFIND") || !strcmp(s, "PROPPATCH")
				|| !strcmp(s, "LOCK") || !strcmp(s, "UNLOCK")
				|| !strcmp(s, "MOVE") || !strcmp(s, "COPY"));
		}
	}
	return 0;
}

/* in: request (must be valid) */
/* in: filename  (must be valid) */
static int extention_matches_script(http_t *conn, string_t filename) {
	int cgi_config_idx, inc, max;
	if (http_match_prefix_strlen(conn->domain->config[QUICKJS_SCRIPT_EXTENSIONS],
		filename)
		> 0) {
		return 1;
	}

	inc = CGI_EXTENSIONS;
	//inc = CGI2_EXTENSIONS - CGI_EXTENSIONS;
	max = PUT_DELETE_PASSWORDS_FILE - CGI_EXTENSIONS;
	for (cgi_config_idx = 0; cgi_config_idx < max; cgi_config_idx += inc) {
		if ((conn->domain->config[CGI_EXTENSIONS + cgi_config_idx] != NULL)
			&& (http_match_prefix_strlen(
				conn->domain->config[CGI_EXTENSIONS + cgi_config_idx],
				filename)
	> 0)) {
			return 1;
		}
	}
	/* filename and conn could be unused, if all preocessor conditions
	 * are false (no script language supported). */
	(void)filename;
	(void)conn;

	return 0;
}

/* in: request (must be valid) */
/* in: filename  (must be valid) */
static int extention_matches_template_text(http_t *conn, string_t filename) {
	if (http_match_prefix_strlen(conn->domain->config[SSI_EXTENSIONS], filename)
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
 * - is_put_or_delete_request:	out: put/delete file?
 * - is_webdav_request: out: webdav request?
 * - is_template_text: out: SSI file or LSP file? */
void http_interpret_uri(http_t *conn,
	char *filename,
	size_t filename_buf_len,
	struct file *filestat,
	int *is_found,
	int *is_script_resource,
	int *is_websocket_request,
	int *is_put_or_delete_request,
	int *is_webdav_request,
	int *is_template_text
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
		http_snprintf(
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
				http_snprintf(
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
			if (!is_empty(filestat->membuf)) {
				*is_found = true;
				return;
			}

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
		http_snprintf(&truncated, gz_path, sizeof(gz_path), "%s.gz", filename);

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
	}

	memcpy(tmp_str, filename, tmp_str_len + 1);

	/* Check config, if index scripts may have sub-resources */
	allow_substitute_script_subresources = str_is_case(conn->domain->config[ALLOW_INDEX_SCRIPT_SUB_RES], "yes");
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
						debug_info("Substitute script %s serving path %s"CLR_LN, tmp_str, filename);

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
						debug_info("Substitute file %s serving path %s"CLR_LN, tmp_str, filename);

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
	const httpi_t *request_info = &conn->req;
	if (request_info) {
		string_t uri = request_info->local_uri;
		size_t urilen = strlen(uri);
		struct http_cb_info *tmp_rh;

		if (!conn || !conn->ctx) {
			return 0;
		}

		atomic_lock(&conn->ctx->nonce_mutex);

		/* first try for an exact match */
		for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
			tmp_rh = tmp_rh->next) {
			if (tmp_rh->handler_type == handler_type) {
				if (urilen == tmp_rh->uri_len && !strcmp(tmp_rh->uri, uri)) {
					if (handler_type == WEBSOCKET_HANDLER) {
						*subprotocols = tmp_rh->subprotocols;
						*connect_handler = tmp_rh->connect_handler;
						*ready_handler = tmp_rh->ready_handler;
						*data_handler = tmp_rh->data_handler;
						*close_handler = tmp_rh->close_handler;
					} else if (handler_type == REQUEST_HANDLER) {
						*handler = tmp_rh->handler;
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

		/* next try for a partial match, we will accept uri/something */
		for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
			tmp_rh = tmp_rh->next) {
			if (tmp_rh->handler_type == handler_type) {
				if (tmp_rh->uri_len < urilen && uri[tmp_rh->uri_len] == '/'
					&& memcmp(tmp_rh->uri, uri, tmp_rh->uri_len) == 0) {
					if (handler_type == WEBSOCKET_HANDLER) {
						*subprotocols = tmp_rh->subprotocols;
						*connect_handler = tmp_rh->connect_handler;
						*ready_handler = tmp_rh->ready_handler;
						*data_handler = tmp_rh->data_handler;
						*close_handler = tmp_rh->close_handler;
					} else if (handler_type == REQUEST_HANDLER) {
						*handler = tmp_rh->handler;
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

		/* finally try for pattern match */
		for (tmp_rh = conn->ctx->handlers; tmp_rh != NULL;
			tmp_rh = tmp_rh->next) {
			if (tmp_rh->handler_type == handler_type) {
				if (http_match_prefix(tmp_rh->uri, tmp_rh->uri_len, uri) > 0) {
					if (handler_type == WEBSOCKET_HANDLER) {
						*subprotocols = tmp_rh->subprotocols;
						*connect_handler = tmp_rh->connect_handler;
						*ready_handler = tmp_rh->ready_handler;
						*data_handler = tmp_rh->data_handler;
						*close_handler = tmp_rh->close_handler;
					} else if (handler_type == REQUEST_HANDLER) {
						*handler = tmp_rh->handler;
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

int http_url_decode(string_t src, int src_len, string dst,
	int dst_len, int is_form_url_encoded) {
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

int http_url_encode(string_t src, string dst, size_t dst_len) {
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

static string_t get_proto_name(http_t *conn) {
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	/* Depending on USE_WEBSOCKET and NO_SSL, some oft the protocols might be
	 * not supported. Clang raises an "unreachable code" warning for parts of ?:
	 * unreachable, but splitting into four different #ifdef clauses here is
	 * more complicated.
	 */
#endif

	const httpi_t *ri = &conn->req;

	string_t proto = ((conn->req.proto == PROTOCOL_WEBSOCKET)
		? (conn->client->has_ssl ? "wss" : "ws")
		: (conn->client->has_ssl ? "https" : "http"));

	return proto;

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
}

static int construct_local_link(http_t *conn,
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
		const httpi_t *ri = &conn->req;

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
		if (conn->client->lsa.sa.sa_family == AF_UNIX) {
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
			http_snprintf(
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
		} else if (conn->client->has_ssl) {
			/* If we did not get a protocol name, use TLS as default if it is
			 * already used. */
			default_port = 443;
		}

		{
			int is_ipv6 = (conn->client->lsa.sa.sa_family == AF_INET6);
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
				async_sockaddr_str(server_ip,
					sizeof(server_ip),
					&conn->client->lsa);
				server_domain = server_ip;
			}

			http_snprintf(
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
	return construct_local_link(conn, buf, buflen, NULL, -1, NULL);
}

/* Writes PROPFIND properties for a collection element */
static int print_props(http_t *conn, string_t uri, string_t name, struct file *filep) {
	size_t i;
	char mtime[64];
	char link_buf[UTF8_PATH_MAX * 2]; /* Path + server root */
	char *link_concat;
	size_t link_concat_len;

	if ((conn == NULL) || (uri == NULL) || (name == NULL) || (filep == NULL)) {
		return 0;
	}

	link_concat_len = strlen(uri) + strlen(name) + 1;
	link_concat = malloc(link_concat_len);
	if (!link_concat) {
		return 0;
	}

	strcpy(link_concat, uri);
	strcat(link_concat, name);

	/* Get full link used in request */
	construct_local_link(conn, link_buf, sizeof(link_buf), NULL, 0, link_concat);

	http_gmt_time_str(mtime, sizeof(mtime), &filep->last_modified);
	http_printf(conn,
		"<d:response>"
		"<d:href>%s</d:href>"
		"<d:propstat>"
		"<d:prop>"
		"<d:resourcetype>%s</d:resourcetype>"
		"<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>"
		"<d:getlastmodified>%s</d:getlastmodified>"
		"<d:lockdiscovery>",
		link_buf,
		filep->is_directory ? "<d:collection/>" : "",
		filep->size,
		mtime);

	for (i = 0; i < NUM_WEBDAV_LOCKS; i++) {
		struct twebdav_lock *dav_lock = conn->ctx->webdav_lock;
		if (!strcmp(dav_lock[i].path, link_buf)) {
			http_printf(conn,
				"<d:activelock>"
				"<d:locktype><d:write/></d:locktype>"
				"<d:lockscope><d:exclusive/></d:lockscope>"
				"<d:depth>0</d:depth>"
				"<d:owner>%s</d:owner>"
				"<d:timeout>Second-%u</d:timeout>"
				"<d:locktoken>"
				"<d:href>%s</d:href>"
				"</d:locktoken>"
				"</d:activelock>\n",
				dav_lock[i].user,
				(unsigned)LOCK_DURATION_S,
				dav_lock[i].token);
		}
	}

	http_printf(conn,
		"</d:lockdiscovery>"
		"</d:prop>"
		"<d:status>HTTP/1.1 200 OK</d:status>"
		"</d:propstat>"
		"</d:response>\n");

	free(link_concat);
	return 1;
}

static int print_dav_dir_entry(struct de *de, void *data) {
	http_t *conn = (http_t *)data;
	if (!de || !conn
		|| !print_props(conn, conn->req.local_uri, de->file_name, &de->file)) {
	 	/* stop scan */
		return 1;
	}
	return 0;
}

static void handle_propfind(http_t *conn, string_t path, struct file *filep) {
	string_t depth = http_get_header(conn, "Depth");

	if (!conn || !path || !filep || !conn->domain) {
		return;
	}

	/* return 207 "Multi-Status" */
	conn->req.must_close = 1;
	http_response_start(conn, 207);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn,
		"Content-Type",
		"application/xml; charset=utf-8",
		-1);
	http_response_send(conn);

	/* Content */
	http_printf(conn,
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<d:multistatus xmlns:d='DAV:'>\n");

	/* Print properties for the requested resource itself */
	print_props(conn, conn->req.local_uri, "", filep);

	/* If it is a directory, print directory entries too if Depth is not 0 */
	if (filep->is_directory && str_is_case(conn->domain->config[ENABLE_DIRECTORY_LISTING], "yes")
		&& ((depth == NULL) || (strcmp(depth, "0") != 0))) {
		//fs_scan_directory(conn, path, conn, &print_dav_dir_entry);
	}

	http_printf(conn, "%s\n", "</d:multistatus>");
}

static void dav_lock_file(http_t *conn, string_t path) {
	/* internal function - therefore conn is assumed to be valid */
	char link_buf[UTF8_PATH_MAX * 2]; /* Path + server root */
	uint64_t new_locktime;
	int lock_index = -1;
	int i;
	uint64_t LOCK_DURATION_NS =
		(uint64_t)(LOCK_DURATION_S) * (uint64_t)1000000000;
	struct twebdav_lock *dav_lock = NULL;

	if (!path || !conn || !conn->domain || !conn->req.remote_user
		|| !conn->ctx) {
		return;
	}

	dav_lock = conn->ctx->webdav_lock;
	http_get_request_link(conn, link_buf, sizeof(link_buf));

	/* string_t refresh = http_get_header(conn, "If"); */
	/* Link refresh should have an "If" header:
	 * http://www.webdav.org/specs/rfc2518.html#n-example---refreshing-a-write-lock
	 * But it seems Windows Explorer does not send them.
	 */

	atomic_lock(&conn->ctx->nonce_mutex);
	new_locktime = events_now();

	/* Find a slot for a lock */
	while (lock_index < 0) {
		/* find existing lock */
		for (i = 0; i < NUM_WEBDAV_LOCKS; i++) {
			if (!strcmp(dav_lock[i].path, link_buf)) {
				if (!strcmp(conn->req.remote_user, dav_lock[i].user)) {
					/* locked by the same user */
					dav_lock[i].locktime = new_locktime;
					lock_index = i;
					break;
				} else {
					/* already locked by someone else */
					if (new_locktime > (dav_lock[i].locktime + LOCK_DURATION_NS)) {
						/* Lock expired */
						dav_lock[i].path[0] = 0;
					} else {
						/* Lock still valid */
						atomic_unlock(&conn->ctx->nonce_mutex);
						http_error(conn, 423, "%s", "Already locked");
						return;
					}
				}
			}
		}

		/* create new lock token */
		for (i = 0; i < NUM_WEBDAV_LOCKS; i++) {
			if (dav_lock[i].path[0] == 0) {
				char s[32];
				dav_lock[i].locktime = events_now();
				sprintf(s, "%" UINT64_FMT, (uint64_t)dav_lock[i].locktime);
				http_md5(dav_lock[i].token,
					link_buf,
					"\x01",
					s,
					"\x01",
					conn->req.remote_user,
					NULL);
				str_lcpy(dav_lock[i].path,
					link_buf,
					sizeof(dav_lock[i].path));
				str_lcpy(dav_lock[i].user,
					conn->req.remote_user,
					sizeof(dav_lock[i].user));
				lock_index = i;
				break;
			}
		}
		if (lock_index < 0) {
			/* too many locks. Find oldest lock */
			uint64_t oldest_locktime = dav_lock[0].locktime;
			lock_index = 0;
			for (i = 1; i < NUM_WEBDAV_LOCKS; i++) {
				if (dav_lock[i].locktime < oldest_locktime) {
					oldest_locktime = dav_lock[i].locktime;
					lock_index = i;
				}
			}
			/* invalidate oldest lock */
			dav_lock[lock_index].path[0] = 0;
		}
	}
	atomic_unlock(&conn->ctx->nonce_mutex);

	/* return 200 "OK" */
	conn->req.must_close = 1;
	http_response_start(conn, 200);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn,
		"Content-Type",
		"application/xml; charset=utf-8",
		-1);
	http_response_add(conn, "Lock-Token", dav_lock[lock_index].token, -1);
	http_response_send(conn);

	/* Content */
	http_printf(conn,
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<d:prop xmlns:d=\"DAV:\">\n"
		"     <d:lockdiscovery>\n"
		"       <d:activelock>\n"
		"         <d:lockscope><d:exclusive/></d:lockscope>\n"
		"         <d:locktype><d:write/></d:locktype>\n"
		"         <d:owner>\n"
		"           <d:href>%s</d:href>\n"
		"         </d:owner>\n"
		"         <d:timeout>Second-%u</d:timeout>\n"
		"         <d:locktoken><d:href>%s</d:href></d:locktoken>\n"
		"         <d:lockroot>\n"
		"           <d:href>%s</d:href>\n"
		"         </d:lockroot>\n"
		"       </d:activelock>\n"
		"     </d:lockdiscovery>\n"
		"   </d:prop>\n",
		dav_lock[lock_index].user,
		(LOCK_DURATION_S),
		dav_lock[lock_index].token,
		dav_lock[lock_index].path);
}

static void dav_unlock_file(http_t *conn, string_t path) {
	/* internal function - therefore conn is assumed to be valid */
	char link_buf[UTF8_PATH_MAX * 2]; /* Path + server root */
	struct twebdav_lock *dav_lock = conn->ctx->webdav_lock;
	int lock_index;

	if (!path || !conn->domain || !conn->req.remote_user) {
		return;
	}

	http_get_request_link(conn, link_buf, sizeof(link_buf));

	atomic_lock(&conn->ctx->nonce_mutex);
	/* find existing lock */
	for (lock_index = 0; lock_index < NUM_WEBDAV_LOCKS; lock_index++) {
		if (!strcmp(dav_lock[lock_index].path, link_buf)) {
			/* Success: return 204 "No Content" */
			atomic_unlock(&conn->ctx->nonce_mutex);
			conn->req.must_close = 1;
			http_response_start(conn, 204);
			http_response_send(conn);
			return;
		}
	}
	atomic_unlock(&conn->ctx->nonce_mutex);

	/* Error: Cannot unlock a resource that is not locked */
	http_error(conn, 423, "%s", "Lock not found");
}

static void dav_proppatch(http_t *conn, string_t path) {
	char link_buf[UTF8_PATH_MAX * 2]; /* Path + server root */

	if (!conn || !path || !conn->domain) {
		return;
	}

	/* return 207 "Multi-Status" */
	conn->req.must_close = 1;
	http_response_start(conn, 207);
	http_static_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn,
		"Content-Type",
		"application/xml; charset=utf-8",
		-1);
	http_response_send(conn);

	http_get_request_link(conn, link_buf, sizeof(link_buf));

	/* Content */
	http_printf(conn,
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<d:multistatus xmlns:d='DAV:'>\n"
		"<d:response>\n<d:href>%s</d:href>\n",
		link_buf);
	http_printf(conn,
		"<d:propstat><d:status>HTTP/1.1 403 "
		"Forbidden</d:status></d:propstat>\n");
	http_printf(conn, "%s\n", "</d:response></d:multistatus>");
}

static void dav_mkcol(http_t *conn, string_t path) {
	int rc, body_len;
	struct de de;

	if (conn == NULL) {
		return;
	}

	/* TODO (mid): Check the `http_error` situations in this function
	 */

	memset(&de.file, 0, sizeof(de.file));
	if (!http_stat(conn, path, &de.file)) {
		http_log(DEBUG_ERROR, conn,
			"%s: http_stat(%s) failed: %s",
			__func__,
			path,
			ex_strerror(os_geterror()));
	}

	if (de.file.last_modified) {
		/* TODO (mid): This check does not seem to make any sense ! */
		/* TODO (mid): Add a webdav unit test first, before changing
		 * anything here. */
		http_error(
			conn, 405, "Error: mkcol(%s): %s", path, ex_strerror(os_geterror()));
		return;
	}

	body_len = conn->req.data_len - conn->req.request_len;
	if (body_len > 0) {
		http_error(
			conn, 415, "Error: mkcol(%s): %s", path, ex_strerror(os_geterror()));
		return;
	}

	rc = fs_mkdir(path, 0755);
	debug_info("mkdir %s: %i"CLR_LN, path, rc);
	if (rc == 0) {
		/* Create 201 "Created" response */
		http_response_start(conn, 201);
		http_static_cache_header(conn);
		http_domain_header(conn);
		http_response_add(conn, "Content-Length", "0", -1);

		/* Send all headers - there is no body */
		http_response_send(conn);
	} else {
		int http_status = 500;
		switch (errno) {
			case EEXIST:
				http_status = 405;
				break;
			case EACCES:
				http_status = 403;
				break;
			case ENOENT:
				http_status = 409;
				break;
		}

		http_error(conn,
			http_status,
			"Error processing %s: %s",
			path,
			ex_strerror(os_geterror()));
	}
}

static void dav_move_file(http_t *conn, string_t path, int do_copy) {
	string_t overwrite_hdr;
	string_t destination_hdr;
	string_t root;
	enum uri_type_t dest_uri_type;
	int rc;
	int http_status = 400;
	int do_overwrite = 0;
	int destination_ok = 0;
	char dest_path[UTF8_PATH_MAX];
	struct file ignored;

	if (conn == NULL) {
		return;
	}

	root = conn->domain->config[DOCUMENT_ROOT];
	overwrite_hdr = http_get_header(conn, "Overwrite");
	destination_hdr = http_get_header(conn, "Destination");
	if ((overwrite_hdr != NULL) && (toupper(overwrite_hdr[0]) == 'T')) {
		do_overwrite = 1;
	}

	if ((destination_hdr == NULL) || (destination_hdr[0] == 0)) {
		http_error(conn, 400, "%s", "Missing destination");
		return;
	}

	if (root != NULL) {
		char *local_dest = NULL;
		dest_uri_type = http_get_uri_type(destination_hdr);
		if (dest_uri_type == URI_TYPE_RELATIVE) {
			local_dest = str_dup_ex(destination_hdr);
		} else if ((dest_uri_type == URI_TYPE_ABS_NOPORT) || (dest_uri_type == URI_TYPE_ABS_PORT)) {
			string_t h =	http_get_rel_url_at_current_server(destination_hdr, conn);
			if (h) {
				size_t len = strlen(h);
				local_dest = malloc(len + 1);
				http_url_decode(h, (int)len, local_dest, (int)len + 1, 0);
			}
		}
		if (local_dest != NULL) {
			remove_double_dots_slashes(local_dest);
			if (local_dest[0] == '/') {
				int trunc_check = 0;
				http_snprintf(
					&trunc_check,
					dest_path,
					sizeof(dest_path),
					"%s/%s",
					root,
					local_dest);
				if (trunc_check == 0) {
					destination_ok = 1;
				}
			}
			free(local_dest);
		}
	}

	if (!destination_ok) {
		http_error(conn, 502, "%s", "Illegal destination");
		return;
	}

	/* Check now if this file exists */
	if (http_stat(conn, dest_path, &ignored)) {
		/* File exists */
		if (do_overwrite) {
			/* Overwrite allowed: delete the file first */
			if (0 != fs_unlink(dest_path)) {
				/* No overwrite: return error */
				http_error(conn, 403, "Cannot overwrite file: %s",
					dest_path);
				return;
			}
		} else {
			/* No overwrite: return error */
			http_error(conn, 412, "Destination already exists: %s",
				dest_path);
			return;
		}
	}

	/* Copy / Move / Rename operation. */
	debug_info("%s %s to %s"CLR_LN, (do_copy ? "copy" : "move"), path, dest_path);
	{
		if (do_copy) {
			rc = fs_copyfile(path, dest_path);
		} else {
			rc = fs_rename(path, dest_path);
		}

		if (rc) {
			switch (errno) {
				case EEXIST:
					http_status = 412;
					break;
				case EACCES:
					http_status = 403;
					break;
				case ENOENT:
					http_status = 409;
					break;
			}
		}
	}

	if (rc == 0) {
		/* Create 204 "No Content" response */
		http_response_start(conn, 204);
		http_response_add(conn, "Content-Length", "0", -1);

		/* Send all headers - there is no body */
		http_response_send(conn);
	} else {
		http_error(conn, http_status, "Operation failed");
	}
}

static void redirect_to_https_port(http_t *conn, int port) {
	char target_url[BUF_LEN];
	int truncated = 0;
	string_t expect_proto =
		(conn->req.proto == PROTOCOL_WEBSOCKET) ? "wss" : "https";

	/* Use "308 Permanent Redirect" */
	int redirect_code = 308;

	/* In any case, close the current connection */
	conn->req.must_close = 1;

	/* Send host, port, uri and (if it exists) ?query_string */
	if (construct_local_link(conn, target_url, sizeof(target_url), expect_proto, port, NULL) < 0) {
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

	/* Check overflow in location buffer (will not occur if BUF_LEN
	 * is used as buffer size) */
	if (truncated) {
		http_error(conn, 500, "%s", "Redirect URL too long");
		return;
	}

	/* Use redirect helper function */
	http_redirect(conn, target_url, redirect_code);
}


static int get_first_ssl_listener_index(const http_ini_t *ctx) {
	int idx = -1;
	if (!is_empty(ctx) && $size(ctx->server_sockets) > 0) {
		foreach(sockets in ctx->server_sockets) {
			http_socket *socket = (http_socket *)sockets.object;
			idx = socket->has_ssl ? ((int)(isockets)) : -1;
			if (idx != -1)
				break;
		}
	}

	return idx;
}

#undef in

void remove_double_dots_slashes(char *inout) {
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
		if (!strncmp(in, "../", 3)) {
			in += 3;
		} else if (!strncmp(in, "./", 2)) {
			in += 2;
		}
		/* otherwise */
		/* Step 2b:
		 * if the input buffer begins with a prefix of "/./" or "/.",
		 * where "." is a complete path segment, then replace that
		 * prefix with "/" in the input buffer;
		 */
		else if (!strncmp(in, "/./", 3)) {
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
		else if (!strncmp(in, "/../", 4)) {
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
	string_t list, ext;
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

	vec->ptr = http_builtin_mime_type(path);
	vec->len = strlen(vec->ptr);
}

void http_send_file_data(http_t *conn, struct file *filep,
	int64_t offset, int64_t len, int no_buffering) {
	char buf[BUF_LEN];
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
			http_error(conn, 500, "%s", "Error: Unable to access file at requested position.");
			http_log(DEBUG_ERROR, conn, "%s: fseek() failed: %s", __func__, ex_strerror(os_geterror()));
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
				if ((num_read = promise_read(filep->pf, fileno(filep->fp), buf, to_read)) <= 0)
					break;

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
		http_snprintf(&truncated, gz_path, sizeof(gz_path), "%s.gz", path);
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
		&& (filep->size >= FILE_COMPRESSION_SIZE_LIMIT)) {
		struct file file_stat;
		http_snprintf(&truncated, gz_path, sizeof(gz_path), "%s.gz", path);
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
		http_error(conn, 500, "Error: Cannot open file\nfopen(%s): %s", path, ex_strerror(os_geterror()));
		return;
	}

	if (is_empty(filep->membuf))
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
			(void)http_fclose(filep); /* ignore error on read only file */
			return;
		}
		conn->status = 206;
		cl = (n == 2) ? (((r2 > cl) ? cl : r2) - r1 + 1) : (cl - r1);
		http_snprintf(
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
	if (filep->size < FILE_COMPRESSION_SIZE_LIMIT) {
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
	http_response_add(conn, "Content-Type", mime_vec.ptr, (int)mime_vec.len);
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
		http_snprintf(&trunc, len, sizeof(len), "%" INT64_FMT, cl);
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
	(void)http_fclose(filep); /* ignore error on read only file */
}

/* Check if the script file is in a path, allowed for script files.
 * This can be used if uploading files is possible not only for the server
 * admin, and the upload mechanism does not check the file extension.  */
static int is_in_script_path(http_t *conn, string_t path) {
	/* TODO (Feature): Add config value for allowed script path.
	 * Default: All allowed. */
	(void)conn;
	if (str_has(path, ".cgi"))
		return 0;
	return 1;
}

static int http_fgetc(struct file *filep) {
	if (filep == NULL) {
		return EOF;
	}

	if (filep->fp != NULL) {
		return promise_fgetc(filep->pf, filep->fp);
	} else {
		return EOF;
	}
}

static void send_ssi_file(http_t *conn, string_t path, struct file *filep, int include_level);

static void do_ssi_include(http_t *conn, string_t ssi, char *tag, int include_level) {
	char file_name[BUF_LEN], path[512], *p;
	struct file file = STRUCT_FILE_INITIALIZER;
	size_t len;
	int truncated = 0;

	if (conn == NULL) {
		return;
	}

	/* sscanf() is safe here, since send_ssi_file() also uses buffer
	 * of size MG_BUF_LEN to get the tag. So strlen(tag) is
	 * always < MG_BUF_LEN. */
	if (sscanf(tag, " virtual=\"%511[^\"]\"", file_name) == 1) {
		/* File name is relative to the webserver root */
		file_name[511] = 0;
		(void)http_snprintf(
			&truncated,
			path,
			sizeof(path),
			"%s/%s",
			conn->domain->config[DOCUMENT_ROOT],
			file_name);
	} else if (sscanf(tag, " abspath=\"%511[^\"]\"", file_name) == 1) {
		/* File name is relative to the webserver working directory
		 * or it is absolute system path */
		file_name[511] = 0;
		(void)http_snprintf(&truncated, path, sizeof(path), "%s", file_name);
	} else if ((sscanf(tag, " file=\"%511[^\"]\"", file_name) == 1)
		|| (sscanf(tag, " \"%511[^\"]\"", file_name) == 1)) {
 		/* File name is relative to the current document */
		file_name[511] = 0;
		(void)http_snprintf(&truncated, path, sizeof(path), "%s", ssi);
		if (!truncated) {
			if ((p = strrchr(path, '/')) != NULL) {
				p[1] = '\0';
			}
			len = strlen(path);
			(void)http_snprintf(&truncated,
				path + len, sizeof(path) - len, "%s", file_name);
		}
	} else {
		http_log(DEBUG_ERROR, conn, "Bad SSI #include: [%s]", tag);
		return;
	}

	if (truncated) {
		http_log(DEBUG_ERROR, conn, "SSI #include path length overflow: [%s]", tag);
		return;
	}

	if (!http_fopen(conn->ctx, conn, path, "rb", &file)) {
		http_log(DEBUG_ERROR, conn,
			"Cannot open SSI #include: [%s]: fopen(%s): %s",
			tag,
			path,
			ex_strerror(os_geterror()));
	} else {
		http_set_close_on_exec(fd2socket(fileno(file.fp)));
		if (http_match_prefix_strlen(conn->domain->config[SSI_EXTENSIONS], path)
	> 0) {
			send_ssi_file(conn, path, &file, include_level + 1);
		} else {
			http_send_file_data(conn, &file, 0, INT64_MAX, 0); /* send static file */
		}
		(void)http_fclose(&file); /* Ignore errors for readonly files */
	}
}

static void do_ssi_exec(http_t *conn, char *tag) {
	char cmd[1024] = "";
	struct file file = STRUCT_FILE_INITIALIZER;

	if (sscanf(tag, " \"%1023[^\"]\"", cmd) != 1) {
		http_log(DEBUG_ERROR, conn, "Bad SSI #exec: [%s]", tag);
	} else {
		cmd[1023] = 0;
		file.pf = alloc_promise();
		if ((file.fp = popen(cmd, "r")) == NULL) {
			http_log(DEBUG_ERROR, conn,
				"Cannot SSI #exec: [%s]: %s",
				cmd,
				ex_strerror(os_geterror()));
			free(file.pf);
			file.pf = null;
		} else {
			http_send_file_data(conn, &file, 0, INT64_MAX, 0); /* send static file */
			promise_pclose(file.pf, file.fp);
			file.pf = null;
			file.fp = null;
		}
	}
}

static void send_ssi_file(http_t *conn,
	string_t path,
	struct file *filep,
	int include_level) {
	char buf[BUF_LEN];
	int ch, len, in_tag, in_ssi_tag;

	if (include_level > 10) {
		http_log(DEBUG_ERROR, conn, "SSI #include level is too deep (%s)", path);
		return;
	}

	in_tag = in_ssi_tag = len = 0;

	/* Read file, byte by byte, and look for SSI include tags */
	while ((ch = http_fgetc(filep)) != EOF) {
		if (in_tag) {
			/* We are in a tag, either SSI tag or html tag */
			if (ch == '>') {
				/* Tag is closing */
				buf[len++] = '>';
				if (in_ssi_tag) {
					/* Handle SSI tag */
					buf[len] = 0;
					if ((len > 12) && !memcmp(buf + 5, "include", 7)) {
						do_ssi_include(conn, path, buf + 12, include_level + 1);
					} else if ((len > 9) && !memcmp(buf + 5, "exec", 4)) {
						do_ssi_exec(conn, buf + 9);
					} else {
						http_log(DEBUG_ERROR, conn,
							"%s: unknown SSI "
							"command: \"%s\"",
							path,
							buf);
					}
					len = 0;
					in_ssi_tag = in_tag = 0;
				} else {
					/* Not an SSI tag */
					/* Flush buffer */
					(void)http_write(conn, buf, (size_t)len);
					len = 0;
					in_tag = 0;
				}
			} else {
				/* Tag is still open */
				buf[len++] = (char)(ch & 0xff);
				if ((len == 5) && !memcmp(buf, "<!--#", 5)) {
					/* All SSI tags start with <!--# */
					in_ssi_tag = 1;
				}

				if ((len + 2) > (int)sizeof(buf)) {
					/* Tag to long for buffer */
					http_log(DEBUG_ERROR, conn, "%s: tag is too large", path);
					return;
				}
			}
		} else {
			/* We are not in a tag yet. */
			if (ch == '<') {
				/* Tag is opening */
				in_tag = 1;
				if (len > 0) {
					/* Flush current buffer.
					 * Buffer is filled with "len" bytes. */
					(void)http_write(conn, buf, (size_t)len);
				}
				/* Store the < */
				len = 1;
				buf[0] = '<';
			} else {
				/* No Tag */
				/* Add data to buffer */
				buf[len++] = (char)(ch & 0xff);
				/* Flush if buffer is full */
				if (len == (int)sizeof(buf)) {
					http_write(conn, buf, (size_t)len);
					len = 0;
				}
			}
		}
	}

	/* Send the rest of buffered data */
	if (len > 0) {
		http_write(conn, buf, (size_t)len);
	}
}

static void handle_ssi_file_request(http_t *conn,
	string_t path,
	struct file *filep) {
	char date[64];
	time_t curtime = time(NULL);

	if ((conn == NULL) || (path == NULL) || (filep == NULL)) {
		return;
	}

	if (!http_fopen(conn->ctx, conn, path, "rb", filep)) {
		/* File exists (precondition for calling this function),
		 * but can not be opened by the server. */
		http_error(conn,
			500,
			"Error: Cannot read file\nfopen(%s): %s",
			path,
			ex_strerror(os_geterror()));
	} else {
		/* Set "must_close" for HTTP/1.x, since we do not know the
		 * content length */
		conn->req.must_close = 1;
		http_gmt_time_str(date, sizeof(date), &curtime);
		http_set_close_on_exec(fd2socket(fileno(filep->fp)));

		/* 200 OK response */
		http_response_start(conn, 200);
		http_no_cache_header(conn);
		http_domain_header(conn);
		http_cors_header(conn);
		http_response_add(conn, "Content-Type", "text/html", -1);
		http_response_send(conn);

		/* Header sent, now send body */
		send_ssi_file(conn, path, filep, 0);
		(void)http_fclose(filep); /* Ignore errors for readonly files */
	}
}

void handle_file_based_request(http_t *conn,
	string_t path,
	struct file *file) {
	int cgi_config_idx, inc, max;

	if (!conn || !conn->domain) {
		return;
	}

	if (http_match_prefix_strlen(conn->domain->config[QUICKJS_SCRIPT_EXTENSIONS],
		path)
	> 0) {
		if (is_in_script_path(conn, path)) {
			/* Call QuickJS to generate the page */
			qjs_exec_script(conn, path);
		} else {
			/* Script was in an illegal path */
			http_error(conn, 403, "%s", "Forbidden");
		}
		return;
	}

	inc = CGI_EXTENSIONS;
	//inc = CGI2_EXTENSIONS - CGI_EXTENSIONS;
	max = PUT_DELETE_PASSWORDS_FILE - CGI_EXTENSIONS;
	for (cgi_config_idx = 0; cgi_config_idx < max; cgi_config_idx += inc) {
		if (conn->domain->config[CGI_EXTENSIONS + cgi_config_idx] != NULL) {
			if (http_match_prefix_strlen(
				conn->domain->config[CGI_EXTENSIONS + cgi_config_idx], path) > 0) {
				if (is_in_script_path(conn, path)) {
					/* CGI scripts may support all HTTP methods */
					//handle_cgi_request(conn, path, cgi_config_idx);
				} else {
					/* Script was in an illegal path */
					http_error(conn, 403, "%s", "Forbidden");
				}
				return;
			}
		}
	}

	if (http_match_prefix_strlen(conn->domain->config[SSI_EXTENSIONS], path) > 0) {
		if (is_in_script_path(conn, path)) {
			handle_ssi_file_request(conn, path, file);
		} else {
			/* Script was in an illegal path */
			http_error(conn, 403, "%s", "Forbidden");
		}
		return;
	}

	if ((!conn->req.in_error_handler) && is_not_modified(conn, file)) {
		/* Send 304 "Not Modified" - this must not send any body data */
		handle_not_modified_static_file_request(conn, file);
		return;
	}

	handle_static_file_request(conn, path, file, NULL, NULL);
}

/* Return True if we should reply 304 Not Modified. */
int is_not_modified(http_t *conn, const struct file *filestat) {
	char etag[64];
	string_t ims = http_get_header(conn, "If-Modified-Since");
	string_t inm = http_get_header(conn, "If-None-Match");
	http_construct_etag(conn, etag, sizeof(etag), filestat);

	if (inm) {
		return str_is_case(etag, inm);
	}
	if (ims) {
		return (filestat->last_modified <= parse_date_str(ims));
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

static int push_all(http_ini_t *ctx, struct file *fp, string_t buf, int len) {
	double timeout = -1.0;
	int n, nwritten = 0;

	if (ctx == NULL) {
		return -1;
	}

	if (ctx->host.config[REQUEST_TIMEOUT]) {
		timeout = atoi(ctx->host.config[REQUEST_TIMEOUT]) / 1000.0;
	}
	if (timeout <= 0.0) {
		timeout = strtod(http_get_default_option(REQUEST_TIMEOUT), NULL)
			/ 1000.0;
	}

	while ((len > 0) && ctx->status == HTTP_STATUS_RUNNING) {
		n = promise_fwrite(fp->pf, (string)buf + nwritten, 1, len, fp->fp);
		if (ferror(fp->fp) || n < 0) {
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

static int forward_body_data(http_t *conn, struct file *fp) {
	string_t expect;
	char buf[BUF_LEN];
	int success = 0;

	if (!conn) {
		return 0;
	}

	expect = http_get_header(conn, "Expect");
	if (!fp) {
		http_error(conn, 500, "%s", "Error: NULL File");
		return 0;
	}

	if ((expect != NULL) && !str_is_case(expect, "100-continue")) {
		/* Client sent an "Expect: xyz" header and xyz is not 100-continue.
		 */
		http_error(conn, 417, "Error: Can not fulfill expectation");
	} else {
		if (expect != NULL) {
			(void)http_printf(conn, "%s", "HTTP/1.1 100 Continue\r\n\r\n");
			conn->status = 100;
		} else {
			conn->status = 200;
		}

		if (conn->req.consumed_content != 0) {
			http_error(conn, 500, "%s", "Error: Size mismatch");
			return 0;
		}

		for (;;) {
			int nread = http_read(conn, buf, sizeof(buf));
			if (nread <= 0) {
				success = (nread == 0);
				break;
			}
			if (push_all(conn->ctx, fp, buf, nread) != nread) {
				break;
			}
		}

		/* Each error code path in this function must send an error */
		if (!success) {
			/* NOTE: Maybe some data has already been sent. */
			/* TODO (low): If some data has been sent, a correct error
			 * reply can no longer be sent, so just close the connection */
			http_error(conn, 500, "%s", "");
		}
	}

	return success;
}

static void put_file(http_t *conn, string_t path) {
	struct file file = STRUCT_FILE_INITIALIZER;
	string_t range;
	int64_t r1, r2;
	int rc;

	if (conn == NULL) {
		return;
	}

	debug_info("store %s"CLR_LN, path);
	if (http_stat(conn, path, &file)) {
		/* File already exists */
		conn->status = 200;

		if (file.is_directory) {
			/* This is an already existing directory,
			 * so there is nothing to do for the server. */
			rc = 0;

		} else {
			/* File exists and is not a directory. */
			/* Can it be replaced? */

			/* Check if the server may write this file */
			if (fs_access(path, W_OK) == 0) {
				/* Access granted */
				rc = 1;
			} else {
				http_error(conn, 403,
					"Error: Put not possible\nReplacing %s is not allowed",
					path);
				return;
			}
		}
	} else {
		/* File should be created */
		conn->status = 201;
		rc = http_put_dir(conn->ctx, conn, path);
	}

	if (rc == 0) {
		/* put_dir returns 0 if path is a directory */

		/* Create response */
		http_response_start(conn, conn->status);
		http_no_cache_header(conn);
		http_domain_header(conn);
		http_response_add(conn, "Content-Length", "0", -1);

		/* Send all headers - there is no body */
		http_response_send(conn);

		/* Request to create a directory has been fulfilled successfully.
		 * No need to put a file. */
		return;
	}

	if (rc == -1) {
		/* put_dir returns -1 if the path is too long */
		http_error(conn, 414, "Error: Path too long\nput_dir(%s): %s",
			path,
			ex_strerror(os_geterror()));
		return;
	}

	if (rc == -2) {
		/* put_dir returns -2 if the directory can not be created */
		http_error(conn, 500, "Error: Can not create directory\nput_dir(%s): %s",
			path, ex_strerror(os_geterror()));
		return;
	}

	/* A file should be created or overwritten. */
	/* Currently `HttPi` does not need read+write access. */
	if (!http_fopen(conn->ctx, conn, path, "wb", &file)
		|| file.fp == NULL) {
		(void)http_fclose(&file);
		http_error(conn, 500, "Error: Can not create file\nfopen(%s): %s",
			path,
			ex_strerror(os_geterror()));
		return;
	}

	http_set_close_on_exec(fd2socket(fileno(file.fp)));
	range = http_get_header(conn, "Content-Range");
	r1 = r2 = 0;
	if ((range != NULL) && parse_range_header(range, &r1, &r2) > 0) {
		conn->status = 206; /* Partial content */
		if (0 != fseek(file.fp, r1, SEEK_SET)) {
			http_error(conn,
				500,
				"Error: Internal error processing file %s",
				path);
			return;
		}
	}

	if (!forward_body_data(conn, &file)) {
		/* forward_body_data failed.
		 * The error code has already been sent to the client,
		 * and conn->status_code is already set. */
		(void)http_fclose(&file);
		return;
	}

	if (http_fclose(&file) != 0) {
		/* fclose failed. This might have different reasons, but a likely
		 * one is "no space on disk", http 507. */
		conn->status = 507;
	}

	/* Create response (status_code has been set before) */
	http_response_start(conn, conn->status);
	http_no_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn, "Content-Length", "0", -1);

	/* Send all headers - there is no body */
	http_response_send(conn);
}

static void delete_file(http_t *conn, string_t path) {
	struct de de;
	memset(&de.file, 0, sizeof(de.file));
	if (!http_stat(conn, path, &de.file)) {
		/* http_stat returns 0 if the file does not exist */
		http_error(conn,
			404,
			"Error: Cannot delete file\nFile %s not found",
			path);
		return;
	}

	debug_info("delete %s", path);
	if (de.file.is_directory) {
		if (remove_directory(conn, path)) {
			/* Delete is successful: Return 204 without content. */
			http_error(conn, 204, "%s", "");
		} else {
			/* Delete is not successful: Return 500 (Server error). */
			http_error(conn, 500, "Error: Could not delete %s", path);
		}
		return;
	}

	/* This is an existing file (not a directory).
	 * Check if write permission is granted. */
	if (fs_access(path, W_OK) != 0) {
		/* File is read only */
		http_error(
			conn,
			403,
			"Error: Delete not possible\nDeleting %s is not allowed",
			path);
		return;
	}

	/* Try to delete it. */
	if (fs_unlink(path) == 0) {
		/* Delete was successful: Return 204 without content. */
		http_response_start(conn, 204);
		http_no_cache_header(conn);
		http_domain_header(conn);
		http_response_add(conn, "Content-Length", "0", -1);
		http_response_send(conn);
	} else {
		/* Delete not successful (file locked). */
		http_error(conn,
			423,
			"Error: Cannot delete file\nremove(%s): %s",
			path,
			ex_strerror(os_geterror()));
	}
}

static uint32_t get_remote_ip(http_t *conn) {
	if (!conn) {
		return 0;
	}
	return ntohl(*(const uint32_t *)&conn->client->rsa.sin.sin_addr);
}

void http_handle_request(http_t *conn) {
	httpi_t *ri = &conn->req;
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
	if (!conn->client->has_ssl && conn->client->has_redir) {
		ssl_index = get_first_ssl_listener_index((const http_ini_t *)conn->ctx);
		if (ssl_index >= 0) {
			http_socket *so = (http_socket *)conn->ctx->server_sockets[ssl_index].object;
			int port = (int)ntohs(USA_IN_PORT_UNSAFE(&so->lsa));
			redirect_to_https_port(conn, port);
		} else {
			/* A http to https forward port has been specified,
			 * but no https port to forward to. */
			http_error(conn, 503, "%s", "Error: SSL forward not configured properly");
			http_log(DEBUG_ERROR, conn, "%s", "Can not redirect to SSL, no SSL port available");
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
	 * pointer to ri->local_uri and ri->local_uri_raw are now different.
	 * ri->local_uri_raw still points to memory allocated in
	 * worker_thread_run(). ri->local_uri is private to the request so we
	 * don't have to use preallocated memory here. */
	tmp = str_dup(ri->local_uri);
	if (!tmp) {
		/* Out of memory. We cannot do anything reasonable here. */
		return;
	}

	remove_double_dots_slashes(tmp);
	ri->local_uri = tmp;

	/* Only compute if later code can actually use it */
	/* Cache URI length once; recompute only if the buffer changes later. */
	uri_len = (int)strlen(ri->local_uri);

	/* step 1. completed, the url is known now */
	debug_info("REQUEST: %s %s"CLR_LN, conn->method, ri->local_uri);

	/* 2. if this ip has limited speed, set it for this connection */
	conn->req.throttle = set_throttle(conn->domain->config[THROTTLE], get_remote_ip(conn), ri->local_uri);

	/* 3. call a "handle everything" callback, if registered */
	if (conn->ctx->callbacks.handler != NULL) {
		/* Note the "handler" function is called before an authorization check.
		 * If an authorization check is required, use a `http_route()` instead. */
		i = conn->ctx->callbacks.handler(conn);
		if (i > 0) {
			/* callback already processed the request. Store the
			return value as a status code for the access log. */
			conn->status = i;
			if (!conn->req.must_close) {
				discard_unread_request_data(conn);
			}
			debug_info("%s", "handler registered handled request"CLR_LN);
			return;
		} else if (i == 0) {
			/* `HttPi` should process the request */
		} else {
			/* unspecified - may change with the next version */
			debug_info("%s", "done (undocumented behavior)"CLR_LN);
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
			debug_info("%s", "OPTIONS done");
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
			debug_info("%s", "must use HTTP/1.x");
			//return;
		}
	}

	/* 5.2. check if the request will be handled by a callback */
	if (http_get_request_handler(conn,
		handler_type,
		&callback_handler,
		&subprotocols,
		&ws_connect_handler,
		&ws_ready_handler,
		&ws_data_handler,
		&ws_close_handler,
		NULL,
		&callback_data,
		&handler_info)) {
	  /* 5.2.1. A callback will handle this request. All requests
		* handled by a callback have to be considered as requests
		* to a script resource. */
		is_callback_resource = 1;
		is_script_resource = 1;
		is_put_or_delete_request = is_put_or_delete_method(conn);
		/* Never handle a C callback according to File WebDav rules,
		 * even if it is a webdav method */
		is_webdav_request = 0; /* is_webdav_method(conn); */
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
			debug_info("%s", "webdav rejected"CLR_LN);
			return;
		}
	}

	/* 6. authorization check */
	/* 6.1. a custom authorization handler is installed */
	if (http_get_request_handler(conn,
		AUTH_HANDLER,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&auth_handler,
		&auth_callback_data,
		NULL)) {
		if (!auth_handler(conn, auth_callback_data)) {
			debug_info("%s", "auth handler rejected request"CLR_LN);
			return;
		}
	} else if (is_put_or_delete_request && !is_script_resource
		&& !is_callback_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
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
			debug_info("%s", "all file based put/delete requests rejected"CLR_LN);
			return;
		}

		/* 6.2.2. Check if put authorization for static files is
		 * available.
		 */
		if (!is_authorized_for_put(conn)) {
			send_authorization_request(conn, NULL);
			debug_info("%s", "file write needs authorization"CLR_LN);
			return;
		}
	} else {
		/* 6.3. This is either a OPTIONS, GET, HEAD or POST request,
		 * or it is a PUT or DELETE request to a resource that does not
		 * correspond to a file. Check authorization. */
		if (!str_is_empty(path) && !check_authorization(conn, path)) {
			send_authorization_request(conn, NULL);
			debug_info("%s", "access authorization required"CLR_LN);
			return;
		}
	}

	/* request is authorized or does not need authorization */

	/* 7. check if there are request handlers for this uri */
	if (is_callback_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
			//return;
		}
		if (!is_websocket_request) {
			i = callback_handler(conn, callback_data);
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
			http_websocket_request(conn->ctx,
				conn,
				is_callback_resource,
				subprotocols,
				ws_connect_handler,
				ws_ready_handler,
				ws_data_handler,
				ws_close_handler,
				callback_data);
		}
		debug_info("%s", "callback handling done"CLR_LN);
		return;
	}

	/* 8. handle websocket requests */
	if (is_websocket_request) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
			//return;
		} else if (!is_script_resource) {
			http_websocket_request(conn->ctx,
				conn,
				is_callback_resource,
				subprotocols,
				ws_connect_handler,
				ws_ready_handler,
				ws_data_handler,
				ws_close_handler,
				callback_data);
		} else if (is_script_resource) {
			/* Check if the script file is in a path, allowed for script files.
			* This can be used if uploading files is possible not only for the server
			* admin, and the upload mechanism does not check the file extension.
			*/
			/* TODO (Feature): Add config value for allowed script path.
			* Default: All allowed. */
			if (true) {
				/* Websocket Lua script */
				http_websocket_request(conn->ctx,
					conn,
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
		debug_info("%s", "websocket script done"CLR_LN);
		return;
	} else
	/* 9b. This request is either for a static file or resource handled
	 * by a script file. Thus, a DOCUMENT_ROOT must exist. */
		if (conn->domain->config[DOCUMENT_ROOT] == NULL) {
			http_error(conn, 404, "%s", "Not Found");
			debug_info("%s", "no document root available"CLR_LN);
			return;
		}

		/* 10. Request is handled by a script */
	if (is_script_resource) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
			//return;
		}
		handle_file_based_request(conn, path, &file);
		debug_info("%s", "script handling done"CLR_LN);
		return;
	}

	/* Request was not handled by a callback or script. It will be
	 * handled by a server internal method. */

	/* 11. Handle put/delete/mkcol requests */
	if (is_put_or_delete_request) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
			//return;
		}
		/* 11.1. PUT method */
		if (!strcmp(conn->method, "PUT")) {
			put_file(conn, path);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.2. DELETE method */
		if (!strcmp(conn->method, "DELETE")) {
			delete_file(conn, path);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.3. MKCOL method */
		if (!strcmp(conn->method, "MKCOL")) {
			dav_mkcol(conn, path);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.4. MOVE method */
		if (!strcmp(conn->method, "MOVE")) {
			dav_move_file(conn, path, 0);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		if (!strcmp(conn->method, "COPY")) {
			dav_move_file(conn, path, 1);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.5. LOCK method */
		if (!strcmp(conn->method, "LOCK")) {
			dav_lock_file(conn, path);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.6. UNLOCK method */
		if (!strcmp(conn->method, "UNLOCK")) {
			dav_unlock_file(conn, path);
			debug_info("handling %s request to %s done"CLR_LN,
				conn->method,
				path);
			return;
		}
		/* 11.7. PROPPATCH method */
		if (!strcmp(conn->method, "PROPPATCH")) {
			dav_proppatch(conn, path);
			debug_info("handling %s request to %s done"CLR_LN, conn->method, path);
			return;
		}
		/* 11.8. Other methods, e.g.: PATCH
		 * This method is not supported for static resources,
		 * only for scripts (Lua, CGI) and callbacks. */
		http_error(conn, 405, "%s method not allowed", conn->method);
		debug_info("method %s on %s is not supported"CLR_LN, conn->method, path);
		return;
	}

	/* 11. File does not exist, or it was configured that it should be
	 * hidden */
	if (!is_found || (http_must_hide_file(conn->ctx, path))) {
		http_error(conn, 404, "%s", "Not found");
		debug_info("handling %s request to %s: file not found"CLR_LN,
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
		debug_info("%s request to %s: directory redirection sent"CLR_LN,
			conn->method,
			path);
		return;
	}

	/* 13. Handle other methods than GET/HEAD */
	/* 13.1. Handle PROPFIND */
	if (!strcmp(conn->method, "PROPFIND")) {
		handle_propfind(conn, path, &file);
		debug_info("handling %s request to %s done"CLR_LN, conn->method, path);
		return;
	}
	/* 13.2. Handle OPTIONS for files */
	if (!strcmp(conn->method, "OPTIONS")) {
		/* This standard handler is only used for real files.
		 * Scripts should support the OPTIONS method themselves, to allow a
		 * maximum flexibility.
		 * Lua and CGI scripts may fully support CORS this way (including
		 * preflights). */
		http_options(conn);
		debug_info("handling %s request to %s done"CLR_LN, conn->method, path);
		return;
	}
	/* 13.3. everything but GET and HEAD (e.g. POST) */
	if (strcmp(conn->method, "GET") && strcmp(conn->method, "HEAD")) {
		http_error(conn,
			405,
			"%s method not allowed",
			conn->method);
		debug_info("handling %s request to %s done"CLR_LN, conn->method, path);
		return;
	}

	/* 14. directories */
	if (file.is_directory) {
		/* Substitute files have already been handled above. */
		/* Here we can either generate and send a directory listing,
		 * or send an "access denied" error. */
		if (str_is_case(conn->domain->config[ENABLE_DIRECTORY_LISTING],
			"yes")) {
			handle_directory_request(conn, path);
		} else {
			http_error(conn,
				403,
				"%s",
				"Error: Directory listing denied");
		}
		debug_info("handling %s request to %s done"CLR_LN, conn->method, path);
		return;
	}

	/* 15. Files with search/replace patterns: LSP and SSI */
	if (is_template_text_file) {
		if (conn->req.proto == PROTOCOL_HTTP2) {
			//http2_must_use_http1(conn);
			debug_info("%s", "must use HTTP/1.x"CLR_LN);
			//return;
		}
		handle_file_based_request(conn, path, &file);
		debug_info("handling %s request to %s done (template)"CLR_LN, conn->method, path);
		return;
	}

	/* 16. Static file - maybe cached */
	if ((!conn->req.in_error_handler) && is_not_modified(conn, &file)) {
		/* Send 304 "Not Modified" - this must not send any body data */
		handle_not_modified_static_file_request(conn, &file);
		debug_info("handling %s request to %s done (not modified)"CLR_LN, conn->method, path);
		return;
	}
	/* 17. Static file - not cached */
	handle_static_file_request(conn, path, &file, NULL, NULL);// `path` buffer overrun issue
	debug_info("handling %s request to %s done (static)"CLR_LN, conn->method, path);
}
