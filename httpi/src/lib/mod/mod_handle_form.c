#include "../httpi_internal.h"

#define MAX_HEADERS 64

struct multi_form_header {
	string_t name;  /* HTTP header name */
	string_t value; /* HTTP header value */
};

struct multi_request_info {
	/* Length (in bytes) of the request body,
	can be -1 if no length was given. */
	long long content_length;
	/* Number of HTTP headers */
	int num_headers;
	/* Allocate maximum headers */
	struct multi_form_header http_headers[MAX_HEADERS];
};

/* Check whether full request is buffered. Return:
 * -1  if request is malformed
 *  0  if request is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n */
static int get_request_len(string_t buf, int buflen) {
	string_t s, e;
	int len = 0;

	for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++)
		/* Control characters are not allowed but >=128 is. */
		if (!isprint(*(const unsigned char *)s) && *s != '\r' && *s != '\n' &&
			*(const unsigned char *)s < 128) {
			len = -1;
			break; /* [i_a] abort scan as soon as one malformed character is
					* found; */
			/* don't let subsequent \r\n\r\n win us over anyhow */
		} else if (s[0] == '\n' && s[1] == '\n') {
			len = (int)(s - buf) + 2;
		} else if (s[0] == '\n' && &s[1] < e && s[1] == '\r' && s[2] == '\n') {
			len = (int)(s - buf) + 3;
		}

		return len;
}

/* Parse HTTP headers from the given buffer, advance buf pointer
 * to the point where parsing stopped.
 * All parameters must be valid pointers (not NULL).
 * Return <0 on error. */
static int parse_form_headers(string *buf, struct multi_form_header hdr[MAX_HEADERS]) {
	int i;
	int num_headers = 0;

	for (i = 0; i < (int)MAX_HEADERS; i++) {
		string dp = *buf;

		/* Skip all ASCII characters (>SPACE, <127), to find a ':' */
		while ((*dp != ':') && (*dp >= 33) && (*dp <= 126)) {
			dp++;
		}
		if (dp == *buf) {
			/* End of headers reached. */
			break;
		}

		/* Drop all spaces after header name before : */
		while (*dp == ' ') {
			*dp = 0;
			dp++;
		}
		if (*dp != ':') {
			/* This is not a valid field. */
			return -1;
		}

		/* End of header key (*dp == ':') */
		/* Truncate here and set the key name */
		*dp = 0;
		hdr[i].name = *buf;

		/* Skip all spaces */
		do {
			dp++;
		} while ((*dp == ' ') || (*dp == '\t'));

		/* The rest of the line is the value */
		hdr[i].value = dp;

		/* Find end of line */
		while ((*dp != 0) && (*dp != '\r') && (*dp != '\n')) {
			dp++;
		};

		/* eliminate \r */
		if (*dp == '\r') {
			*dp = 0;
			dp++;
			if (*dp != '\n') {
				/* This is not a valid line. */
				return -1;
			}
		}

		/* here *dp is either 0 or '\n' */
		/* in any case, we have found a complete header */
		num_headers = i + 1;

		if (*dp) {
			*dp = 0;
			dp++;
			*buf = dp;

			if ((dp[0] == '\r') || (dp[0] == '\n')) {
				/* We've had CRLF twice in a row
				 * This is the end of the headers */
				break;
			}
			/* continue within the loop, find the next header */
		} else {
			*buf = dp;
			break;
		}
	}

	return num_headers;
}

/* Return HTTP header value, or NULL if not found. */
static string_t get_header(struct multi_form_header *hdr, int num_hdr, string_t name) {
	int i;
	for (i = 0; i < num_hdr; i++) {
		if (str_is_case(name, hdr[i].name)) {
			return hdr[i].value;
		}
	}

	return NULL;
}

static int url_encoded_field_found(http_t *conn, string_t key, size_t key_len, string_t filename,
	size_t filename_len, string path, size_t path_len, form_data_handler_t *fdh) {
	char key_dec[1024];
	char filename_dec[1024];
	int key_dec_len;
	int filename_dec_len;
	int ret;

	key_dec_len = http_url_decode(key, (int)key_len, key_dec, (int)sizeof(key_dec), 1);

	if (((size_t)key_dec_len >= (size_t)sizeof(key_dec)) || (key_dec_len < 0)) {
		return FORM_FIELD_STORAGE_ABORT;
	}

	if (filename) {
		filename_dec_len = http_url_decode(filename,
			(int)filename_len,
			filename_dec,
			(int)sizeof(filename_dec),
			1);

		if (((size_t)filename_dec_len >= (size_t)sizeof(filename_dec))
			|| (filename_dec_len < 0)) {
			/* Log error message and skip this field. */
			http_log(DEBUG_ERROR, conn, "%s: Cannot decode filename", __func__);
			return FORM_FIELD_STORAGE_ABORT;
		}
		remove_double_dots_slashes(filename_dec);

	} else {
		filename_dec[0] = 0;
	}

	ret =
		fdh->field_found(key_dec, filename_dec, path, path_len, fdh->user_data);

	if ((ret & 0xF) == FORM_FIELD_STORAGE_GET) {
		if (fdh->field_get == NULL) {
			http_log(DEBUG_ERROR, conn,
				"%s: Function \"Get\" not available",
				__func__);
			return FORM_FIELD_STORAGE_SKIP;
		}
	}
	if ((ret & 0xF) == FORM_FIELD_STORAGE_STORE) {
		if (fdh->field_store == NULL) {
			http_log(DEBUG_ERROR, conn,
				"%s: Function \"Store\" not available",
				__func__);
			return FORM_FIELD_STORAGE_SKIP;
		}
	}

	return ret;
}

static int url_encoded_field_get(
	http_t *conn,
	string_t key,
	size_t key_len,
	string_t value,
	size_t *value_len, /* IN: number of bytes available in "value", OUT: number
						  of bytes processed */
	form_data_handler_t *fdh) {
	char key_dec[1024];
	int key_dec_len;

	string value_dec = (string)malloc(*value_len + 1);
	int value_dec_len, ret;

	if (!value_dec) {
		/* Log error message and stop parsing the form data. */
		http_log(DEBUG_ERROR, conn,
			"%s: Not enough memory (required: %lu)",
			__func__,
			(unsigned long)(*value_len + 1));
		return FORM_FIELD_STORAGE_ABORT;
	}

	key_dec_len =
		http_url_decode(key, (int)key_len, key_dec, (int)sizeof(key_dec), 1);

	if (*value_len >= 2 && value[*value_len - 2] == '%')
		*value_len -= 2;
	else if (*value_len >= 1 && value[*value_len - 1] == '%')
		(*value_len)--;
	value_dec_len = http_url_decode(
		value, (int)*value_len, value_dec, ((int)*value_len) + 1, 1);

	if ((key_dec_len < 0) || (value_dec_len < 0)) {
		free(value_dec);
		return FORM_FIELD_STORAGE_ABORT;
	}

	ret = fdh->field_get(key_dec,
		value_dec,
		(size_t)value_dec_len,
		fdh->user_data);

	free(value_dec);

	return ret;
}

static int unencoded_field_get(http_t *conn, string_t key, size_t key_len,
	string_t value, size_t value_len, form_data_handler_t *fdh) {
	char key_dec[1024];
	int key_dec_len;
	(void)conn;

	key_dec_len = http_url_decode(key, (int)key_len, key_dec, (int)sizeof(key_dec), 1);
	if (key_dec_len < 0) {
		return FORM_FIELD_STORAGE_ABORT;
	}

	return fdh->field_get(key_dec, value, value_len, fdh->user_data);
}

static int field_stored(http_t *conn, string_t path, long long file_size, form_data_handler_t *fdh) {
	/* Equivalent to "upload" callback of "http_upload". */
	(void)conn;
	return fdh->field_store(path, file_size, fdh->user_data);
}

static string_t search_boundary(string_t buf,
	size_t buf_len,
	string_t boundary,
	size_t boundary_len) {
	string boundary_start = "\r\n--";
	size_t boundary_start_len = strlen(boundary_start);

	/* We must do a binary search here, not a string search, since the
	 * buffer may contain '\x00' bytes, if binary data is transferred. */
	int clen = (int)buf_len - (int)boundary_len - boundary_start_len;
	int i;

	for (i = 0; i <= clen; i++) {
		if (!memcmp(buf + i, boundary_start, boundary_start_len)) {
			if (!memcmp(buf + i + boundary_start_len, boundary, boundary_len)) {
				return buf + i;
			}
		}
	}
	return NULL;
}

struct upload_user_data {
	http_t *conn;
	string_t destination_dir;
	int num_uploaded_files;
};

static int http_upload_field_found(string_t key,
	string_t filename,
	char *path,
	size_t pathlen,
	void *user_data) {
	int truncated = 0;
	struct upload_user_data *fud = (struct upload_user_data *)user_data;
	(void)key;

	if (!filename) {
		http_log(DEBUG_ERROR, fud->conn, "%s: No filename set", __func__);
		return FORM_FIELD_STORAGE_ABORT;
	}

	http_snprintf(&truncated,
		path,
		pathlen - 1,
		"%s/%s",
		fud->destination_dir,
		filename);
	if (!truncated) {
		http_log(DEBUG_ERROR, fud->conn, "%s: File path too long", __func__);
		return FORM_FIELD_STORAGE_ABORT;
	}

	return FORM_FIELD_STORAGE_STORE;
}

static int http_upload_field_get(string_t key,
	string_t value,
	size_t value_size,
	void *user_data) {
/* Function should never be called */
	(void)key;
	(void)value;
	(void)value_size;
	(void)user_data;

	return 0;
}

static int http_upload_field_stored(string_t path, int64_t file_size, void *user_data) {
	struct upload_user_data *fud = (struct upload_user_data *)user_data;
	(void)file_size;

	fud->num_uploaded_files++;
	fud->conn->ctx->callbacks.upload(fud->conn, path);

	return 0;
}

int http_form_upload(http_t *conn, string_t destination_dir) {
	string_t content_type_header, boundary_start, sc;
	string s;
	char buf[BUF_LEN], path[PATH_MAX], tmp_path[PATH_MAX], fname[1024],
		boundary[100];
	struct file fp = STRUCT_FILE_INITIALIZER;
	int bl, n, i, headers_len, boundary_len, eof, len = 0,
		num_uploaded_files = 0;

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
	if ((content_type_header = http_get_header(conn, "Content-Type")) == NULL
		|| conn->boundary == NULL) {
		return num_uploaded_files;
	}

	snprintf(boundary, sizeof(boundary), "%s", conn->boundary);
	boundary[99] = '\0';
	boundary_len = (int)strlen(conn->boundary);
	bl = boundary_len + 4; /* \r\n--<boundary> */
	for (;;) {
		/* Pull in headers */
		/* assert(len >= 0 && len <= (int) sizeof(buf)); */
		if (len < 0 || len >(int)sizeof(buf)) {
			break;
		}
		while ((n = http_read(conn, buf + len, sizeof(buf) - (size_t)len)) > 0) {
			len += n;
			/* assert(len <= (int) sizeof(buf)); */
			if (len > (int)sizeof(buf)) {
				break;
			}
		}
		if ((headers_len = get_request_len(buf, len)) <= 0) {
			break;
		}

		/* terminate header */
		buf[headers_len - 1] = 0;

		/* Scan for the boundary string and skip it */
		if (buf[0] == '-' && buf[1] == '-' &&
			!memcmp(buf + 2, boundary, (size_t)boundary_len)) {
			s = &buf[bl];
		} else {
			s = &buf[2];
		}

		/* Get headers for this part of the multipart message */
		conn->body = buf;
		parse_multipart(conn);
		/* assert(&buf[headers_len-1] == s); */
		if (&buf[headers_len - 1] != s) {
			break;
		}

		/* Fetch file name. */
		sc = http_get_header(conn, "Content-Disposition");
		if (!sc) {
			/* invalid part of a multipart message */
			break;
		}

		sc = strstr(sc, "filename");
		if (!sc) {
			/* no filename set */
			break;
		}
		sc += 8; /* skip "filename" */
		fname[0] = '\0';
		(void)(sscanf(sc, " = \"%1023[^\"]", fname));
		fname[1023] = 0;

		/* Give up if the headers are not what we expect */
		if (fname[0] == '\0') {
			break;
		}

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
		snprintf(path, sizeof(path) - 1, "%s/%s", destination_dir, s);
		strcpy(tmp_path, path);
		strcat(tmp_path, "~");

		/* We open the file with exclusive lock held. This guarantee us
		 * there is no other thread can save into the same file
		 * simultaneously. */
		fp.pf = promise_fopen(tmp_path, "wb");
		/* Open file in binary mode. */
		if ((fp.fp = (FILE *)promise_wait(fp.pf).object) == NULL) {
			promise_clean(fp.pf);
			break;
		}

		/* Move data to the beginning of the buffer */
		/* part_request_info is no longer valid after this operation */
		/* assert(len >= headers_len); */
		if (len < headers_len) {
			break;
		}
		memmove(buf, &buf[headers_len], (size_t)(len - headers_len));
		len -= headers_len;

		/* Read POST data, write into file until boundary is found. */
		eof = n = 0;
		do {
			len += n;
			for (i = 0; i < len - bl; i++) {
				if (!memcmp(&buf[i], "\r\n--", 4) &&
					!memcmp(&buf[i + 4], boundary, (size_t)boundary_len)) {
					/* Found boundary, that's the end of file data. */
					promise_fwrite(fp.pf, buf, 1, (size_t)i, fp.fp);
					eof = 1;
					memmove(buf, &buf[i + bl], (size_t)(len - (i + bl)));
					len -= i + bl;
					break;
				}
			}
			if (!eof && len > bl) {
				promise_fwrite(fp.pf, buf, 1, (size_t)(len - bl), fp.fp);
				memmove(buf, &buf[len - bl], (size_t)bl);
				len = bl;
			}
			n = http_read(conn, buf + len, sizeof(buf) - ((size_t)(len)));
		} while (!eof && (n > 0));
		promise_fclose(fp.pf, fp.fp);
		if (eof) {
			fs_unlink(path);
			fs_rename(tmp_path, path);
			num_uploaded_files++;
			if (conn && conn->ctx && conn->ctx->callbacks.upload != NULL) {
				conn->ctx->callbacks.upload(conn, path);
			}
		} else {
			fs_unlink(tmp_path);
		}
	}

	return num_uploaded_files;
}

int http_upload(http_t *conn, string_t destination_dir) {
	struct upload_user_data fud = {conn, destination_dir, 0};
	form_data_handler_t fdh = {http_upload_field_found, http_upload_field_get, http_upload_field_stored, 0};
	int ret;

	fdh.user_data = (void *)&fud;
	ret = http_handle_form_request(conn, &fdh);
	if (ret < 0) {
		http_log(DEBUG_ERROR, conn, "%s: Error while parsing the request", __func__);
	}

	return fud.num_uploaded_files;
}

int http_handle_form_request(http_t *conn, form_data_handler_t *fdh) {
	string_t content_type;
	char path[512];
	char buf[BUF_LEN]; /* Must not be smaller than ~900 */
	int field_storage;
	size_t buf_fill = 0;
	int r;
	int field_count = 0;
	int abort_read = 0;
	struct file fstore = STRUCT_FILE_INITIALIZER;
	int64_t file_size = 0; /* init here, to a avoid a false positive
							 "uninitialized variable used" warning */

	int has_body_data = (conn->content_length > 0) || (conn->req.is_chunked);

	/* Unused without filesystems */
	(void)fstore;
	(void)file_size;

	/* There are three ways to encode data from a HTML form:
	 * 1) method: GET (default)
	 *    The form data is in the HTTP query string.
	 * 2) method: POST, enctype: "application/x-www-form-urlencoded"
	 *    The form data is in the request body.
	 *    The body is url encoded (the default encoding for POST).
	 * 3) method: POST, enctype: "multipart/form-data".
	 *    The form data is in the request body of a multipart message.
	 *    This is the typical way to handle file upload from a form.
	 */

	if (!has_body_data) {
		string_t data;

		if (0 != strcmp(conn->method, "GET")) {
			/* No body data, but not a GET request.
			 * This is not a valid form request. */
			return -1;
		}

		/* GET request: form data is in the query string. */
		/* The entire data has already been loaded, so there is no need to
		 * call `http_read`. We just need to split the query string into key-value
		 * pairs. */
		data = conn->req.query_string;
		if (!data) {
			/* No query string. */
			return -1;
		}

		/* Split data in a=1&b=xy&c=3&c=4 ... */
		while (*data) {
			string_t val = strchr(data, '=');
			string_t next;
			ptrdiff_t keylen, vallen;

			if (!val) {
				break;
			}
			keylen = val - data;

			/* In every "field_found" callback we ask what to do with the
			 * data ("field_storage"). This could be:
			 * FORM_FIELD_STORAGE_SKIP (0):
			 *   ignore the value of this field
			 * FORM_FIELD_STORAGE_GET (1):
			 *   read the data and call the get callback function
			 * FORM_FIELD_STORAGE_STORE (2):
			 *   store the data in a file
			 * FORM_FIELD_STORAGE_READ (3):
			 *   let the user read the data (for parsing long data on the fly)
			 * FORM_FIELD_STORAGE_ABORT (flag):
			 *   stop parsing
			 */
			memset(path, 0, sizeof(path));
			field_count++;
			field_storage = url_encoded_field_found(conn,
				data,
				(size_t)keylen,
				NULL,
				0,
				path,
				sizeof(path) - 1,
				fdh);

			val++;
			next = strchr(val, '&');
			if (next) {
				vallen = next - val;
			} else {
				vallen = (ptrdiff_t)strlen(val);
			}

			if (field_storage == FORM_FIELD_STORAGE_GET) {
				/* Call callback */
				r = url_encoded_field_get(
					conn, data, (size_t)keylen, val, (size_t *)&vallen, fdh);
				if (r == FORM_FIELD_HANDLE_ABORT) {
					/* Stop request handling */
					abort_read = 1;
					break;
				}
				if (r == FORM_FIELD_HANDLE_NEXT) {
					/* Skip to next field */
					field_storage = FORM_FIELD_STORAGE_SKIP;
				}
			}

			if (next) {
				next++;
			} else {
				/* vallen may have been modified by url_encoded_field_get */
				next = val + vallen;
			}

			if (field_storage == FORM_FIELD_STORAGE_STORE) {
				/* Store the content to a file */
				if (http_fopen(conn->ctx, conn, path, "wb", &fstore) == 0) {
					fstore.fp = NULL;
				}
				file_size = 0;
				if (fstore.fp != NULL) {
					size_t n = (size_t)
						promise_fwrite(fstore.pf, (void_t)val, 1, (size_t)vallen, fstore.fp);
					if ((n != (size_t)vallen) || (ferror(fstore.fp))) {
						http_log(DEBUG_ERROR, conn,
							"%s: Cannot write file %s",
							__func__,
							path);
						(void)http_fclose(&fstore);
						http_remove_bad_file(conn->ctx, conn, path);
					}
					file_size += (int64_t)n;

					if (fstore.fp) {
						r = http_fclose(&fstore);
						if (r == 0) {
							/* stored successfully */
							r = field_stored(conn, path, file_size, fdh);
							if (r == FORM_FIELD_HANDLE_ABORT) {
								/* Stop request handling */
								abort_read = 1;
								break;
							}

						} else {
							http_log(DEBUG_ERROR, conn,
								"%s: Error saving file %s",
								__func__,
								path);
							http_remove_bad_file(conn->ctx, conn, path);
						}
						fstore.fp = NULL;
					}

				} else {
					http_log(DEBUG_ERROR, conn,
						"%s: Cannot create file %s",
						__func__,
						path);
				}
			}

			/* if (field_storage == FORM_FIELD_STORAGE_READ) { */
			/* The idea of "field_storage=read" is to let the API user read
			 * data chunk by chunk and to some data processing on the fly.
			 * This should avoid the need to store data in the server:
			 * It should neither be stored in memory, like
			 * "field_storage=get" does, nor in a file like
			 * "field_storage=store".
			 * However, for a "GET" request this does not make any much
			 * sense, since the data is already stored in memory, as it is
			 * part of the query string. */
			/* } */
			if ((field_storage & FORM_FIELD_STORAGE_ABORT)
				== FORM_FIELD_STORAGE_ABORT) {
				/* Stop parsing the request */
				abort_read = 1;
				break;
			}

			/* Proceed to next entry */
			data = next;
		}

		return field_count;
	}

	content_type = http_get_header(conn, "Content-Type");
	if (!content_type
		|| str_case_equal(content_type, "APPLICATION/X-WWW-FORM-URLENCODED", 33)
		|| str_case_equal(content_type, "APPLICATION/WWW-FORM-URLENCODED", 31)) {
		/* The form data is in the request body data, encoded in key/value pairs. */
		int all_data_read = 0;

		/* Read body data and split it in keys and values.
		 * The encoding is like in the "GET" case above: a=1&b&c=3&c=4.
		 * Here we use "POST", and read the data from the request body.
		 * The data read on the fly, so it is not required to buffer the
		 * entire request in memory before processing it. */
		while (!abort_read) {
			string_t val;
			string_t next;
			ptrdiff_t keylen, vallen;
			ptrdiff_t used;
			int end_of_key_value_pair_found = 0;
			int get_block;

			if (buf_fill < (sizeof(buf) - 1)) {
				size_t to_read = sizeof(buf) - 1 - buf_fill;
				r = http_read(conn, buf + buf_fill, to_read);
				if ((r < 0) || ((r == 0) && all_data_read)) {
					/* read error */
					return -1;
				}

				if (r == 0) {
					/* TODO: Create a function to get "all_data_read" from
					 * the conn object. All data is read if the Content-Length
					 * has been reached, or if chunked encoding is used and
					 * the end marker has been read, or if the connection has
					 * been closed. */
					all_data_read = (buf_fill == 0);
				}
				buf_fill += r;
				buf[buf_fill] = 0;
				if (buf_fill < 1) {
					break;
				}
			}

			val = strchr(buf, '=');

			if (!val) {
				break;
			}
			keylen = val - buf;
			val++;

			/* Call callback */
			memset(path, 0, sizeof(path));
			field_count++;
			field_storage = url_encoded_field_found(conn,
				buf,
				(size_t)keylen,
				NULL,
				0,
				path,
				sizeof(path) - 1,
				fdh);

			if ((field_storage & FORM_FIELD_STORAGE_ABORT)
				== FORM_FIELD_STORAGE_ABORT) {
				/* Stop parsing the request */
				abort_read = 1;
				break;
			}

			if (field_storage == FORM_FIELD_STORAGE_STORE) {
				if (http_fopen(conn->ctx, conn, path, "wb", &fstore) == 0) {
					fstore.fp = NULL;
				}

				file_size = 0;
				if (!fstore.fp) {
					http_log(DEBUG_ERROR, conn,
						"%s: Cannot create file %s",
						__func__,
						path);
				}
			}

			get_block = 0;
			/* Loop to read values larger than sizeof(buf)-keylen-2 */
			do {
				next = strchr(val, '&');
				if (next) {
					vallen = next - val;
					end_of_key_value_pair_found = 1;
				} else {
					vallen = (ptrdiff_t)strlen(val);
					end_of_key_value_pair_found = all_data_read;
					if ((buf + buf_fill) > (val + vallen)) {
						/* Avoid DoS attacks by having a zero byte in the middle
						 * of a request that is supposed to be URL encoded.
						 * Since this request is certainly invalid, according to
						 * the protocol
						 * specification, stop processing it. Fixes #1348 */
						abort_read = 1;
						break;
					}
				}

				if (field_storage == FORM_FIELD_STORAGE_GET) {
					/* Call callback */
					r = url_encoded_field_get(conn,
						((get_block > 0) ? NULL : buf),
						((get_block > 0)
							? 0
							: (size_t)keylen),
						val,
						(size_t *)&vallen,
						fdh);
					get_block++;
					if (r == FORM_FIELD_HANDLE_ABORT) {
						/* Stop request handling */
						abort_read = 1;
						break;
					}
					if (r == FORM_FIELD_HANDLE_NEXT) {
						/* Skip to next field */
						field_storage = FORM_FIELD_STORAGE_SKIP;
					}
				}

				if (next) {
					next++;
				} else {
					/* vallen may have been modified by url_encoded_field_get */
					next = val + vallen;
				}

				if (fstore.fp) {
					size_t n = (size_t)
						promise_fwrite(fstore.pf, (void_t)val, 1, (size_t)vallen, fstore.fp);
					if ((n != (size_t)vallen) || (ferror(fstore.fp))) {
						http_log(DEBUG_ERROR, conn,
							"%s: Cannot write file %s",
							__func__,
							path);
						http_fclose(&fstore);
						http_remove_bad_file(conn->ctx, conn, path);
					}
					file_size += (int64_t)n;
				}

				if (!end_of_key_value_pair_found) {
					used = next - buf;
					memmove(buf,
						buf + (size_t)used,
						sizeof(buf) - (size_t)used);
					next = buf;
					buf_fill -= used;
					if (buf_fill < (sizeof(buf) - 1)) {

						size_t to_read = sizeof(buf) - 1 - buf_fill;
						r = http_read(conn, buf + buf_fill, to_read);
						if ((r < 0) || ((r == 0) && all_data_read)) {
							/* read error */
							if (fstore.fp) {
								http_fclose(&fstore);
								http_remove_bad_file(conn->ctx, conn, path);
							}
							return -1;
						}
						if (r == 0) {
							/* TODO: Create a function to get "all_data_read"
							 * from the conn object. All data is read if the
							 * Content-Length has been reached, or if chunked
							 * encoding is used and the end marker has been
							 * read, or if the connection has been closed. */
							all_data_read = (buf_fill == 0);
						}
						buf_fill += r;
						buf[buf_fill] = 0;
						if (buf_fill < 1) {
							break;
						}
						val = buf;
					}
				}
			} while (!end_of_key_value_pair_found);

			if (fstore.fp) {
				r = http_fclose(&fstore);
				if (r == 0) {
					/* stored successfully */
					r = field_stored(conn, path, file_size, fdh);
					if (r == FORM_FIELD_HANDLE_ABORT) {
						/* Stop request handling */
						abort_read = 1;
						break;
					}
				} else {
					http_log(DEBUG_ERROR, conn,
						"%s: Error saving file %s",
						__func__,
						path);
					http_remove_bad_file(conn->ctx, conn, path);
				}
				fstore.fp = NULL;
			}

			if ((all_data_read && (buf_fill == 0)) || abort_read) {
				/* nothing more to process */
				break;
			}

			/* Proceed to next entry */
			used = next - buf;
			memmove(buf, buf + (size_t)used, sizeof(buf) - (size_t)used);
			buf_fill -= used;
		}

		return field_count;
	}

	if (str_case_equal(content_type, "MULTIPART/FORM-DATA;", 20)) {
		/* The form data is in the request body data, encoded as multipart
		 * content (see https://www.ietf.org/rfc/rfc1867.txt,
		 * https://www.ietf.org/rfc/rfc2388.txt). */
		string boundary;
		size_t bl;
		ptrdiff_t used;
		struct multi_request_info part_header;
		string hbuf;
		string_t content_disp, hend, fbeg, fend, nbeg, nend;
		string_t next;
		unsigned part_no;
		int all_data_read = 0;

		memset(&part_header, 0, sizeof(part_header));
		/* Skip all spaces between MULTIPART/FORM-DATA; and BOUNDARY= */
		bl = 20;
		while (content_type[bl] == ' ') {
			bl++;
		}

		/* There has to be a BOUNDARY definition in the Content-Type header */
		if (!str_case_equal(content_type + bl, "BOUNDARY=", 9)) {
			/* Malformed request */
			return -1;
		}

		/* Copy boundary string to variable "boundary" */
		/* fbeg is pointer to start of value of boundary */
		fbeg = content_type + bl + 9;
		bl = strlen(fbeg);
		boundary = (string)malloc(bl + 1);
		if (!boundary) {
			/* Out of memory */
			http_log(DEBUG_ERROR, conn,
				"%s: Cannot allocate memory for boundary [%lu]",
				__func__,
				(unsigned long)bl);
			return -1;
		}
		memcpy(boundary, fbeg, bl);
		boundary[bl] = 0;

		/* RFC 2046 permits the boundary string to be quoted. */
		/* If the boundary is quoted, trim the quotes */
		if (boundary[0] == '"') {
			hbuf = strchr(boundary + 1, '"');
			if ((!hbuf) || (*hbuf != '"')) {
				/* Malformed request */
				free(boundary);
				return -1;
			}
			*hbuf = 0;
			memmove(boundary, boundary + 1, bl);
			bl = strlen(boundary);
		}

		/* Do some sanity checks for boundary lengths */
		if (bl > 70) {
			/* From RFC 2046:
			 * Boundary delimiters must not appear within the
			 * encapsulated material, and must be no longer
			 * than 70 characters, not counting the two
			 * leading hyphens.
			 */

			/* The algorithm can not work if bl >= sizeof(buf), or if buf
			 * can not hold the multipart header plus the boundary.
			 * Requests with long boundaries are not RFC compliant, maybe they
			 * are intended attacks to interfere with this algorithm. */
			free(boundary);
			return -1;
		}
		if (bl < 4) {
			/* Sanity check:  A boundary string of less than 4 bytes makes
			 * no sense either. */
			free(boundary);
			return -1;
		}

		for (part_no = 0;; part_no++) {
			size_t towrite, fnlen, n;
			int get_block;
			size_t to_read = sizeof(buf) - 1 - buf_fill;

			/* Unused without filesystems */
			(void)n;

			r = http_read(conn, buf + buf_fill, to_read);
			if ((r < 0) || ((r == 0) && all_data_read)) {
				/* read error */
				free(boundary);
				return -1;
			}
			if (r == 0) {
				all_data_read = (buf_fill == 0);
			}

			buf_fill += r;
			buf[buf_fill] = 0;
			if (buf_fill < 1) {
				/* No data */
				free(boundary);
				return -1;
			}

			/* @see https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1
			 *
			 * multipart-body := [preamble CRLF]
			 *     dash-boundary transport-padding CRLF
			 *     body-part *encapsulation
			 *     close-delimiter transport-padding
			 *     [CRLF epilogue]
			 */

			if (part_no == 0) {
				size_t preamble_length = 0;
				/* skip over the preamble until we find a complete boundary
				 * limit the preamble length to prevent abuse */
				/* +2 for the -- preceding the boundary */
				while (preamble_length < 1024
					&& (preamble_length < buf_fill - bl)
					&& strncmp(buf + preamble_length + 2, boundary, bl)) {
					preamble_length++;
				}
				/* reset the start of buf to remove the preamble */
				if (0 == strncmp(buf + preamble_length + 2, boundary, bl)) {
					memmove(buf,
						buf + preamble_length,
						(unsigned)buf_fill - (unsigned)preamble_length);
					buf_fill -= preamble_length;
					buf[buf_fill] = 0;
				}
			}

			/* either it starts with a boundary and it's fine, or it's malformed
			 * because:
			 * - the preamble was longer than accepted
			 * - couldn't find a boundary at all in the body
			 * - didn't have a terminating boundary */
			if (buf_fill < (bl + 2) || strncmp(buf, "--", 2)
				|| strncmp(buf + 2, boundary, bl)) {
				/* Malformed request */
				free(boundary);
				return -1;
			}

			/* skip the -- */
			string boundary_start = buf + 2;
			size_t transport_padding = 0;
			while (boundary_start[bl + transport_padding] == ' '
				|| boundary_start[bl + transport_padding] == '\t') {
				transport_padding++;
			}
			string boundary_end = boundary_start + bl + transport_padding;

			/* after the transport padding, if the boundary isn't
			 * immediately followed by a \r\n then it is either... */
			if (strncmp(boundary_end, "\r\n", 2)) {
				/* ...the final boundary, and it is followed by --, (in which
				 * case it's the end of the request) or it's a malformed
				 * request */
				if (strncmp(boundary_end, "--", 2)) {
					/* Malformed request */
					free(boundary);
					return -1;
				}
				/* Ingore any epilogue here */
				break;
			}

			/* skip the \r\n */
			hbuf = boundary_end + 2;
			/* Next, we need to get the part header: Read until \r\n\r\n */
			hend = strstr(hbuf, "\r\n\r\n");
			if (!hend) {
				/* Malformed request */
				free(boundary);
				return -1;
			}

			part_header.num_headers = parse_form_headers(&hbuf, part_header.http_headers);
			if ((hend + 2) != hbuf) {
				/* Malformed request */
				free(boundary);
				return -1;
			}

			/* Skip \r\n\r\n */
			hend += 4;

			/* According to the RFC, every part has to have a header field like:
			 * Content-Disposition: form-data; name="..." */
			content_disp = get_header(part_header.http_headers, part_header.num_headers, "Content-Disposition");
			if (!content_disp) {
				/* Malformed request */
				free(boundary);
				return -1;
			}

			/* Get the mandatory name="..." part of the Content-Disposition
			 * header. */
			nbeg = strstr(content_disp, "name=\"");
			while ((nbeg != NULL) && (strcspn(nbeg - 1, ":,; \t") != 0)) {
				/* It could be somethingname= instead of name= */
				nbeg = strstr(nbeg + 1, "name=\"");
			}

			/* This line is not required, but otherwise some compilers
			 * generate spurious warnings. */
			nend = nbeg;
			/* And others complain, the result is unused. */
			(void)nend;

			/* If name=" is found, search for the closing " */
			if (nbeg) {
				nbeg += 6;
				nend = strchr(nbeg, '\"');
				if (!nend) {
					/* Malformed request */
					free(boundary);
					return -1;
				}
			} else {
				/* name= without quotes is also allowed */
				nbeg = strstr(content_disp, "name=");
				while ((nbeg != NULL) && (strcspn(nbeg - 1, ":,; \t") != 0)) {
					/* It could be somethingname= instead of name= */
					nbeg = strstr(nbeg + 1, "name=");
				}
				if (!nbeg) {
					/* Malformed request */
					free(boundary);
					return -1;
				}
				nbeg += 5;

				/* RFC 2616 Sec. 2.2 defines a list of allowed
				 * separators, but many of them make no sense
				 * here, e.g. various brackets or slashes.
				 * If they are used, probably someone is
				 * trying to attack with curious hand made
				 * requests. Only ; , space and tab seem to be
				 * reasonable here. Ignore everything else. */
				nend = nbeg + strcspn(nbeg, ",; \t");
			}

			/* Get the optional filename="..." part of the Content-Disposition
			 * header. */
			fbeg = strstr(content_disp, "filename=\"");
			while ((fbeg != NULL) && (strcspn(fbeg - 1, ":,; \t") != 0)) {
				/* It could be somethingfilename= instead of filename= */
				fbeg = strstr(fbeg + 1, "filename=\"");
			}

			/* This line is not required, but otherwise some compilers
			 * generate spurious warnings. */
			fend = fbeg;

			/* If filename=" is found, search for the closing " */
			if (fbeg) {
				fbeg += 10;
				fend = strchr(fbeg, '\"');

				if (!fend) {
					/* Malformed request (the filename field is optional, but if
					 * it exists, it needs to be terminated correctly). */
					free(boundary);
					return -1;
				}

				/* TODO: check Content-Type */
				/* Content-Type: application/octet-stream */
			}
			if (!fbeg) {
				/* Try the same without quotes */
				fbeg = strstr(content_disp, "filename=");
				while ((fbeg != NULL) && (strcspn(fbeg - 1, ":,; \t") != 0)) {
					/* It could be somethingfilename= instead of filename= */
					fbeg = strstr(fbeg + 1, "filename=");
				}
				if (fbeg) {
					fbeg += 9;
					fend = fbeg + strcspn(fbeg, ",; \t");
				}
			}

			if (!fbeg || !fend) {
				fbeg = NULL;
				fend = NULL;
				fnlen = 0;
			} else {
				fnlen = (size_t)(fend - fbeg);
			}

			/* In theory, it could be possible that someone crafts
			 * a request like name=filename=xyz. Check if name and
			 * filename do not overlap. */
			if (!(((ptrdiff_t)fbeg > (ptrdiff_t)nend)
				|| ((ptrdiff_t)nbeg > (ptrdiff_t)fend))) {
				free(boundary);
				return -1;
			}

			/* Call callback for new field */
			memset(path, 0, sizeof(path));
			field_count++;
			field_storage = url_encoded_field_found(conn,
				nbeg,
				(size_t)(nend - nbeg),
				((fnlen > 0) ? fbeg : NULL),
				fnlen,
				path,
				sizeof(path) - 1,
				fdh);

				/* If the boundary is already in the buffer, get the address,
				* otherwise next will be NULL. */
			next = search_boundary(hbuf,
				(size_t)((buf - hbuf) + buf_fill),
				boundary,
				bl);

			if (field_storage == FORM_FIELD_STORAGE_STORE) {
				/* Store the content to a file */
				if (http_fopen(conn->ctx, conn, path, "wb", &fstore) == 0) {
					fstore.fp = NULL;
				}
				file_size = 0;

				if (!fstore.fp) {
					http_log(DEBUG_ERROR, conn,
						"%s: Cannot create file %s",
						__func__,
						path);
				}
			}

			get_block = 0;
			while (!next) {
				/* Set "towrite" to the number of bytes available
				 * in the buffer */
				towrite = (size_t)(buf - hend + buf_fill);

				if (towrite < bl + 4) {
					/* Not enough data stored. */
					/* Incomplete request. */
					free(boundary);
					return -1;
				}

				/* Subtract the boundary length, to deal with
				 * cases the boundary is only partially stored
				 * in the buffer. */
				towrite -= bl + 4;

				if (field_storage == FORM_FIELD_STORAGE_GET) {
					r = unencoded_field_get(conn,
						((get_block > 0) ? NULL : nbeg),
						((get_block > 0)
							? 0
							: (size_t)(nend - nbeg)),
						hend,
						towrite,
						fdh);
					get_block++;
					if (r == FORM_FIELD_HANDLE_ABORT) {
						/* Stop request handling */
						abort_read = 1;
						break;
					}
					if (r == FORM_FIELD_HANDLE_NEXT) {
						/* Skip to next field */
						field_storage = FORM_FIELD_STORAGE_SKIP;
					}
				}

				if (field_storage == FORM_FIELD_STORAGE_STORE) {
					if (fstore.fp) {

						/* Store the content of the buffer. */
						n = promise_fwrite(fstore.pf, (void_t)hend, 1, towrite, fstore.fp);
						if ((n != towrite) || (ferror(fstore.fp))) {
							http_log(DEBUG_ERROR, conn,
								"%s: Cannot write file %s",
								__func__,
								path);
							http_fclose(&fstore);
							http_remove_bad_file(conn->ctx, conn, path);
						}
						file_size += (int64_t)n;
					}
				}

				memmove(buf, hend + towrite, bl + 4);
				buf_fill = bl + 4;
				hend = buf;

				/* Read new data */
				to_read = sizeof(buf) - 1 - buf_fill;
				r = http_read(conn, buf + buf_fill, to_read);
				if ((r < 0) || ((r == 0) && all_data_read)) {
					/* read error */
					if (fstore.fp) {
						http_fclose(&fstore);
						http_remove_bad_file(conn->ctx, conn, path);
					}

					free(boundary);
					return -1;
				}
				/* r==0 already handled, all_data_read is false here */

				buf_fill += r;
				buf[buf_fill] = 0;
				/* buf_fill is at least 8 here */

				/* Find boundary */
				next = search_boundary(buf, buf_fill, boundary, bl);

				if (!next && (r == 0)) {
					/* incomplete request */
					all_data_read = 1;
				}
			}

			towrite = (next ? (size_t)(next - hend) : 0);

			if (field_storage == FORM_FIELD_STORAGE_GET) {
				/* Call callback */
				r = unencoded_field_get(conn,
					((get_block > 0) ? NULL : nbeg),
					((get_block > 0)
						? 0
						: (size_t)(nend - nbeg)),
					hend,
					towrite,
					fdh);
				if (r == FORM_FIELD_HANDLE_ABORT) {
					/* Stop request handling */
					abort_read = 1;
					break;
				}
				if (r == FORM_FIELD_HANDLE_NEXT) {
					/* Skip to next field */
					field_storage = FORM_FIELD_STORAGE_SKIP;
				}
			}

			if (field_storage == FORM_FIELD_STORAGE_STORE) {
				if (fstore.fp) {
					n = (size_t)promise_fwrite(fstore.pf, (void_t)hend, 1, towrite, fstore.fp);
					if ((n != towrite) || (ferror(fstore.fp))) {
						http_log(DEBUG_ERROR, conn,
							"%s: Cannot write file %s",
							__func__,
							path);
						http_fclose(&fstore);
						http_remove_bad_file(conn->ctx, conn, path);
					} else {
						file_size += (int64_t)n;
						r = http_fclose(&fstore);
						if (r == 0) {
							/* stored successfully */
							r = field_stored(conn, path, file_size, fdh);
							if (r == FORM_FIELD_HANDLE_ABORT) {
								/* Stop request handling */
								abort_read = 1;
								break;
							}
						} else {
							http_log(DEBUG_ERROR, conn,
								"%s: Error saving file %s",
								__func__,
								path);
							http_remove_bad_file(conn->ctx, conn, path);
						}
					}
					fstore.fp = NULL;
				}
			}

			if ((field_storage & FORM_FIELD_STORAGE_ABORT)
				== FORM_FIELD_STORAGE_ABORT) {
				/* Stop parsing the request */
				abort_read = 1;
				break;
			}

			/* Remove from the buffer */
			if (next) {
				used = next - buf + 2;
				memmove(buf, buf + (size_t)used, sizeof(buf) - (size_t)used);
				buf_fill -= used;
			} else {
				buf_fill = 0;
			}
		}

		/* All parts handled */
		free(boundary);
		return field_count;
	}

	/* Unknown Content-Type */
	return -1;
}
