#include "httpi_internal.h"
#include <openssl/md5.h>

/* Stringify binary data. Output buffer must be twice as big as input,
 * because each byte takes 2 bytes in string representation */
static void bin2str(char *to, const unsigned char *p, size_t len) {
	static string_t hex = "0123456789abcdef";

	for (; len--; p++) {
		*to++ = hex[p[0] >> 4];
		*to++ = hex[p[0] & 0x0f];
	}
	*to = '\0';
}

char *http_md5(char buf[33], ...) {
	unsigned char hash[16];
	string_t p;
	va_list ap;
	MD5_CTX ctx;

	MD5_Init(&ctx);

	va_start(ap, buf);
	while ((p = va_arg(ap, string_t)) != NULL) {
		MD5_Update(&ctx, (const_t)p, strlen(p));
	}
	va_end(ap);

	MD5_Final(hash, &ctx);
	bin2str(buf, hash, sizeof(hash));
	return buf;
}


/* Check the user's password, return 1 if OK */
static int check_password_digest(string_t method,
	string_t ha1,
	string_t uri,
	string_t nonce,
	string_t nc,
	string_t cnonce,
	string_t qop,
	string_t response) {
	char ha2[32 + 1], expected_response[32 + 1];

	/* Some of the parameters may be NULL */
	if ((method == NULL) || (nonce == NULL) || (nc == NULL) || (cnonce == NULL)
		|| (qop == NULL) || (response == NULL)) {
		return 0;
	}

	/* NOTE(lsm): due to a bug in MSIE, we do not compare the URI */
	if (strlen(response) != 32) {
		return 0;
	}

	http_md5(ha2, method, ":", uri, NULL);
	http_md5(expected_response,
		ha1,
		":",
		nonce,
		":",
		nc,
		":",
		cnonce,
		":",
		qop,
		":",
		ha2,
		NULL);

	return str_is_case(response, expected_response);
}

/* Skip the characters until one of the delimiters characters found.
 * 0-terminate resulting word. Skip the delimiter and following whitespaces.
 * Advance pointer to buffer to the next word. Return found 0-terminated
 * word.
 * Delimiters can be quoted with quotechar. */
static char *skip_quoted(char **buf, string_t delimiters,
	string_t whitespace, char quotechar) {
	char *p, *begin_word, *end_word, *end_whitespace;

	begin_word = *buf;
	end_word = begin_word + strcspn(begin_word, delimiters);

	/* Check for quotechar */
	if (end_word > begin_word) {
		p = end_word - 1;
		while (*p == quotechar) {
			/* While the delimiter is quoted, look for the next delimiter. */
			/* This happens, e.g., in calls from parse_auth_header,
			 * if the user name contains a " character. */

			/* If there is anything beyond end_word, copy it. */
			if (*end_word != '\0') {
				size_t end_off = strcspn(end_word + 1, delimiters);
				memmove(p, end_word, end_off + 1);
				p += end_off; /* p must correspond to end_word - 1 */
				end_word += end_off + 1;
			} else {
				*p = '\0';
				break;
			}
		}
		for (p++; p < end_word; p++) {
			*p = '\0';
		}
	}

	if (*end_word == '\0') {
		*buf = end_word;
	} else {

#if defined(GCC_DIAGNOSTIC)
		/* Disable spurious conversion warning for GCC */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif /* defined(GCC_DIAGNOSTIC) */

		end_whitespace = end_word + strspn(&end_word[1], whitespace) + 1;

#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic pop
#endif /* defined(GCC_DIAGNOSTIC) */

		for (p = end_word; p < end_whitespace; p++) {
			*p = '\0';
		}

		*buf = end_whitespace;
	}

	return begin_word;
}

/* Return 1 on success. Always initializes the auth_header structure. */
static int parse_auth_header(http_t *conn, char *buf,
	size_t buf_size, struct auth_header *auth_header) {
	char *name, *value, *s;
	string_t ah;
	uint64_t nonce;

	if (!auth_header || !conn) {
		return 0;
	}

	(void)memset(auth_header, 0, sizeof(*auth_header));
	ah = http_get_header(conn, "Authorization");

	if (ah == NULL) {
		/* No Authorization header at all */
		return 0;
	}
	if (str_case_equal(ah, "Basic ", 6)) {
		/* Basic Auth (we never asked for this, but some client may send it) */
		char *split;
		string_t userpw_b64 = ah + 6;
		size_t userpw_b64_len = strlen(userpw_b64);
		size_t buf_len_r = buf_size;
		if (is_empty(buf = str_decode64(userpw_b64, buf, BUF_LEN))) {
			return 0; /* decode error */
		}
		split = strchr(buf, ':');
		if (!split) {
			return 0; /* Format error */
		}

		/* Separate string at ':' */
		*split = 0;

		/* User name is before ':', Password is after ':'  */
		auth_header->user = buf;
		auth_header->type = 1;
		auth_header->plain_password = split + 1;

		return 1;

	} else if (str_case_equal(ah, "Digest ", 7)) {
		/* Digest Auth ... implemented below */
		auth_header->type = 2;

	} else {
		/* Unknown or invalid Auth method */
		return 0;
	}

	/* Make modifiable copy of the auth header */
	(void)str_lcpy(buf, ah + 7, buf_size);
	s = buf;

	/* Parse authorization header */
	for (;;) {
		/* Gobble initial spaces */
		while (isspace((unsigned char)*s)) {
			s++;
		}
		name = skip_quoted(&s, "=", " ", 0);
		/* Value is either quote-delimited, or ends at first comma or space.
		 */
		if (s[0] == '\"') {
			s++;
			value = skip_quoted(&s, "\"", " ", '\\');
			if (s[0] == ',') {
				s++;
			}
		} else {
			value = skip_quoted(&s, ", ", " ", 0); /* IE uses commas, FF
													* uses spaces */
		}
		if (*name == '\0') {
			break;
		}

		if (!strcmp(name, "username")) {
			auth_header->user = value;
		} else if (!strcmp(name, "cnonce")) {
			auth_header->cnonce = value;
		} else if (!strcmp(name, "response")) {
			auth_header->response = value;
		} else if (!strcmp(name, "uri")) {
			auth_header->uri = value;
		} else if (!strcmp(name, "qop")) {
			auth_header->qop = value;
		} else if (!strcmp(name, "nc")) {
			auth_header->nc = value;
		} else if (!strcmp(name, "nonce")) {
			auth_header->nonce = value;
		}
	}

#if !defined(NO_NONCE_CHECK)
	/* Read the nonce from the response. */
	if (auth_header->nonce == NULL) {
		return 0;
	}
	s = NULL;
	nonce = strtoull(auth_header->nonce, &s, 10);
	if ((s == NULL) || (*s != 0)) {
		return 0;
	}

	/* Convert the nonce from the client to a number. */
	nonce ^= conn->domain->auth_nonce_mask;

	/* The converted number corresponds to the time the nounce has been
	 * created. This should not be earlier than the server start. */
	/* Server side nonce check is valuable in all situations but one:
	 * if the server restarts frequently, but the client should not see
	 * that, so the server should accept nonces from previous starts. */
	/* However, the reasonable default is to not accept a nonce from a
	 * previous start, so if anyone changed the access rights between
	 * two restarts, a new login is required. */
	if (nonce < (uint64_t)conn->ctx->start_time) {
		/* nonce is from a previous start of the server and no longer valid
		 * (replay attack?) */
		return 0;
	}
	/* Check if the nonce is too high, so it has not (yet) been used by the
	 * server. */
	if (nonce >= ((uint64_t)conn->ctx->start_time
		+ conn->domain->nonce_count)) {
		return 0;
	}
#else
	(void)nonce;
#endif

	return (auth_header->user != NULL);
}

/* Define the initial recursion depth for processing htpasswd files that
 * include other htpasswd (or even the same) files.
 * It is not difficult to provide a file or files
 * s.t. they force `HttPi` to infinitely recurse and then crash. */
#define INITIAL_DEPTH 9

/* Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory. */
static void open_auth_file(http_t *conn, string_t path, struct file *filep) {
	if ((conn != NULL) && (conn->domain != NULL)) {
		char name[UTF8_PATH_MAX];
		string_t p, e,
			gpass = conn->domain->config[GLOBAL_PASSWORDS_FILE];
		int truncated;

		if (gpass != NULL) {
			/* Use global passwords file */
			if (!http_fopen(conn->ctx, conn, gpass, "rb", filep)) {
				/* Use http_log here, since gpass has been
				 * configured. */
				http_log(DEBUG_ERROR, conn, "fopen(%s): %s", gpass, ex_strerror(os_geterror()));

			}
			/* Important: using local struct http_file to test path for
			 * is_directory flag. If filep is used, http_stat() makes it
			 * appear as if auth file was opened.
			 * TODO(mid): Check if this is still required after rewriting
			 * http_stat */
		} else if (http_stat(conn, path, filep)
			&& filep->is_directory) {
			http_snprintf(
				&truncated,
				name,
				sizeof(name),
#ifdef _WIN32
				"%s%s%s",
#else
				"%s%s%s",
#endif
				path,
				SYS_DIRSEP,
				PASSWORDS_FILE_NAME);

			if (truncated || !http_fopen(conn->ctx, conn, name, "rb", filep)) {
				/* Don't use http_log here, but only a trace, since
				 * this is a typical case. It will occur for every directory
				 * without a password file. */
				debug_info("fopen(%s): %s"CLR_LN, name, ex_strerror(os_geterror()));
			}
		} else {
			/* Try to find .htpasswd in requested directory. */
			for (p = path, e = p + strlen(p) - 1; e > p; e--) {
				if (e[0] == SYS_DIRSEP_C) {
					break;
				}
			}
			http_snprintf(
				&truncated,
				name,
				sizeof(name),

#ifdef _WIN32
				".%.*s%s%s",
#else
				"%.*s%s%s",
#endif
				(int)(e - p),
				p,
				SYS_DIRSEP,
				PASSWORDS_FILE_NAME);

			if (truncated || !http_fopen(conn->ctx, conn, name, "rb", filep)) {
				/* Don't use http_log here, but only a trace, since
				 * this is a typical case. It will occur for every directory
				 * without a password file. */
				debug_info("fopen(%s): %s"CLR_LN, name, ex_strerror(os_geterror()));
			}
		}
	}
}

static int read_auth_file(struct file *filep,
	struct read_auth_file_struct *workdata, int depth) {
	int is_authorized = 0;
	struct file fp;
	size_t l;
	union {
		string_t con;
		char *var;
	} ptr;

	if (!filep || !workdata || (0 == depth)) {
		return 0;
	}

	/* Loop over passwords file */
	ptr.con = filep->membuf;
	while (http_fgets(workdata->buf, sizeof(workdata->buf), filep, &ptr.var) != NULL) {
		l = strlen(workdata->buf);
		while (l > 0) {
			if (isspace((unsigned char)workdata->buf[l - 1])
				|| iscntrl((unsigned char)workdata->buf[l - 1])) {
				l--;
				workdata->buf[l] = 0;
			} else
				break;
		}

		if (l < 1) {
			continue;
		}

		workdata->f_user = workdata->buf;
		if (workdata->f_user[0] == ':') {
			/* user names may not contain a ':' and may not be empty,
			 * so lines starting with ':' may be used for a special purpose
			 */
			if (workdata->f_user[1] == '#') {
				/* :# is a comment */
				continue;
			} else if (!strncmp(workdata->f_user + 1, "include=", 8)) {
				if (http_fopen(workdata->conn->ctx, workdata->conn,
					workdata->f_user + 9, "rb", &fp)) {
					is_authorized = read_auth_file(&fp, workdata, depth - 1);
					(void)http_fclose(&fp); /* ignore error on read only file */

					/* No need to continue processing files once we have a
					 * match, since nothing will reset it back
					 * to 0.
					 */
					if (is_authorized) {
						return is_authorized;
					}
				} else {
					http_log(DEBUG_ERROR, workdata->conn,
						"%s: cannot open authorization file: %s",
						__func__,
						workdata->buf);
				}
				continue;
			}

			/* everything is invalid for the moment (might change in the
			 * future) */
			http_log(DEBUG_ERROR, workdata->conn,
				"%s: syntax error in authorization file: %s",
				__func__,
				workdata->buf);
			continue;
		}

		workdata->f_domain = strchr(workdata->f_user, ':');
		if (workdata->f_domain == NULL) {
			http_log(DEBUG_ERROR, workdata->conn,
				"%s: syntax error in authorization file: %s",
				__func__,
				workdata->buf);
			continue;
		}

		*(char *)(workdata->f_domain) = 0;
		(workdata->f_domain)++;
		workdata->f_ha1 = strchr(workdata->f_domain, ':');
		if (workdata->f_ha1 == NULL) {
			http_log(DEBUG_ERROR, workdata->conn,
				"%s: syntax error in authorization file: %s",
				__func__,
				workdata->buf);
			continue;
		}

		*(char *)(workdata->f_ha1) = 0;
		(workdata->f_ha1)++;
		if (!strcmp(workdata->auth_header.user, workdata->f_user)
			&& !strcmp(workdata->domain, workdata->f_domain)) {
			switch (workdata->auth_header.type) {
				case 1: /* Basic */
					{
						char md5[33];
						http_md5(md5,
							workdata->f_user,
							":",
							workdata->domain,
							":",
							workdata->auth_header.plain_password,
							NULL);
						return 0 == memcmp(workdata->f_ha1, md5, 33);
					}
				case 2: /* Digest */
					return check_password_digest(
						workdata->conn->method,
						workdata->f_ha1,
						workdata->auth_header.uri,
						workdata->auth_header.nonce,
						workdata->auth_header.nc,
						workdata->auth_header.cnonce,
						workdata->auth_header.qop,
						workdata->auth_header.response);
				default: /* None/Other/Unknown */
					return 0;
			}
		}
	}

	return is_authorized;
}

int authorize(http_t *conn, struct file *filep, string_t realm) {
	struct read_auth_file_struct workdata;
	char buf[BUF_LEN];

	if (!conn || !conn->domain) {
		return 0;
	}

	memset(&workdata, 0, sizeof(workdata));
	workdata.conn = conn;

	if (!parse_auth_header(conn, buf, sizeof(buf), &workdata.auth_header)) {
		return 0;
	}

	/* CGI needs it as REMOTE_USER */
	conn->req.remote_user = str_dup_ex(workdata.auth_header.user);

	if (realm) {
		workdata.domain = realm;
	} else {
		workdata.domain = conn->domain->config[AUTHENTICATION_DOMAIN];
	}

	return read_auth_file(filep, &workdata, INITIAL_DEPTH);
}

int http_check_digest_access_authentication(http_t *conn,
	string_t realm,
	string_t filename) {
	struct file file = STRUCT_FILE_INITIALIZER;
	int auth;

	if (!conn || !filename) {
		return -1;
	}
	if (!http_fopen(conn->ctx, conn, filename, "r", &file)) {
		return -2;
	}

	auth = authorize(conn, &file, realm);

	http_fclose(&file);

	return auth;
}

int check_authorization(http_t *conn, string_t path) {
	char fname[UTF8_PATH_MAX];
	struct vec uri_vec, filename_vec;
	string_t list;
	struct file file = STRUCT_FILE_INITIALIZER;
	int authorized = 1, truncated;

	if (!conn || !conn->domain) {
		return 0;
	}

	list = conn->domain->config[PROTECT_URI];
	while ((list = http_next_option(list, &uri_vec, &filename_vec)) != NULL) {
		if (!memcmp(conn->req.local_uri, uri_vec.ptr, uri_vec.len)) {
			http_snprintf(
				&truncated,
				fname,
				sizeof(fname),
				"%.*s",
				(int)filename_vec.len,
				filename_vec.ptr);

			if (truncated
				|| !http_fopen(conn->ctx, conn, fname, "rb", &file)) {
				http_log(DEBUG_ERROR, conn,
					"%s: cannot open %s: %s",
					__func__,
					fname,
					ex_strerror(os_geterror()));
			}
			break;
		}
	}

	if (!http_is_file_opened(&file)) {
		open_auth_file(conn, path, &file);
	}

	if (http_is_file_opened(&file)) {
		authorized = authorize(conn, &file, NULL);
		(void)http_fclose(&file); /* ignore error on read only file */
	}

	return authorized;
}

void send_authorization_request(http_t *conn, string_t realm) {
	uint64_t nonce = (uint64_t)(conn->ctx->start_time);
	int trunc = 0;
	char buf[128];

	if (!realm) {
		realm = conn->domain->config[AUTHENTICATION_DOMAIN];
	}

	atomic_lock(&conn->ctx->nonce_mutex);
	nonce += conn->domain->nonce_count;
	++conn->domain->nonce_count;
	atomic_unlock(&conn->ctx->nonce_mutex);

	nonce ^= conn->domain->auth_nonce_mask;
	conn->req.must_close = 1;

	/* Create 401 response */
	http_response_start(conn, 401);
	http_no_cache_header(conn);
	http_domain_header(conn);
	http_response_add(conn, "Content-Length", "0", -1);

	/* Content for "WWW-Authenticate" header */
	http_snprintf(
		&trunc,
		buf,
		sizeof(buf),
		"Digest qop=\"auth\", realm=\"%s\", "
		"nonce=\"%" UINT64_FMT "\"",
		realm,
		nonce);

	if (!trunc) {
		/* !trunc should always be true */
		http_response_add(conn, "WWW-Authenticate", buf, -1);
	}

	/* Send all headers */
	http_response_send(conn);
}

int http_send_digest_access_authentication_request(http_t *conn,
	string_t realm) {
	if (conn && conn->domain) {
		send_authorization_request(conn, realm);
		return 0;
	}
	return -1;
}

int is_authorized_for_put(http_t *conn) {
	int ret = 0;

	if (conn) {
		struct file file = STRUCT_FILE_INITIALIZER;
		string_t passfile = conn->domain->config[PUT_DELETE_PASSWORDS_FILE];

		if (passfile != NULL
			&& http_fopen(conn->ctx, conn, passfile, "rb", &file)) {
			ret = authorize(conn, &file, NULL);
			(void)http_fclose(&file); /* ignore error on read only file */
		}
	}

	debug_info("file write authorization: %i"CLR_LN, ret);
	return ret;
}

static int modify_passwords_file_ha1(string_t fname,
	string_t domain,
	string_t user,
	string_t ha1) {
	int found = 0, i, result = 1;
	char line[512], u[256], d[256], h[256];
	struct stat st = {0};
	struct file fp = STRUCT_FILE_INITIALIZER;
	char *temp_file = NULL;
	int temp_file_offs = 0;

	/* Regard empty password as no password - remove user record. */
	if ((ha1 != NULL) && (ha1[0] == '\0')) {
		ha1 = NULL;
	}

	/* Other arguments must not be empty */
	if ((fname == NULL) || (domain == NULL) || (user == NULL)) {
		return 0;
	}

	/* Using the given file format, user name and domain must not contain
	 * the ':' character */
	if (strchr(user, ':') != NULL) {
		return 0;
	}
	if (strchr(domain, ':') != NULL) {
		return 0;
	}

	/* Do not allow control characters like newline in user name and domain.
	 * Do not allow excessively long names either. */
	for (i = 0; ((i < 255) && (user[i] != 0)); i++) {
		if (iscntrl((unsigned char)user[i])) {
			return 0;
		}
	}
	if (user[i]) {
		return 0; /* user name too long */
	}
	for (i = 0; ((i < 255) && (domain[i] != 0)); i++) {
		if (iscntrl((unsigned char)domain[i])) {
			return 0;
		}
	}
	if (domain[i]) {
		return 0; /* domain name too long */
	}

	/* The maximum length of the path to the password file is limited */
	if (strlen(fname) >= UTF8_PATH_MAX) {
		return 0;
	}

	/* Check if the file exists, and get file size */
	if (0 == stat(fname, &st)) {
		int temp_buf_len;
		if (st.st_size > 10485760) {
			/* Some funster provided a >10 MB text file */
			return 0;
		}

		/* Add enough space for one more line */
		temp_buf_len = (int)st.st_size + 1024;

		/* Allocate memory (instead of using a temporary file) */
		temp_file = (char *)calloc(1, (size_t)temp_buf_len + 1);
		if (!temp_file) {
			/* Out of memory */
			return 0;
		}

		memset(&fp, 0, sizeof(fp));
		/* File exists. Read it into a memory buffer. */
		fp.fp = fopen(fname, "rb");
		if (fp.fp == NULL) {
			/* Cannot read file. No permission? */
			free(temp_file);
			return 0;
		}

		/* Read content and store in memory */
		while ((fgets(line, sizeof(line), fp.fp) != NULL)
			&& ((temp_file_offs + 600) < temp_buf_len)) {
		 /* file format is "user:domain:hash\n" */
			if (sscanf(line, "%255[^:]:%255[^:]:%255s", u, d, h) != 3) {
				continue;
			}
			u[255] = 0;
			d[255] = 0;
			h[255] = 0;

			if (!strcmp(u, user) && !strcmp(d, domain)) {
				/* Found the user: change the password hash or drop the user
				 */
				if ((ha1 != NULL) && (!found)) {
					i = sprintf(temp_file + temp_file_offs,
						"%s:%s:%s\n",
						user,
						domain,
						ha1);
					if (i < 1) {
						fclose(fp.fp);
						free(temp_file);
						return 0;
					}
					temp_file_offs += i;
				}
				found = 1;
			} else {
				/* Copy existing user, including password hash */
				i = sprintf(temp_file + temp_file_offs, "%s:%s:%s\n", u, d, h);
				if (i < 1) {
					fclose(fp.fp);
					free(temp_file);
					return 0;
				}
				temp_file_offs += i;
			}
		}
		fclose(fp.fp);
	}

	/* Create new file */
	fp.fp = fopen(fname, "wb");
	if (!fp.fp) {
		free(temp_file);
		return 0;
	}

#if !defined(_WIN32)
	/* On Linux & co., restrict file read/write permissions to the owner */
	if (fchmod(fileno(fp.fp), S_IRUSR | S_IWUSR) != 0) {
		result = 0;
	}
#endif

	if ((temp_file != NULL) && (temp_file_offs > 0)) {
		/* Store buffered content of old file */
		if (fwrite(temp_file, 1, (size_t)temp_file_offs, fp.fp)
			!= (size_t)temp_file_offs) {
			result = 0;
		}
	}

	/* If new user, just add it */
	if ((ha1 != NULL) && (!found)) {
		char ha1_buf[PATH_MAX] = {0};
		snprintf(ha1_buf, sizeof(ha1_buf), "%s:%s:%s\n", user, domain, ha1);
		if (fprintf(fp.fp, ha1_buf) < 6) {
			result = 0;
		}
	}

	/* All data written */
	if (fclose(fp.fp) != 0) {
		result = 0;
	}

	free(temp_file);
	return result;
}

static FORCEINLINE void *httpi_modify_passwords_file_ha1(param_t args) {
	return casting(modify_passwords_file_ha1(args[0].const_char_ptr,
		args[1].const_char_ptr, args[2].const_char_ptr, args[3].const_char_ptr));
}

FORCEINLINE int http_modify_passwords_file_ha1(string_t fname, string_t domain, string_t user, string_t ha1) {
	return queue_get(queue_work(futures_pool(), httpi_modify_passwords_file_ha1, 4, fname, domain, user, ha1)).integer;
}

int http_modify_passwords_file(string_t fname,
	string_t domain,
	string_t user,
	string_t pass) {
	char ha1buf[33];
	if ((fname == NULL) || (domain == NULL) || (user == NULL)) {
		return 0;
	}
	if ((pass == NULL) || (pass[0] == 0)) {
		return http_modify_passwords_file_ha1(fname, domain, user, NULL);
	}

	http_md5(ha1buf, user, ":", domain, ":", pass, NULL);
	return http_modify_passwords_file_ha1(fname, domain, user, ha1buf);
}
