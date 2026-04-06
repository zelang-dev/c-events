#include "httpie_internal.h"

/* Config option name, config types, default value.
 * Must be in the same order as the enum const above. */
static const struct ini_option config_options[] = {
	/* Once for each server */
	{"listening_ports", INI_TYPE_STRING_LIST, "8080"},
	{"num_threads", INI_TYPE_NUMBER, "50"},
	{"prespawn_threads", INI_TYPE_NUMBER, "0"},
	{"run_as_user", INI_TYPE_STRING, NULL},
	{"tcp_nodelay", INI_TYPE_NUMBER, "0"},
	{"max_request_size", INI_TYPE_NUMBER, "16384"},
	{"linger_timeout_ms", INI_TYPE_NUMBER, NULL},
	{"connection_queue", INI_TYPE_NUMBER, "20"},
	{"listen_backlog", INI_TYPE_NUMBER, "200"},
	{"allow_sendfile_call", INI_TYPE_BOOLEAN, "yes"},
	{"throttle", INI_TYPE_STRING_LIST, NULL},
	{"enable_keep_alive", INI_TYPE_BOOLEAN, "no"},
	{"request_timeout_ms", INI_TYPE_NUMBER, "30000"},
	{"keep_alive_timeout_ms", INI_TYPE_NUMBER, "500"},
	{"websocket_timeout_ms", INI_TYPE_NUMBER, NULL},
	{"enable_websocket_ping_pong", INI_TYPE_BOOLEAN, "no"},
	{"decode_url", INI_TYPE_BOOLEAN, "yes"},
	{"decode_query_string", INI_TYPE_BOOLEAN, "no"},
	{"enable_http2", INI_TYPE_BOOLEAN, "no"},

	/* Once for each domain */
	{"document_root", INI_TYPE_DIRECTORY, NULL},
	{"fallback_document_root", INI_TYPE_DIRECTORY, NULL},

	{"access_log_file", INI_TYPE_FILE, NULL},
	{"error_log_file", INI_TYPE_FILE, NULL},

	{"cgi_pattern", INI_TYPE_EXT_PATTERN, "**.cgi$|**.pl$|**.php$"},
	{"cgi_environment", INI_TYPE_STRING_LIST, NULL},
	{"cgi_interpreter", INI_TYPE_FILE, NULL},
	{"cgi_interpreter_args", INI_TYPE_STRING, NULL},
	{"cgi_buffering", INI_TYPE_BOOLEAN, "yes"},

	{"cgi2_pattern", INI_TYPE_EXT_PATTERN, NULL},
	{"cgi2_environment", INI_TYPE_STRING_LIST, NULL},
	{"cgi2_interpreter", INI_TYPE_FILE, NULL},
	{"cgi2_interpreter_args", INI_TYPE_STRING, NULL},
	{"cgi2_buffering", INI_TYPE_BOOLEAN, "yes"},

	{"put_delete_auth_file", INI_TYPE_FILE, NULL},
	{"protect_uri", INI_TYPE_STRING_LIST, NULL},
	{"authentication_domain", INI_TYPE_STRING, "mydomain.com"},
	{"enable_auth_domain_check", INI_TYPE_BOOLEAN, "yes"},
	{"ssi_pattern", INI_TYPE_EXT_PATTERN, "**.shtml$|**.shtm$"},
	{"enable_directory_listing", INI_TYPE_BOOLEAN, "yes"},
	{"enable_webdav", INI_TYPE_BOOLEAN, "no"},
	{"global_auth_file", INI_TYPE_FILE, NULL},
	{"index_files", INI_TYPE_STRING_LIST, "index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php"},
	{"access_control_list", INI_TYPE_STRING_LIST, NULL},
	{"extra_mime_types", INI_TYPE_STRING_LIST, NULL},
	{"ssl_certificate", INI_TYPE_FILE, NULL},
	{"ssl_certificate_chain", INI_TYPE_FILE, NULL},
	{"url_rewrite_patterns", INI_TYPE_STRING_LIST, NULL},
	{"hide_files_patterns", INI_TYPE_EXT_PATTERN, NULL},

	{"ssl_verify_peer", INI_TYPE_YES_NO_OPTIONAL, "no"},
	{"ssl_cache_timeout", INI_TYPE_NUMBER, "-1"},
	{"ssl_ca_path", INI_TYPE_DIRECTORY, NULL},
	{"ssl_ca_file", INI_TYPE_FILE, NULL},
	{"ssl_verify_depth", INI_TYPE_NUMBER, "9"},
	{"ssl_default_verify_paths", INI_TYPE_BOOLEAN, "yes"},
	{"ssl_cipher_list", INI_TYPE_STRING, NULL},

	/* HTTP2 requires ALPN, and anyway TLS1.2 should be considered
	* as a minimum in 2020 */
	{"ssl_protocol_version", INI_TYPE_NUMBER, "4"},
	{"ssl_short_trust", INI_TYPE_BOOLEAN, "no"},

	{"websocket_root", INI_TYPE_DIRECTORY, NULL},
	{"fallback_websocket_root", INI_TYPE_DIRECTORY, NULL},
	{"replace_asterisk_with_origin", INI_TYPE_BOOLEAN, "no"},
	{"access_control_allow_origin", INI_TYPE_STRING, "*"},
	{"access_control_allow_methods", INI_TYPE_STRING, "*"},
	{"access_control_allow_headers", INI_TYPE_STRING, "*"},
	{"access_control_expose_headers", INI_TYPE_STRING, ""},
	{"access_control_allow_credentials", INI_TYPE_STRING, ""},
	{"error_pages", INI_TYPE_DIRECTORY, NULL},
	{"static_file_max_age", INI_TYPE_NUMBER, "3600"},
	{"static_file_cache_control", INI_TYPE_STRING, NULL},
	{"strict_transport_security_max_age", INI_TYPE_NUMBER, NULL},
	{"additional_header", INI_TYPE_STRING_MULTILINE, NULL},
	{"allow_index_script_resource", INI_TYPE_BOOLEAN, "no"},

	{NULL, INI_TYPE_UNKNOWN, NULL}
};

#define ARRAY_SIZE_EX(array) (sizeof(array) / sizeof(array[0]))

static const struct {
	string_t extension;
	size_t ext_len;
	string_t mime_type;
} builtin_mime_types[] = {
	/* IANA registered MIME types
	 * (http://www.iana.org/assignments/media-types)
	 * application types */
	{".bin", 4, "application/octet-stream"},
	{".cer", 4, "application/pkix-cert"},
	{".crl", 4, "application/pkix-crl"},
	{".crt", 4, "application/pkix-cert"},
	{".deb", 4, "application/octet-stream"},
	{".dmg", 4, "application/octet-stream"},
	{".dll", 4, "application/octet-stream"},
	{".doc", 4, "application/msword"},
	{".eps", 4, "application/postscript"},
	{".exe", 4, "application/octet-stream"},
	{".iso", 4, "application/octet-stream"},
	{".js", 3, "application/javascript"},
	{".json", 5, "application/json"},
	{".mjs", 4, "application/javascript"},
	{".msi", 4, "application/octet-stream"},
	{".pem", 4, "application/x-pem-file"},
	{".pdf", 4, "application/pdf"},
	{".ps", 3, "application/postscript"},
	{".rtf", 4, "application/rtf"},
	{".wasm", 5, "application/wasm"},
	{".xhtml", 6, "application/xhtml+xml"},
	{".xsl", 4, "application/xml"},
	{".xslt", 5, "application/xml"},

	/* fonts */
	{".ttf", 4, "application/font-sfnt"},
	{".cff", 4, "application/font-sfnt"},
	{".otf", 4, "application/font-sfnt"},
	{".aat", 4, "application/font-sfnt"},
	{".sil", 4, "application/font-sfnt"},
	{".pfr", 4, "application/font-tdpfr"},
	{".woff", 5, "application/font-woff"},
	{".woff2", 6, "application/font-woff2"},

	/* audio */
	{".mp3", 4, "audio/mpeg"},
	{".oga", 4, "audio/ogg"},
	{".ogg", 4, "audio/ogg"},

	/* image */
	{".gif", 4, "image/gif"},
	{".ief", 4, "image/ief"},
	{".jpeg", 5, "image/jpeg"},
	{".jpg", 4, "image/jpeg"},
	{".jpm", 4, "image/jpm"},
	{".jpx", 4, "image/jpx"},
	{".png", 4, "image/png"},
	{".svg", 4, "image/svg+xml"},
	{".tif", 4, "image/tiff"},
	{".tiff", 5, "image/tiff"},

	/* model */
	{".wrl", 4, "model/vrml"},

	/* text */
	{".css", 4, "text/css"},
	{".csv", 4, "text/csv"},
	{".htm", 4, "text/html"},
	{".html", 5, "text/html"},
	{".sgm", 4, "text/sgml"},
	{".shtm", 5, "text/html"},
	{".shtml", 6, "text/html"},
	{".txt", 4, "text/plain"},
	{".xml", 4, "text/xml"},

	/* video */
	{".mov", 4, "video/quicktime"},
	{".mp4", 4, "video/mp4"},
	{".mpeg", 5, "video/mpeg"},
	{".mpg", 4, "video/mpeg"},
	{".ogv", 4, "video/ogg"},
	{".qt", 3, "video/quicktime"},

	/* not registered types
	 * (http://reference.sitepoint.com/html/mime-types-full,
	 * http://www.hansenb.pdx.edu/DMKB/dict/tutorials/mime_typ.php, ..) */
	{".arj", 4, "application/x-arj-compressed"},
	{".gz", 3, "application/x-gunzip"},
	{".rar", 4, "application/x-arj-compressed"},
	{".swf", 4, "application/x-shockwave-flash"},
	{".tar", 4, "application/x-tar"},
	{".tgz", 4, "application/x-tar-gz"},
	{".torrent", 8, "application/x-bittorrent"},
	{".ppt", 4, "application/x-mspowerpoint"},
	{".xls", 4, "application/x-msexcel"},
	{".zip", 4, "application/x-zip-compressed"},
	{".aac",
	 4,
	 "audio/aac"}, /* http://en.wikipedia.org/wiki/Advanced_Audio_Coding */
	{".flac", 5, "audio/flac"},
	{".aif", 4, "audio/x-aif"},
	{".m3u", 4, "audio/x-mpegurl"},
	{".mid", 4, "audio/x-midi"},
	{".ra", 3, "audio/x-pn-realaudio"},
	{".ram", 4, "audio/x-pn-realaudio"},
	{".wav", 4, "audio/x-wav"},
	{".bmp", 4, "image/bmp"},
	{".ico", 4, "image/x-icon"},
	{".pct", 4, "image/x-pct"},
	{".pict", 5, "image/pict"},
	{".rgb", 4, "image/x-rgb"},
	{".webm", 5, "video/webm"}, /* http://en.wikipedia.org/wiki/WebM */
	{".asf", 4, "video/x-ms-asf"},
	{".avi", 4, "video/x-msvideo"},
	{".m4v", 4, "video/x-m4v"},
	{NULL, 0, NULL}
};

static string_t month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

string_t http_get_builtin_mime_type(string_t path) {
	string_t ext;
	size_t i, path_len;

	path_len = strlen(path);

	for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
		ext = path + (path_len - builtin_mime_types[i].ext_len);
		if ((path_len > builtin_mime_types[i].ext_len)
			&& (str_is_case(ext, builtin_mime_types[i].extension))) {
			return builtin_mime_types[i].mime_type;
		}
	}

	return "text/plain";
}

/* Convert month to the month number. Return -1 on error, or month number */
static int get_month_index(string_t s) {

	size_t i;

	for (i = 0; i < ARRAY_SIZE_EX(month_names); i++) {

		if (!strcmp(s, month_names[i])) return (int)i;
	}

	return -1;
}

time_t http_parse_date_string(string_t datetime) {
	char month_str[32] = {0};
	int second;
	int minute;
	int hour;
	int day;
	int month;
	int year;
	time_t result = (time_t)0;
	struct tm tm;

	if ((sscanf(datetime, "%d/%3s/%d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) ||
		(sscanf(datetime, "%d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) ||
		(sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) ||
		(sscanf(datetime, "%d-%3s-%d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6)) {
		month = get_month_index(month_str);
		if (month >= 0 && year >= 1970) {
			memset(&tm, 0, sizeof(tm));
			tm.tm_year = year - 1900;
			tm.tm_mon = month;
			tm.tm_mday = day;
			tm.tm_hour = hour;
			tm.tm_min = minute;
			tm.tm_sec = second;
			result = timegm(&tm);
		}
	}

	return result;
}

bool http_is_not_modified(http_ini_t *ctx, http_t *conn, const struct file *filep) {
	char etag[64];
	string_t ims = http_get_header(conn, "If-Modified-Since");
	string_t inm = http_get_header(conn, "If-None-Match");

	if (ctx == NULL || conn == NULL || filep == NULL)
		return false;

	http_construct_etag(conn, etag, sizeof(etag), filep);
	return (inm != NULL && str_is_case(etag, inm))
		|| (ims != NULL && (filep->last_modified <= http_parse_date_string(ims)));
}

int http_get_option_index(string_t name) {
	int i;

	for (i = 0; config_options[i].name != NULL; i++) {
		if (str_is(config_options[i].name, name)) {
			return i;
		}
	}

	return -1;
}

FORCEINLINE string_t http_get_default_option(ini_options_type name) {
	return config_options[name].default_value;
}

string_t http_get_option(http_ini_t *ctx, string_t name) {
	int i;
	if ((i = get_option_index(name)) == -1) {
		return NULL;
	} else if (!ctx || ctx->host.config[i] == NULL) {
		return "";
	} else {
		return ctx->host.config[i];
	}
}

string http_error_string(int error_code, string buf, size_t buf_len) {
	if (buf == NULL || buf_len < 1)
		return NULL;
#ifdef _WIN32
	int return_val = strerror_s(buf, buf_len, error_code);
	if (return_val != 0)
		return NULL;

	return buf;
#elif defined(__FreeBSD__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))
	int return_val = strerror_r(error_code, buf, buf_len);
	if (return_val != 0)
		return NULL;

	return buf;
#else /* GNU version of strerror_r */
	return strerror_r(error_code, buf, buf_len);
#endif
}

/* Construct fake connection structure. Used for logging, if connection
 * is not applicable at the moment of logging. */
static http_t *fake_conn(http_t *fc, http_ini_t *ctx) {
	static const http_t conn_zero = {0};
	*fc = conn_zero;
	fc->ctx = ctx;
	fc->domain = &(ctx->host);
	return fc;
}

bool http_set_gpass_option(http_ini_t *ctx) {
	if (is_empty(ctx))
		return true;

	struct file file = STRUCT_FILE_INITIALIZER;
	struct ini_domain_s *dom_ctx = &(ctx->host);
	http_t fc;
	string_t path;
	char error_string[ARRAY_SIZE];

	path = dom_ctx->config[GLOBAL_PASSWORDS_FILE];
	if (!str_is_empty(path) && !http_stat(fake_conn(&fc, ctx), path, &file)) {
		http_log(DEBUG_ERROR, NULL, "%s: cannot open %s: %s",
			__func__, path, http_error_string(os_geterror(), error_string, ARRAY_SIZE));
		return false;
	}

	return true;
}

bool http_set_uid_option_ex(http_ini_t *ctx) {
#if defined(_WIN32)

	return (ctx != NULL);

#else  /* _WIN32 */

	struct passwd *pw;
	string_t uid;// = getuid();
	char error_string[ERROR_STRING_LEN];

	if (ctx == NULL) return false;

	uid = ctx->host.config[RUN_AS_USER];

	if (uid == NULL) return true;

	if ((pw = getpwnam(uid)) == NULL)
		http_log(DEBUG_CRASH, NULL, "%s: unknown user [%s]", __func__, uid);
	else if (setgid(pw->pw_gid) == -1)
		http_log(DEBUG_CRASH, NULL, "%s: setgid(%s): %s", __func__, uid, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
	else if (setgroups(0, NULL))
		http_log(DEBUG_CRASH, NULL, "%s: setgroups(): %s", __func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
	else if (setuid(pw->pw_uid) == -1)
		http_log(DEBUG_CRASH, NULL, "%s: setuid(%s): %s", __func__, uid, httplib_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
	else
		return true;

	return false;

#endif /* !_WIN32 */

}
#if !defined(_WIN32) && !defined(__ZEPHYR__)
bool http_set_uid_option(http_ini_t *ctx) {
	bool success = false;
	char error_string[ERROR_STRING_LEN];

	if (ctx) {
		/* We are currently running as curr_uid. */
		const uid_t curr_uid = getuid();
		/* If set, we want to run as run_as_user. */
		string_t run_as_user = ctx->host.config[RUN_AS_USER];
		const struct passwd *to_pw = NULL;

		if ((run_as_user != NULL) && (to_pw = getpwnam(run_as_user)) == NULL) {
			/* run_as_user does not exist on the system. We can't proceed
			 * further. */
			http_abort_start(ctx, "%s: unknown user [%s]", __func__, run_as_user);
		} else if ((run_as_user == NULL) || (curr_uid == to_pw->pw_uid)) {
			/* There was either no request to change user, or we're already
			 * running as run_as_user. Nothing else to do.
			 */
			success = true;
		} else {
			/* Valid change request.  */
			if (setgid(to_pw->pw_gid) == -1) {
				http_abort_start(ctx, "%s: setgid(%s): %s", __func__, run_as_user, strerror(errno));
			} else if (setgroups(0, NULL) == -1) {
				http_abort_start(ctx, "%s: setgroups(): %s", __func__, strerror(errno));
			} else if (setuid(to_pw->pw_uid) == -1) {
				http_abort_start(ctx, "%s: setuid(%s): %s", __func__, run_as_user, strerror(errno));
			} else {
				success = true;
			}
		}
	}

	return success;
}
#endif /* !_WIN32 */

string_t http_next_option(string_t list, struct vec *val, struct vec *eq_val) {
	int end;

reparse:
	if (val == NULL || list == NULL || *list == '\0') {
		/* End of the list */
		return NULL;
	}

	/* Skip over leading LWS */
	while (*list == ' ' || *list == '\t')
		list++;

	val->ptr = list;
	if ((list = strchr(val->ptr, ',')) != NULL) {
		/* Comma found. Store length and shift the list ptr */
		val->len = ((size_t)(list - val->ptr));
		list++;
	} else {
		/* This value is the last one */
		list = val->ptr + strlen(val->ptr);
		val->len = ((size_t)(list - val->ptr));
	}

	/* Adjust length for trailing LWS */
	end = (int)val->len - 1;
	while (end >= 0 && ((val->ptr[end] == ' ') || (val->ptr[end] == '\t')))
		end--;
	val->len = (size_t)(end)+(size_t)(1);

	if (val->len == 0) {
		/* Ignore any empty entries. */
		goto reparse;
	}

	if (eq_val != NULL) {
		/* Value has form "x=y", adjust pointers and lengths
		 * so that val points to "x", and eq_val points to "y". */
		eq_val->len = 0;
		eq_val->ptr = (string_t)memchr(val->ptr, '=', val->len);
		if (eq_val->ptr != NULL) {
			eq_val->ptr++; /* Skip over '=' character */
			eq_val->len = ((size_t)(val->ptr - eq_val->ptr)) + val->len;
			val->len = ((size_t)(eq_val->ptr - val->ptr)) - 1;
		}
	}

	return list;
}

int http_parse_match_net(const struct vec *vec, const union usa *sa, int no_strict) {
	int n;
	unsigned int a, b, c, d, slash;

	if (sscanf(vec->ptr, "%u.%u.%u.%u/%u%n", &a, &b, &c, &d, &slash, &n)
		!= 5) { // NOLINT(cert-err34-c) 'sscanf' used to convert a string to an
				// integer value, but function will not report conversion
				// errors; consider using 'strtol' instead
		slash = 32;
		if (sscanf(vec->ptr, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n)
			!= 4) { // NOLINT(cert-err34-c) 'sscanf' used to convert a string to
					// an integer value, but function will not report conversion
					// errors; consider using 'strtol' instead
			n = 0;
		}
	}

	if ((n > 0) && ((size_t)n == vec->len)) {
		if ((a < 256) && (b < 256) && (c < 256) && (d < 256) && (slash < 33)) {
			/* IPv4 format */
			if (sa->sa.sa_family == AF_INET) {
				uint32_t ip = ntohl(sa->sin.sin_addr.s_addr);
				uint32_t net = ((uint32_t)a << 24) | ((uint32_t)b << 16)
					| ((uint32_t)c << 8) | (uint32_t)d;
				uint32_t mask = slash ? (0xFFFFFFFFu << (32 - slash)) : 0;
				return (ip & mask) == net;
			}
			return 0;
		}
	}

	(void)no_strict;

	/* malformed */
	return -1;
}

/* Verify given socket address against the ACL.
 * Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed.
 */
static int http_check_acl(http_ini_t *ctx, const union usa *sa) {
	int allowed, flag, matched;
	struct vec vec;

	if (ctx) {
		string_t list = ctx->host.config[ACCESS_CONTROL_LIST];

		/* If any ACL is set, deny by default */
		allowed = (list == NULL) ? '+' : '-';

		while ((list = http_next_option(list, &vec, NULL)) != NULL) {
			flag = vec.ptr[0];
			matched = -1;
			if ((vec.len > 0) && ((flag == '+') || (flag == '-'))) {
				vec.ptr++;
				vec.len--;
				matched = http_parse_match_net(&vec, sa, 1);
			}
			if (matched < 0) {
				cerr("%s: subnet must be [+|-]IP-addr[/x]",
					__func__);
				return -1;
			}

			if (matched) {
				allowed = flag;
			}
		}

		return allowed == '+';
	}

	return -1;
}

bool http_set_acl_option(http_ini_t *ctx) {
	union usa sa;
	memset(&sa, 0, sizeof(sa));
#if defined(USE_IPV6)
	sa.sin6.sin6_family = AF_INET6;
#else
	sa.sin.sin_family = AF_INET;
#endif
	return http_check_acl(ctx, &sa) != -1;
}

bool http_init_options(http_ini_t *ctx, string_t *options) {
	string_t name, value, default_value;
	int itmp, i, idx;

	/* Store options */
	while (options && (name = *options++) != NULL) {
		idx = http_get_option_index(name);
		if (idx == -1) {
			http_abort_start(ctx, "Invalid configuration option: %s", name);
			return true;

		} else if ((value = *options++) == NULL) {
			http_abort_start(ctx, "%s: option value cannot be NULL", name);
			return true;
		}

		if (ctx->host.config[idx] != NULL) {
			/* A duplicate configuration option is not an error - the last
			 * option value will be used. */
			cerr("warning: %s: duplicate option"CLR_LN, name);
			free(ctx->host.config[idx]);
		}

		ctx->host.config[idx] = str_dup_ex(value);
	}

	/* Set default value if needed */
	for (i = 0; config_options[i].name != NULL; i++) {
		default_value = config_options[i].default_value;
		if ((ctx->host.config[i] == NULL) && (default_value != NULL)) {
			ctx->host.config[i] = str_dup_ex(default_value);
		}
	}

	/* Request size option */
	itmp = atoi(ctx->host.config[MAX_REQUEST_SIZE]);
	if (itmp < 1024) {
		http_abort_start(ctx, "%s too small", config_options[MAX_REQUEST_SIZE].name);
		return true;
	}

	ctx->max_request_size = (unsigned)itmp;
	return false;
}

int http_match_prefix(string_t pattern, size_t pattern_len, string_t str) {
	string_t or_str;
	size_t i;
	int j;
	int len;
	int res;

	or_str = (string_t)memchr(pattern, '|', pattern_len);
	if (or_str != NULL) {
		res = http_match_prefix(pattern, (size_t)(or_str - pattern), str);
		return (res > 0) ? res : http_match_prefix(or_str + 1, (size_t)((pattern + pattern_len) - (or_str + 1)), str);
	}

	i = 0;
	j = 0;
	while (i < pattern_len) {
		if (pattern[i] == '?' && str[j] != '\0')
			continue;

		if (pattern[i] == '$')
			return (str[j] == '\0') ? j : -1;

		if (pattern[i] == '*') {
			i++;
			if (pattern[i] == '*') {
				i++;
				len = (int)strlen(str + j);
			} else
				len = (int)strcspn(str + j, "/");

			if (i == pattern_len)
				return j + len;

			do {
				res = http_match_prefix(pattern + i, pattern_len - i, str + j + len);
			} while (res == -1 && len-- > 0);

			return (res == -1) ? -1 : j + res + len;
		} else if (tolower(*(const unsigned char *)&pattern[i]) != tolower(*(const unsigned char *)&str[j]))
			return -1;
		i++;
		j++;
	}

	return j;
}

FORCEINLINE ptrdiff_t http_match_prefix_strlen(string_t pattern, string_t str) {
	if (pattern == NULL) {
		return -1;
	}

	return http_match_prefix(pattern, strlen(pattern), str);
}

bool http_must_hide_file(http_ini_t *ctx, string_t path) {
	string_t pw_pattern;
	string_t pattern;

	if (ctx == NULL) return false;

	pw_pattern = "**" PASSWORDS_FILE_NAME "$";
	pattern = ctx->host.config[HIDE_FILES];

	return (pw_pattern != NULL && http_match_prefix(pw_pattern, strlen(pw_pattern), path) > 0) ||
		(pattern != NULL && http_match_prefix(pattern, strlen(pattern), path) > 0);
}

/* Return host (without port) */
static void get_host_from_request(struct vec *host, const http_t *conn) {
	string_t host_header = http_get_header((http_t *)conn, "Host");

	host->ptr = NULL;
	host->len = 0;
	if (host_header != NULL) {
		string_t pos;

		/* If the "Host" is an IPv6 address, like [::1], parse until ]
		 * is found. */
		if (*host_header == '[') {
			pos = strchr(host_header, ']');
			if (!pos) {
				/* Malformed hostname starts with '[', but no ']' found */
				http_log(DEBUG_CRASH, null, "%s", "Host name format error '[' without ']'");
				return;
			}
			/* terminate after ']' */
			host->ptr = host_header;
			host->len = (size_t)(pos + 1 - host_header);
		} else {
			/* Otherwise, a ':' separates hostname and port number */
			pos = strchr(host_header, ':');
			if (pos != NULL) {
				host->len = (size_t)(pos - host_header);
			} else {
				host->len = strlen(host_header);
			}
			host->ptr = host_header;
		}
	}
}

int http_switch_domain(http_t *conn) {
	struct vec host;

	get_host_from_request(&host, conn);
	if (host.ptr) {
		if (conn->client.has_ssl) {
			/* This is a HTTPS connection, maybe we have a hostname
			 * from SNI (set in ssl_servername_callback). */
			string_t sslhost = conn->domain->config[AUTHENTICATION_DOMAIN];
			if (sslhost && (conn->domain != &(conn->ctx->host))) {
				/* We are not using the default domain */
				if ((strlen(sslhost) != host.len)
					|| !str_case_equal(host.ptr, sslhost, host.len)) {
					/* Mismatch between SNI domain and HTTP domain */
					debug_info("Host mismatch: SNI: %s, HTTPS: %.*s",
						sslhost, (int)host.len, host.ptr);
					return 0;
				}
			}
		} else {
			struct ini_domain_s *dom = &(conn->ctx->host);
			while (dom) {
				string_t domName = dom->config[AUTHENTICATION_DOMAIN];
				size_t domNameLen = strlen(domName);
				if ((domNameLen == host.len)
					&& str_case_equal(host.ptr, domName, host.len)) {
					/* Found matching domain */
					debug_info("HTTP domain %s found",
						dom->config[AUTHENTICATION_DOMAIN]);
					conn->domain = dom;
					break;
				}

				atomic_lock(&conn->ctx->nonce_mutex);
				dom = dom->next;
				atomic_unlock(&conn->ctx->nonce_mutex);
			}
		}
		debug_info("HTTP%s Host: %.*s", conn->client.has_ssl ? "S" : "", (int)host.len, host.ptr);
	} else {
		debug_info("HTTP%s Host is not set", conn->client.has_ssl ? "S" : "");
		return 0;
	}

	return 1;
}

static FORCEINLINE int is_valid_port(unsigned long port) {
	return (port <= 0xffff);
}

/* Valid listening port specification is: [ip_address:]port[s]
 * Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
 * Examples for IPv6: [::]:80, [::1]:80,
 *   [2001:0db8:7654:3210:FEDC:BA98:7654:3210]:443s
 *   see https://tools.ietf.org/html/rfc3513#section-2.2
 * In order to bind to both, IPv4 and IPv6, you can either add
 * both ports using 8080,[::]:8080, or the short form +8080.
 * Both forms differ in detail: 8080,[::]:8080 create two sockets,
 * one only accepting IPv4 the other only IPv6. +8080 creates
 * one socket accepting IPv4 and IPv6. Depending on the IPv6
 * environment, they might work differently, or might not work
 * at all - it must be tested what options work best in the
 * relevant network environment. */
static int parse_port_string(const struct vec *vec, http_socket *so, int *ip_version) {
	unsigned int a, b, c, d;
	unsigned port;
	unsigned long portUL;
	int len;
	string_t cb;
	char *endptr;
	char buf[100] = {0};

	/* MacOS needs that. If we do not zero it, subsequent bind() will fail.
	 * Also, all-zeroes in the socket address means binding to all addresses
	 * for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT). */
	memset(so, 0, sizeof(*so));
	so->lsa.sin.sin_family = AF_INET;
	*ip_version = 0;

	/* Initialize len as invalid. */
	port = 0;
	len = 0;

	/* Test for different ways to format this string */
	if (sscanf(vec->ptr,
		"%u.%u.%u.%u:%u%n",
		&a,
		&b,
		&c,
		&d,
		&port,
		&len) // NOLINT(cert-err34-c) 'sscanf' used to convert a string
			  // to an integer value, but function will not report
			  // conversion errors; consider using 'strtol' instead
		== 5) {
		/* Bind to a specific IPv4 address, e.g. 192.168.1.5:8080 */
		so->lsa.sin.sin_addr.s_addr =
			htonl((a << 24) | (b << 16) | (c << 8) | d);
		so->lsa.sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;
	} else if (sscanf(vec->ptr, "[%49[^]]]:%u%n", buf, &port, &len) == 2
		&& ((size_t)len <= vec->len)
		&& http_inet_pton(AF_INET6, buf, &so->lsa.sin6, sizeof(so->lsa.sin6), 0)) {
		/* IPv6 address, examples: see above */
		/* so->lsa.sin6.sin6_family = AF_INET6; already set by mg_inet_pton */
		so->lsa.sin6.sin6_port = htons((uint16_t)port);
		*ip_version = 6;
	} else if ((vec->ptr[0] == '+')
		&& (sscanf(vec->ptr + 1, "%u%n", &port, &len)
			== 1)) { // NOLINT(cert-err34-c) 'sscanf' used to convert a
					 // string to an integer value, but function will not
					 // report conversion errors; consider using 'strtol'
					 // instead

		/* Port is specified with a +, bind to IPv6 and IPv4, INADDR_ANY */
		/* Add 1 to len for the + character we skipped before */
		len++;
		/* Set socket family to IPv6, do not use IPV6_V6ONLY */
		so->lsa.sin6.sin6_family = AF_INET6;
		so->lsa.sin6.sin6_port = htons((uint16_t)port);
		*ip_version = 4 + 6;
	} else if (is_valid_port(portUL = strtoul(vec->ptr, &endptr, 0))
		&& (vec->ptr != endptr)) {
		len = (int)(endptr - vec->ptr);
		port = (uint16_t)portUL;
		/* If only port is specified, bind to IPv4, INADDR_ANY */
		so->lsa.sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;

	} else if ((cb = strchr(vec->ptr, ':')) != NULL) {
		/* String could be a hostname. This check algorithm
		 * will only work for RFC 952 compliant hostnames,
		 * starting with a letter, containing only letters,
		 * digits and hyphen ('-'). Newer specs may allow
		 * more, but this is not guaranteed here, since it
		 * may interfere with rules for port option lists. */

		/* According to RFC 1035, hostnames are restricted to 255 characters
		 * in total (63 between two dots). */
		char hostname[256];
		size_t hostnlen = (size_t)(cb - vec->ptr);
		if ((hostnlen >= vec->len) || (hostnlen >= sizeof(hostname))) {
			/* This would be invalid in any case */
			*ip_version = 0;
			return 0;
		}

		str_lcpy(hostname, vec->ptr, hostnlen + 1);
		if (http_inet_pton(AF_INET, hostname, &so->lsa.sin, sizeof(so->lsa.sin), 1)) {
			if (sscanf(cb + 1, "%u%n", &port, &len)
				== 1) { // NOLINT(cert-err34-c) 'sscanf' used to convert a
						// string to an integer value, but function will not
						// report conversion errors; consider using 'strtol'
						// instead
				*ip_version = 4;
				so->lsa.sin.sin_port = htons((uint16_t)port);
				len += (int)(hostnlen + 1);
			} else {
				len = 0;
			}
		} else if (http_inet_pton(AF_INET6, hostname, &so->lsa.sin6, sizeof(so->lsa.sin6), 1)) {
			if (sscanf(cb + 1, "%u%n", &port, &len) == 1) {
				*ip_version = 6;
				so->lsa.sin6.sin6_port = htons((uint16_t)port);
				len += (int)(hostnlen + 1);
			} else {
				len = 0;
			}
		} else {
			len = 0;
		}
	} else if (vec->ptr[0] == 'x') {
		/* unix (linux) domain socket */
		if (vec->len < sizeof(so->lsa.sun.sun_path)) {
			len = vec->len;
			so->lsa.sun.sun_family = AF_UNIX;
			memset(so->lsa.sun.sun_path, 0, sizeof(so->lsa.sun.sun_path));
			memcpy(so->lsa.sun.sun_path, (char *)vec->ptr + 1, vec->len - 1);
			port = 0;
			*ip_version = 99;
		} else {
			/* String too long */
			len = 0;
		}
	} else {
		/* Parsing failure. */
		len = 0;
	}

	/* sscanf and the option splitting code ensure the following condition
	 * Make sure the port is valid and vector ends with the port, 'o', 's', or
	 * 'r' */
	if ((len > 0) && (is_valid_port(port))) {
		int bad_suffix = 0;
		size_t i;

		/* Parse any suffix character(s) after the port number */
		for (i = len; i < vec->len; i++) {
			unsigned char *opt = NULL;
			switch (vec->ptr[i]) {
				case 'o':
					opt = &so->is_optional;
					break;
				case 'r':
					opt = &so->has_redir;
					break;
				case 's':
					opt = &so->has_ssl;
					break;
				default: /* empty */
					break;
			}

			if ((opt) && (*opt == 0))
				*opt = 1;
			else {
				bad_suffix = 1;
				break;
			}
		}

		if ((bad_suffix == 0) && ((so->has_ssl == 0) || (so->has_redir == 0))) {
			return 1;
		}
	}

	/* Reset ip_version to 0 if there is an error */
	*ip_version = 0;
	return 0;
}

void http_set_close_on_exec(fds_t sock) {
#ifdef _WIN32
	(void)SetHandleInformation((HANDLE)(intptr_t)sock, HANDLE_FLAG_INHERIT, 0);
#else
	(void)fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
}

static int http_set_ports(http_ini_t *phys_ctx, struct vec vec,
	int portsOk, int portsTotal, int ip_version, http_socket so) {
	http_socket *ptr;
	int off, on = 0;
	union usa usa;
	socklen_t len;
	string_t opt_txt;
	long opt_listen_backlog;

	/* Create socket. */
	/* For a list of protocol numbers (e.g., TCP==6) see:
	 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml */
	if ((so.sock = socket(so.lsa.sa.sa_family, SOCK_STREAM,
		(ip_version == 99) ? (/* LOCAL */ 0) : (/* TCP */ 6))) == INVALID_SOCKET) {
		http_log(DEBUG_CRASH, NULL, "cannot create socket (entry %i)", portsTotal);
		if (so.is_optional) {
			portsOk++; /* it's okay if we couldn't create a socket,
					this port is optional anyway */
		}
		return portsOk;
	}

	if (ip_version == 99) {
		/* Unix domain socket */
	} else if (ip_version > 4) {
			/* Could be 6 for IPv6 only or 10 (4+6) for IPv4+IPv6 */
		if (ip_version > 6) {
			if (so.lsa.sa.sa_family == AF_INET6
				&& setsockopt(so.sock,
					IPPROTO_IPV6,
					IPV6_V6ONLY,
					(void *)&off,
					sizeof(off))
				!= 0) {
				/* Set IPv6 only option, but don't abort on errors. */
				http_log(DEBUG_CRASH, NULL,
					"cannot set socket option "
					"IPV6_V6ONLY=off (entry %i)",
					portsTotal);
			}
		} else {
			if (so.lsa.sa.sa_family == AF_INET6
				&& setsockopt(so.sock,
					IPPROTO_IPV6,
					IPV6_V6ONLY,
					(void *)&on,
					sizeof(on))
				!= 0) {
				/* Set IPv6 only option, but don't abort on errors. */
				http_log(DEBUG_CRASH, NULL,
					"cannot set socket option "
					"IPV6_V6ONLY=on (entry %i)",
					portsTotal);
			}
		}
	}

	if (so.lsa.sa.sa_family == AF_INET) {
		len = sizeof(so.lsa.sin);
		if (bind(so.sock, &so.lsa.sa, len) != 0) {
			http_log(DEBUG_CRASH, NULL,
				"cannot bind to %.*s: %d (%s)",
				(int)vec.len,
				vec.ptr,
				os_geterror(),
				strerror(errno));
			close(so.sock);
			so.sock = INVALID_SOCKET;
			if (so.is_optional) {
				portsOk++; /* it's okay if we couldn't bind, this port is
							  optional anyway */
			}
			return portsOk;
		}
	} else if (so.lsa.sa.sa_family == AF_INET6) {
		len = sizeof(so.lsa.sin6);
		if (bind(so.sock, &so.lsa.sa, len) != 0) {
			http_log(DEBUG_CRASH, NULL,
				"cannot bind to IPv6 %.*s: %d (%s)",
				(int)vec.len,
				vec.ptr,
				os_geterror(),
				strerror(errno));
			close(so.sock);
			so.sock = INVALID_SOCKET;
			if (so.is_optional) {
				portsOk++; /* it's okay if we couldn't bind, this port is
							  optional anyway */
			}
			return portsOk;
		}
	} else if (so.lsa.sa.sa_family == AF_UNIX) {
		len = sizeof(so.lsa.sun);
		if (bind(so.sock, &so.lsa.sa, len) != 0) {
			http_log(DEBUG_CRASH, NULL,
				"cannot bind to unix socket %s: %d (%s)",
				so.lsa.sun.sun_path,
				os_geterror(),
				strerror(errno));
			close(so.sock);
			so.sock = INVALID_SOCKET;
			if (so.is_optional) {
				portsOk++; /* it's okay if we couldn't bind, this port is
							  optional anyway */
			}
			return portsOk;
		}
	} else {
		http_log(DEBUG_CRASH, NULL, "cannot bind: address family not supported (entry %i)", portsTotal);
		close(so.sock);
		so.sock = INVALID_SOCKET;
		return portsOk;
	}

	if ((so.lsa.sa.sa_family == AF_INET) || (so.lsa.sa.sa_family == AF_INET6)) {
		if (getsockopt(so.sock, SOL_SOCKET, SO_TYPE, (void *)&on, &on) >= 0) {
			on = 1;
			if (setsockopt(so.sock,	SOL_SOCKET,	SO_REUSEADDR, (string_t)&on, sizeof(on)) != 0) {
				/* Set reuse option, but don't abort on errors. */
				http_log(DEBUG_CRASH, NULL,
					"cannot set socket option SO_REUSEADDR (entry %i)", portsTotal);
			}
		}
	}

	opt_txt = phys_ctx->host.config[LISTEN_BACKLOG_SIZE];
	opt_listen_backlog = strtol(opt_txt, NULL, 10);
	if ((opt_listen_backlog > INT_MAX) || (opt_listen_backlog < 1)) {
		http_log(DEBUG_CRASH, NULL,
			"%s value \"%s\" is invalid",
			config_options[LISTEN_BACKLOG_SIZE].name,
			opt_txt);
		close(so.sock);
		so.sock = INVALID_SOCKET;
		return portsOk;
	}

	if (listen(so.sock, (int)opt_listen_backlog) != 0) {
		http_log(DEBUG_CRASH, NULL,
			"cannot listen to %.*s: %d (%s)",
			(int)vec.len,
			vec.ptr,
			os_geterror(),
			strerror(errno));
		close(so.sock);
		so.sock = INVALID_SOCKET;
		return portsOk;
	}

	if ((getsockname(so.sock, &(usa.sa), &len) != 0)
		|| (usa.sa.sa_family != so.lsa.sa.sa_family)) {
		int err = os_geterror();
		http_log(DEBUG_CRASH, NULL,
			"call to getsockname failed %.*s: %d (%s)",
			(int)vec.len,
			vec.ptr,
			err,
			strerror(errno));
		close(so.sock);
		so.sock = INVALID_SOCKET;
		return portsOk;
	}

	/* Update lsa port in case of random free ports */
	if (so.lsa.sa.sa_family == AF_INET6) {
		so.lsa.sin6.sin6_port = usa.sin6.sin6_port;
	} else {
		so.lsa.sin.sin_port = usa.sin.sin_port;
	}

	if ((ptr = (http_socket *)
		realloc(phys_ctx->listening_sockets,
			(phys_ctx->num_listening_sockets + 1) * sizeof(phys_ctx->listening_sockets[0])))
		== NULL) {
		http_log(DEBUG_CRASH, NULL, "%s", "Out of memory");
		close(so.sock);
		so.sock = INVALID_SOCKET;
		return portsOk;
	}

	events_set_nonblocking(so.sock);
	phys_ctx->listening_sockets = ptr;
	phys_ctx->listening_sockets[phys_ctx->num_listening_sockets] = so;
	phys_ctx->num_listening_sockets++;
	portsOk++;

	return portsOk;
}

void http_close_listening_sockets(http_ini_t *ctx) {
	if (is_empty(ctx))
		return;

	if (!is_empty(ctx->listening_sockets)) {
		unsigned int i;
		for (i = 0; i < ctx->num_listening_sockets; i++) {
			close(ctx->listening_sockets[i].sock);
			/* For unix domain sockets, the socket name represents a file that has
			 * to be deleted. */
			/* See
			 * https://stackoverflow.com/questions/15716302/so-reuseaddr-and-af-unix
			 */
			if ((ctx->listening_sockets[i].lsa.sin.sin_family == AF_UNIX)
				&& (ctx->listening_sockets[i].sock != INVALID_SOCKET)) {
				(void)remove(ctx->listening_sockets[i].lsa.sun.sun_path);
			}
			ctx->listening_sockets[i].sock = INVALID_SOCKET;
		}
		free(ctx->listening_sockets);
		ctx->listening_sockets = NULL;
	}
}

int http_set_ports_option(http_ini_t *ctx) {
	string_t list;
	char error_string[ERROR_STRING_LEN];
	int on;
	int off;
	struct vec vec;
	http_socket so;
	http_socket *ptr;
	struct pollfd *pfd;
	union usa usa;
	socklen_t len;
	int ip_version;
	int ports_total;
	int ports_ok;

	if (ctx == NULL) return 0;

	on = 1;
	off = 0;
	ports_total = 0;
	ports_ok = 0;

	memset(&so, 0, sizeof(so));
	memset(&usa, 0, sizeof(usa));

	len = sizeof(usa);
	list = ctx->host.config[LISTENING_PORTS];
	while ((list = http_next_option(list, &vec, NULL)) != NULL) {
		ports_total++;
		if (!parse_port_string(&vec, &so, &ip_version)) {
			http_log(DEBUG_CRASH, NULL, "%s: %.*s: invalid port spec (entry %i). Expecting list of: %s",
				__func__, (int)vec.len, vec.ptr,
				ports_total, "[IP_ADDRESS:]PORT[s|r]");
			continue;
		}

		ports_ok = http_set_ports(ctx, vec, ports_ok, ports_total, ip_version, so);
	}

	if (ports_ok != ports_total) {
		http_close_listening_sockets(ctx);
		ports_ok = 0;
	}

	return ports_ok;

}

int http_inet_pton(int af, string_t src, void *dst, size_t dstlen, int resolve_src) {
	struct addrinfo hints, *res, *ressave;
	int func_ret = 0;
	int gai_ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = af;
	if (!resolve_src) {
		hints.ai_flags = AI_NUMERICHOST;
	}

	gai_ret = async_getaddrinfo(src, NULL, &hints, &res);
	if (gai_ret != 0) {
		/* gai_strerror could be used to convert gai_ret to a string */
		/* POSIX return values: see
		 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/freeaddrinfo.html
		 */
		/* Windows return values: see
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520%28v=vs.85%29.aspx
		 */
		return 0;
	}

	ressave = res;
	while (res) {
		if ((dstlen >= (size_t)res->ai_addrlen)
			&& (res->ai_addr->sa_family == af)) {
			memcpy(dst, res->ai_addr, res->ai_addrlen);
			func_ret = 1;
		}
		res = res->ai_next;
	}

	freeaddrinfo(ressave);
	return func_ret;
}

static const struct {
	string_t proto;
	size_t proto_len;
	unsigned default_port;
} abs_uri_protocols[] = {{"http://", 7, 80},
						 {"https://", 8, 443},
						 {"ws://", 5, 80},
						 {"wss://", 6, 443},
						 {NULL, 0, 0}};

enum uri_type_t http_get_uri_type(string_t uri) {
	int i;
	string_t hostend, portbegin;
	char *portend;
	unsigned long port;

	/* According to the HTTP standard
	 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
	 * URI can be an asterisk (*) or should start with slash (relative uri),
	 * or it should start with the protocol (absolute uri). */
	if ((uri[0] == '*') && (uri[1] == '\0')) {
		/* asterisk */
		return URI_TYPE_ASTERISK;
	}

	/* Valid URIs according to RFC 3986
	 * (https://www.ietf.org/rfc/rfc3986.txt)
	 * must only contain reserved characters :/?#[]@!$&'()*+,;=
	 * and unreserved characters A-Z a-z 0-9 and -._~
	 * and % encoded symbols.
	 */
	for (i = 0; uri[i] != 0; i++) {
		/* Check for CRLF injection attempts */
		if (uri[i] == '%') {
			if (uri[i + 1] == '0' && (uri[i + 2] == 'd' || uri[i + 2] == 'D')) {
				/* Found %0d (CR) */
				debug_info("CRLF injection attempt detected: %s\r\n", uri);
				return URI_TYPE_UNKNOWN;
			}
			if (uri[i + 1] == '0' && (uri[i + 2] == 'a' || uri[i + 2] == 'A')) {
				/* Found %0a (LF) */
				debug_info("CRLF injection attempt detected: %s\r\n", uri);
				return URI_TYPE_UNKNOWN;
			}
		}
		if ((unsigned char)uri[i] < 33) {
			/* control characters and spaces are invalid */
			return URI_TYPE_UNKNOWN;
		}
		/* Allow everything else here (See #894) */
	}

	/* A relative uri starts with a / character */
	if (uri[0] == '/') {
		/* relative uri */
		return URI_TYPE_RELATIVE;
	}

	/* It could be an absolute uri: */
	/* This function only checks if the uri is valid, not if it is
	 * addressing the current server. So civetweb can also be used
	 * as a proxy server. */
	for (i = 0; abs_uri_protocols[i].proto != NULL; i++) {
		if (str_case_equal(uri,
			abs_uri_protocols[i].proto,
			abs_uri_protocols[i].proto_len)) {

			hostend = strchr(uri + abs_uri_protocols[i].proto_len, '/');
			if (!hostend) {
				return URI_TYPE_UNKNOWN;
			}
			portbegin = strchr(uri + abs_uri_protocols[i].proto_len, ':');
			if (!portbegin) {
				return URI_TYPE_ABS_NOPORT;
			}

			port = strtoul(portbegin + 1, &portend, 10);
			if ((portend != hostend) || (port <= 0) || !is_valid_port(port)) {
				return URI_TYPE_UNKNOWN;
			}

			return URI_TYPE_ABS_PORT;
		}
	}

	return URI_TYPE_UNKNOWN;
}

string_t http_get_rel_url_at_current_server(string_t uri, http_t *conn) {
	string_t server_domain;
	size_t server_domain_len;
	size_t request_domain_len = 0;
	unsigned long port = 0;
	int i, auth_domain_check_enabled;
	string_t hostbegin = NULL;
	string_t hostend = NULL;
	string_t portbegin;
	char *portend;

	auth_domain_check_enabled =	str_is_case(conn->domain->config[ENABLE_AUTH_DOMAIN_CHECK], "yes");

	/* DNS is case insensitive, so use case insensitive string compare here */
	for (i = 0; abs_uri_protocols[i].proto != NULL; i++) {
		if (str_case_equal(uri,
			abs_uri_protocols[i].proto,
			abs_uri_protocols[i].proto_len)) {
			hostbegin = uri + abs_uri_protocols[i].proto_len;
			hostend = strchr(hostbegin, '/');
			if (!hostend) {
				return 0;
			}
			portbegin = strchr(hostbegin, ':');
			if ((!portbegin) || (portbegin > hostend)) {
				port = abs_uri_protocols[i].default_port;
				request_domain_len = (size_t)(hostend - hostbegin);
			} else {
				port = strtoul(portbegin + 1, &portend, 10);
				if ((portend != hostend) || (port <= 0)
					|| !is_valid_port(port)) {
					return 0;
				}
				request_domain_len = (size_t)(portbegin - hostbegin);
			}
			/* protocol found, port set */
			break;
		}
	}

	if (!port) {
		/* port remains 0 if the protocol is not found */
		return 0;
	}

	/* Check if the request is directed to a different server. */
	/* First check if the port is the same. */
	if (ntohs(USA_IN_PORT_UNSAFE(&conn->client.lsa)) != port) {
		/* Request is directed to a different port */
		return 0;
	}

	/* Finally check if the server corresponds to the authentication
	 * domain of the server (the server domain).
	 * Allow full matches (like http://mydomain.com/path/file.ext), and
	 * allow subdomain matches (like http://www.mydomain.com/path/file.ext),
	 * but do not allow substrings (like
	 * http://notmydomain.com/path/file.ext
	 * or http://mydomain.com.fake/path/file.ext). */
	if (auth_domain_check_enabled) {
		server_domain = conn->domain->config[AUTHENTICATION_DOMAIN];
		server_domain_len = strlen(server_domain);
		if ((server_domain_len == 0) || (hostbegin == NULL)) {
			return 0;
		}
		if ((request_domain_len == server_domain_len)
			&& (!memcmp(server_domain, hostbegin, server_domain_len))) {
			/* Request is directed to this server - full name match. */
		} else {
			if (request_domain_len < (server_domain_len + 2)) {
				/* Request is directed to another server: The server name
				 * is longer than the request name.
				 * Drop this case here to avoid overflows in the
				 * following checks. */
				return 0;
			}
			if (hostbegin[request_domain_len - server_domain_len - 1] != '.') {
				/* Request is directed to another server: It could be a
				 * substring
				 * like notmyserver.com */
				return 0;
			}
			if (0
				!= memcmp(server_domain,
					hostbegin + request_domain_len - server_domain_len,
					server_domain_len)) {
				/* Request is directed to another server:
				* The server name is different. */
				return 0;
			}
		}
	}

	return hostend;
}
