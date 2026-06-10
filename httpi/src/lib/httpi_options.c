#include "httpi_internal.h"

/* Config option name, config types, default value.
 * Must be in the same order as the enum const above. */
static const options_ini_t config_options[] = {
	{"max_fd", INI_TYPE_NUMBER, "4096"},
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
/*
	{"cgi2_pattern", INI_TYPE_EXT_PATTERN, NULL},
	{"cgi2_environment", INI_TYPE_STRING_LIST, NULL},
	{"cgi2_interpreter", INI_TYPE_FILE, NULL},
	{"cgi2_interpreter_args", INI_TYPE_STRING, NULL},
	{"cgi2_buffering", INI_TYPE_BOOLEAN, "yes"},
*/
	{"put_delete_auth_file", INI_TYPE_FILE, NULL},
	{"protect_uri", INI_TYPE_STRING_LIST, NULL},
	{"authentication_domain", INI_TYPE_STRING, "mydomain.com"},
	{"enable_auth_domain_check", INI_TYPE_BOOLEAN, "yes"},
	{"ssi_pattern", INI_TYPE_EXT_PATTERN, "**.shtml$|**.shtm$"},
	{"enable_directory_listing", INI_TYPE_BOOLEAN, "yes"},
	{"enable_webdav", INI_TYPE_BOOLEAN, "no"},
	{"global_auth_file", INI_TYPE_FILE, NULL},
	{"index_files", INI_TYPE_STRING_LIST, "index.xhtml,index.html,index.htm,index.shtml,index.php"},
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

    /* The support for QuickJS.
     * The name of this config option might change. */
	{"quickjs_script_pattern", INI_TYPE_EXT_PATTERN, "**.ssjs$"},

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

string_t http_builtin_mime_type(string_t path) {
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

	for (i = 0; i < get_array_size(month_names); i++) {

		if (!strcmp(s, month_names[i])) return (int)i;
	}

	return -1;
}

time_t parse_date_str(string_t datetime) {
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
		|| (ims != NULL && (filep->last_modified <= parse_date_str(ims)));
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

string_t http_get_default_option(ini_options_type name) {
	return config_options[name].default_value;
}

FORCEINLINE const options_ini_t *http_get_valid_options(void) {
	return config_options;
}

int http_server_ports(http_ini_t *ctx, int size, http_server_port_t *ports) {
	int i, cnt = 0;

	if (size <= 0 || is_empty(ctx) || !($size(ctx->server_sockets) > 0))
		return DATA_INVALID;

	memset(ports, 0, sizeof(*ports) * (size_t)size);
	foreach(sockets in ctx->server_sockets) {
		http_socket *socket = (http_socket *)sockets.object;
		ports[cnt].port = ntohs(USA_IN_PORT_UNSAFE(&(socket->lsa)));
		ports[cnt].is_ssl = socket->has_ssl;
		ports[cnt].is_redirect = socket->has_redir;
		ports[cnt].is_optional = socket->is_optional;
		ports[cnt].is_bound = socket->sock != INVALID_SOCKET;
		if (socket->lsa.sa.sa_family == AF_INET) {
			/* IPv4 */
			ports[cnt].protocol = 1;
			cnt++;
		} else if (socket->lsa.sa.sa_family == AF_INET6) {
			/* IPv6 */
			ports[cnt].protocol = 3;
			cnt++;
		}

		if (isockets == size)
			break;
	}

	return cnt;
}

string_t http_get_option(http_ini_t *ctx, string_t name) {
	int i;
	if ((i = http_get_option_index(name)) == -1) {
		return NULL;
	} else if (!ctx || ctx->host.config[i] == NULL) {
		return "";
	} else {
		return ctx->host.config[i];
	}
}

http_t *fake_conn(http_t *fc, http_ini_t *ctx) {
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
			__func__, path, ex_strerror(os_geterror()));
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

	if (ctx == NULL) return false;

	uid = ctx->host.config[RUN_AS_USER];

	if (uid == NULL) return true;

	if ((pw = getpwnam(uid)) == NULL)
		http_log(DEBUG_CRASH, NULL, "%s: unknown user [%s]", __func__, uid);
	else if (setgid(pw->pw_gid) == -1)
		http_log(DEBUG_CRASH, NULL, "%s: setgid(%s): %s", __func__, uid, ex_strerror(os_geterror()));
	else if (setgroups(0, NULL))
		http_log(DEBUG_CRASH, NULL, "%s: setgroups(): %s", __func__, ex_strerror(os_geterror()));
	else if (setuid(pw->pw_uid) == -1)
		http_log(DEBUG_CRASH, NULL, "%s: setuid(%s): %s", __func__, uid, ex_strerror(os_geterror()));
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
				http_abort_start(ctx, "%s: setgid(%s): %s", __func__, run_as_user, ex_strerror(os_geterror()));
			} else if (setgroups(0, NULL) == -1) {
				http_abort_start(ctx, "%s: setgroups(): %s", __func__, ex_strerror(os_geterror()));
			} else if (setuid(to_pw->pw_uid) == -1) {
				http_abort_start(ctx, "%s: setuid(%s): %s", __func__, run_as_user, ex_strerror(os_geterror()));
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

int http_parse_match_net(const struct vec *vec, const u_saddr_t *sa, int no_strict) {
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
static int http_check_acl(http_ini_t *ctx, const u_saddr_t *sa) {
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
	u_saddr_t sa;
	memset(&sa, 0, sizeof(sa));
	//sa.sin6.sin6_family = AF_INET6;
	sa.sin.sin_family = AF_INET;
	return http_check_acl(ctx, &sa) != -1;
}

bool http_set_ini_option(http_ini_t *ctx, string_t option, string_t value) {
	int idx = http_get_option_index(option);
	if (idx == -1) {
		debug_info("Invalid configuration option: %s", option);
		return false;
	}

	if (ctx->host.config[idx] != NULL) {
		/* A duplicate configuration option is not an error - the last
		 * option value will be used. */
		debug_info("warning: %s: duplicate option"CLR_LN, option);
	}

	ctx->host.config[idx] = (string)value;
	//ctx->host.config[idx] = str_dup(value);
	debug_info("[%s] -> [%s]"CLR_LN, option, value);
	return true;
}

bool http_ini_options(http_ini_t *ctx, string_t *options) {
	string_t name, value, default_value;
	int ireq, i, idx;

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
			//free(ctx->host.config[idx]);
		}

		ctx->host.config[idx] = (string)value;
		//$append_string(ctx->options, ctx->host.config[idx]);
		debug_info("[%s] -> [%s]"CLR_LN, name, value);
	}

	/* Set default value if needed */
	for (i = 0; config_options[i].name != NULL; i++) {
		default_value = config_options[i].default_value;
		if ((ctx->host.config[i] == NULL) && (default_value != NULL)) {
			ctx->host.config[i] = (string)default_value;
			//$append_string(ctx->options, ctx->host.config[i]);
		}
	}

	/* Request size option */
	ireq = atoi(ctx->host.config[MAX_REQUEST_SIZE]);
	if (ireq < 1024) {
		http_abort_start(ctx, "%s too small", config_options[MAX_REQUEST_SIZE].name);
		return true;
	}

	ctx->max_request_size = (unsigned)ireq;
	ireq = atoi(ctx->host.config[REQUEST_TIMEOUT]);
	ctx->request_timeout = (unsigned)ireq;
	return false;
}

int http_match_prefix(string_t pattern, size_t pattern_len, string_t str) {
	string_t or_str;
	size_t i;
	int j, len, res;

	if ((or_str = (string_t)memchr(pattern, '|', pattern_len)) != NULL) {
		res = http_match_prefix(pattern, (size_t)(or_str - pattern), str);
		return res > 0
			? res
			: http_match_prefix(or_str + 1, (size_t)((pattern + pattern_len) - (or_str + 1)), str);
	}

	for (i = 0, j = 0; i < pattern_len; i++, j++) {
		if (pattern[i] == '?' && str[j] != '\0') {
			continue;
		} else if (pattern[i] == '$') {
			return str[j] == '\0' ? j : -1;
		} else if (pattern[i] == '*') {
			i++;
			if (pattern[i] == '*') {
				i++;
				len = (int)strlen(str + j);
			} else {
				len = (int)strcspn(str + j, "/");
			}
			if (i == pattern_len) {
				return j + len;
			}
			do {
				res = http_match_prefix(pattern + i, pattern_len - i, str + j + len);
			} while (res == -1 && len-- > 0);
			return res == -1 ? -1 : j + res + len;
		} else if (tolower(*(const unsigned char *)&pattern[i]) != tolower(*(const unsigned char *)&str[j])) {
			return -1;
		}
	}
	return j;
}

ptrdiff_t http_match_prefix_strlen(string_t pattern, string_t str) {
	if (pattern == NULL) {
		return -1;
	}

	return http_match_prefix(pattern, strlen(pattern), str);
}

static int isbyte(int n) { return n >= 0 && n <= 255; }
static int parse_net(string_t spec, uint32_t *net, uint32_t *mask) {
	int n, a, b, c, d, slash = 32, len = 0;

	if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5 ||
		sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) &&
		isbyte(a) && isbyte(b) && isbyte(c) && isbyte(d) && slash >= 0 &&
		slash < 33) {
		len = n;
		*net = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) |
			(uint32_t)d;
		*mask = slash ? 0xffffffffU << (32 - slash) : 0;
	}

	return len;
}

int set_throttle(string_t spec, uint32_t remote_ip, string_t uri) {
	int throttle = 0;
	struct vec vec, val;
	uint32_t net, mask;
	char mult;
	double v;

	while ((spec = http_next_option(spec, &vec, &val)) != NULL) {
		mult = ',';
		if (sscanf(val.ptr, "%lf%c", &v, &mult) < 1 || v < 0 ||
			(tolower(*(const unsigned char *)&mult) != 'k' && tolower(*(const unsigned char *)&mult) != 'm' &&
				mult != ',')) {
			continue;
		}
		v *= tolower(*(const unsigned char *)&mult) == 'k' ? 1024 : tolower(*(const unsigned char *)&mult) == 'm' ? 1048576
			: 1;
		if (vec.len == 1 && vec.ptr[0] == '*') {
			throttle = (int)v;
		} else if (parse_net(vec.ptr, &net, &mask) > 0) {
			if ((remote_ip & mask) == net) {
				throttle = (int)v;
			}
		} else if (http_match_prefix(vec.ptr, vec.len, uri) > 0) {
			throttle = (int)v;
		}
	}

	return throttle;
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
		if (conn->client->has_ssl) {
			/* This is a HTTPS connection, maybe we have a hostname
			 * from SNI (set in ssl_servername_callback). */
			string_t sslhost = conn->domain->config[AUTHENTICATION_DOMAIN];
			if (sslhost && (conn->domain != &(conn->ctx->host))) {
				/* We are not using the default domain */
				if ((strlen(sslhost) != host.len)
					|| !str_case_equal(host.ptr, sslhost, host.len)) {
					/* Mismatch between SNI domain and HTTP domain */
					debug_info("Host mismatch: SNI: %s, HTTPS: %.*s"CLR_LN,
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
					debug_info("HTTP domain %s found"CLR_LN,
						dom->config[AUTHENTICATION_DOMAIN]);
					conn->domain = dom;
					break;
				}

				atomic_lock(&conn->ctx->nonce_mutex);
				dom = dom->next;
				atomic_unlock(&conn->ctx->nonce_mutex);
			}
		}
		debug_info("HTTP%s Host: %.*s"CLR_LN, conn->client->has_ssl ? "S" : "", (int)host.len, host.ptr);
	} else {
		debug_info("HTTP%s Host is not set"CLR_LN, conn->client->has_ssl ? "S" : "");
	}

	return 1;
}

int is_valid_port(unsigned long port) {
	return (port <= 0xffff);
}

int parse_port_string(const struct vec *vec, http_socket *so, int *ip_version) {
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
	memset(so, 0, sizeof(http_socket));
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
		snprintf((string)vec->hostname, sizeof(vec->hostname), "%s", (string)vec->ptr);
		*ip_version = 4;
	} else if (sscanf(vec->ptr, "[%49[^]]]:%u%n", buf, &port, &len) == 2
		&& ((size_t)len <= vec->len)
		&& async_inet_pton(AF_INET6, buf, &so->lsa.sin6, sizeof(so->lsa.sin6), 0)) {
		snprintf((string)vec->hostname, sizeof(vec->hostname), "%s", (string)buf);
		/* IPv6 address, examples: see above */
		/* so->lsa.sin6.sin6_family = AF_INET6; already set by async_inet_pton */
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
		size_t hostnlen = (size_t)(cb - vec->ptr);
		if ((hostnlen >= vec->len) || (hostnlen >= sizeof(vec->hostname))) {
			/* This would be invalid in any case */
			*ip_version = 0;
			return 0;
		}

		str_lcpy((string)vec->hostname, vec->ptr, hostnlen + 1);
		if (async_inet_pton(AF_INET, vec->hostname, &so->lsa.sin, sizeof(so->lsa.sin), 1)) {
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
		} else if (async_inet_pton(AF_INET6, vec->hostname, &so->lsa.sin6, sizeof(so->lsa.sin6), 1)) {
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
					opt = (unsigned char *)&so->has_redir;
					break;
				case 's':
					opt = (unsigned char *)&so->has_ssl;
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
	int portsOk, int portsTotal, int ip_version, http_socket *so) {
	int ip_family, off = 0, on = 0;
	u_saddr_t usa;
	socklen_t len;
	string_t opt_txt;
	long opt_listen_backlog;

	opt_txt = phys_ctx->host.config[LISTEN_BACKLOG_SIZE];
	opt_listen_backlog = strtol(opt_txt, NULL, 10);
	if ((opt_listen_backlog > INT_MAX) || (opt_listen_backlog < 1)) {
		http_log(DEBUG_CRASH, NULL,
			"%s value \"%s\" is invalid",
			config_options[LISTEN_BACKLOG_SIZE].name,
			opt_txt);

		return portsOk;
	}

	ip_family = ip_version == 99
		? -1
		: (ip_version >= 6
			? ip_version
			: (ip_version == 4 ? 1 : 0));
	if (so->has_ssl) {
		if ((so->sock = tls_socket_set(&so->lsa.sa, vec.hostname, opt_listen_backlog, ip_family)) < 0) {
			http_log(DEBUG_CRASH, NULL, "cannot create secure socket on %s (entry %i)", vec.hostname, portsTotal);
			free(so);
			return portsOk;
		}
	} else {

		if ((so->sock = async_socket(&so->lsa.sa, vec.hostname, opt_listen_backlog, ip_family)) == INVALID_SOCKET) {
			http_log(DEBUG_CRASH, NULL, "cannot create socket or listen on %s (entry %i)", vec.hostname, portsTotal);
			if (so->is_optional) {
				portsOk++; /* it's okay if we couldn't create a socket,
						this port is optional anyway */
			}
			free(so);
			return portsOk;
		}
	}

	so->lsa.sa = events_get_sockaddr(so->sock)->sa;
	memset(&usa.storage, 0, sizeof(usa.storage));
	len = so->lsa.sa.sa_family == AF_INET6 ? sizeof(so->lsa.sin6) : sizeof(so->lsa.sin);
	if ((getsockname(so->sock, &usa.sa, &len) != 0) || (usa.sa.sa_family != so->lsa.sa.sa_family)) {
		int err = os_geterror();
		http_log(DEBUG_CRASH, NULL, "call to getsockname failed `%s` : %d (%s)",
			vec.hostname, err, ex_strerror(err));
		tls_closer(so->sock);
		so->sock = INVALID_SOCKET;
		free(so);
		return portsOk;
	}

	/* Update lsa port in case of random free ports */
	if (so->lsa.sa.sa_family == AF_INET6) {
		so->lsa.sin6.sin6_port = usa.sin6.sin6_port;
	} else {
		so->lsa.sin.sin_port = usa.sin.sin_port;
	}

	$append(phys_ctx->server_sockets, so);
	portsOk++;
	return portsOk;
}

int http_set_ports_option(http_ini_t *ctx) {
	string_t list;
	char error_string[ERROR_STRING_LEN];
	struct vec vec;
	http_socket *so;
	u_saddr_t usa;
	socklen_t len;
	int on, off, ip_version, ports_total, ports_ok;

	if (ctx == NULL) return 0;

	on = 1;
	off = 0;
	ip_version = 0;
	ports_total = 0;
	ports_ok = 0;

	list = ctx->host.config[LISTENING_PORTS];
	memset(&vec, 0, sizeof(vec));
	while ((list = http_next_option(list, &vec, NULL)) != NULL) {
		ports_total++;
		if (is_empty(so = calloc(1, sizeof(http_socket)))) {
			http_log(DEBUG_CRASH, NULL, "%s", "Out of memory");
			break;
		}

		if (!parse_port_string(&vec, so, &ip_version)) {
			http_log(DEBUG_CRASH, NULL, "%s: %.*s: invalid port spec (entry %i). Expecting list of: %s",
				__func__, (int)vec.len, vec.ptr,
				ports_total, "[IP_ADDRESS:]PORT[s|r]");
			free(so);
			continue;
		}

		/* Create socket. */
		/* For a list of protocol numbers (e.g., TCP==6) see:
		* https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml */
		ports_ok = http_set_ports(ctx, vec, ports_ok, ports_total, ip_version, so);
	}

	if (ports_ok != ports_total) {
		http_close_listening_sockets(ctx);
		ports_ok = 0;
	}

	return ports_ok;
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
				debug_info("CRLF injection attempt detected: %s"CLR_LN, uri);
				return URI_TYPE_UNKNOWN;
			}
			if (uri[i + 1] == '0' && (uri[i + 2] == 'a' || uri[i + 2] == 'A')) {
				/* Found %0a (LF) */
				debug_info("CRLF injection attempt detected: %s"CLR_LN, uri);
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
	if (ntohs(USA_IN_PORT_UNSAFE(&conn->client->lsa)) != port) {
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

static size_t http_str_append(char **dst, char *end, string_t src) {
	size_t len = strlen(src);
	if (*dst != end) {
		/* Append src if enough space, or close dst. */
		if ((size_t)(end - *dst) > len) {
			strcpy(*dst, src);
			*dst += len;
		} else {
			*dst = end;
		}
	}
	return len;
}

int http_get_system_info(char *buffer, int buflen) {
	char *end, *append_eoobj = NULL, block[256];
	size_t system_info_length = 0;

#if defined(_WIN32)
	static const char eol[] = "\r\n", eoobj[] = "\r\n}\r\n";
#else
	static const char eol[] = "\n", eoobj[] = "\n}\n";
#endif

	if ((buffer == NULL) || (buflen < 1)) {
		buflen = 0;
		end = buffer;
	} else {
		*buffer = 0;
		end = buffer + buflen;
	}
	if (buflen > (int)(sizeof(eoobj) - 1)) {
		/* has enough space to append eoobj */
		append_eoobj = buffer;
		if (end) {
			end -= sizeof(eoobj) - 1;
		}
	}

	system_info_length += http_str_append(&buffer, end, "{");

	/* Server version */
	{
		string_t version = httpi_version();
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			"%s\"version\" : \"%s\"",
			eol,
			version);
		system_info_length += http_str_append(&buffer, end, block);
	}

	/* System info */
	{
#if defined(_WIN32)
		DWORD dwVersion = 0;
		DWORD dwMajorVersion = 0;
		DWORD dwMinorVersion = 0;
		SYSTEM_INFO si;

		GetSystemInfo(&si);

#if defined(_MSC_VER)
#pragma warning(push)
		/* GetVersion was declared deprecated */
#pragma warning(disable : 4996)
#endif
		dwVersion = GetVersion();
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

		dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
		dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"os\" : \"Windows %u.%u\"",
			eol,
			(unsigned)dwMajorVersion,
			(unsigned)dwMinorVersion);
		system_info_length += http_str_append(&buffer, end, block);

		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"cpu\" : \"type %u, cores %u, mask %x\"",
			eol,
			(unsigned)si.wProcessorArchitecture,
			(unsigned)si.dwNumberOfProcessors,
			(unsigned)si.dwActiveProcessorMask);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__rtems__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"os\" : \"%s %s\"",
			eol,
			"RTEMS",
			rtems_version());
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__ZEPHYR__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"os\" : \"%s\"",
			eol,
			"Zephyr OS",
			ZEPHYR_VERSION);
		system_info_length += http_str_append(&buffer, end, block);
#else
		struct utsname name;
		memset(&name, 0, sizeof(name));
		uname(&name);

		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"os\" : \"%s %s (%s) - %s\"",
			eol,
			name.sysname,
			name.version,
			name.release,
			name.machine);
		system_info_length += http_str_append(&buffer, end, block);
#endif
	}

	/* Features */
	{
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"features\" : %lu"
			",%s\"feature_list\" : \"Server:%s%s%s%s%s%s%s%s%s\"",
			eol,
			(unsigned long)6,
			eol,
			" Files",
			" HTTPS",
			"",
			" IPv6",
			" WebSockets",
			"",
			" JavaScript",
			" Cache",
			"");
		system_info_length += http_str_append(&buffer, end, block);

		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"javascript\" : \"QuickJS-NG %u.%u.%u\"",
			eol,
			(unsigned)QJS_VERSION_MAJOR,
			(unsigned)QJS_VERSION_MINOR,
			(unsigned)QJS_VERSION_PATCH);
		system_info_length += http_str_append(&buffer, end, block);
	}

	/* Build identifier. If BUILD_DATE is not set, __DATE__ will be used. */
	{
#if defined(BUILD_DATE)
		string_t bd = BUILD_DATE;
#else
#if defined(GCC_DIAGNOSTIC)
#if GCC_VERSION >= 40900
#pragma GCC diagnostic push
		/* Disable idiotic compiler warning -Wdate-time, appeared in gcc5. This
		 * does not work in some versions. If "BUILD_DATE" is defined to some
		 * string, it is used instead of __DATE__. */
#pragma GCC diagnostic ignored "-Wdate-time"
#endif
#endif
		string_t bd = __DATE__;
#if defined(GCC_DIAGNOSTIC)
#if GCC_VERSION >= 40900
#pragma GCC diagnostic pop
#endif
#endif
#endif

		http_snprintf(null, block, sizeof(block), ",%s\"build\" : \"%s\"", eol, bd);

		system_info_length += http_str_append(&buffer, end, block);
	}

	/* Compiler information */
	/* http://sourceforge.net/p/predef/wiki/Compilers/ */
	{
#if defined(_MSC_VER)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"MSC: %u (%u)\"",
			eol,
			(unsigned)_MSC_VER,
			(unsigned)_MSC_FULL_VER);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__MINGW64__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"MinGW64: %u.%u\"",
			eol,
			(unsigned)__MINGW64_VERSION_MAJOR,
			(unsigned)__MINGW64_VERSION_MINOR);
		system_info_length += http_str_append(&buffer, end, block);
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"MinGW32: %u.%u\"",
			eol,
			(unsigned)__MINGW32_MAJOR_VERSION,
			(unsigned)__MINGW32_MINOR_VERSION);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__MINGW32__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"MinGW32: %u.%u\"",
			eol,
			(unsigned)__MINGW32_MAJOR_VERSION,
			(unsigned)__MINGW32_MINOR_VERSION);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__clang__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"clang: %u.%u.%u (%s)\"",
			eol,
			__clang_major__,
			__clang_minor__,
			__clang_patchlevel__,
			__clang_version__);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__GNUC__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"gcc: %u.%u.%u\"",
			eol,
			(unsigned)__GNUC__,
			(unsigned)__GNUC_MINOR__,
			(unsigned)__GNUC_PATCHLEVEL__);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__INTEL_COMPILER)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"Intel C/C++: %u\"",
			eol,
			(unsigned)__INTEL_COMPILER);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__BORLANDC__)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"Borland C: 0x%x\"",
			eol,
			(unsigned)__BORLANDC__);
		system_info_length += http_str_append(&buffer, end, block);
#elif defined(__SUNPRO_C)
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"Solaris: 0x%x\"",
			eol,
			(unsigned)__SUNPRO_C);
		system_info_length += http_str_append(&buffer, end, block);
#else
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"compiler\" : \"other\"",
			eol);
		system_info_length += http_str_append(&buffer, end, block);
#endif
	}

	/* Determine 32/64 bit data mode.
	 * see https://en.wikipedia.org/wiki/64-bit_computing */
	{
		http_snprintf(
			NULL,
			block,
			sizeof(block),
			",%s\"data_model\" : \"int:%u/%u/%u/%u, float:%u/%u/%u, "
			"char:%u/%u, "
			"ptr:%u, size:%u, time:%u\"",
			eol,
			(unsigned)sizeof(short),
			(unsigned)sizeof(int),
			(unsigned)sizeof(long),
			(unsigned)sizeof(long long),
			(unsigned)sizeof(float),
			(unsigned)sizeof(double),
			(unsigned)sizeof(long double),
			(unsigned)sizeof(char),
			(unsigned)sizeof(wchar_t),
			(unsigned)sizeof(void *),
			(unsigned)sizeof(size_t),
			(unsigned)sizeof(time_t));
		system_info_length += http_str_append(&buffer, end, block);
	}

	/* Terminate string */
	if (append_eoobj) {
		strcat(append_eoobj, eoobj);
	}
	system_info_length += sizeof(eoobj) - 1;

	return (int)system_info_length;
}

int http_get_context_info(const http_ini_t *ctx, char *buffer, int buflen) {
	(void)ctx;
	if ((buffer != NULL) && (buflen > 0)) {
		*buffer = 0;
	}
	return 0;
}

FORCEINLINE void http_user_data_set(const http_t *const_conn, void_t data) {
	if (const_conn != NULL) {
		http_t *conn = (http_t *)const_conn;
		conn->req.conn_data = data;
	}
}

FORCEINLINE void_t http_user_data(const http_t *conn) {
	if (conn != NULL) {
		return conn->req.conn_data;
	}
	return NULL;
}

FORCEINLINE httpi_t *http_request_info(const http_t *conn) {
	if (conn != NULL) {
		return (httpi_t *)&conn->req;
	}

	return NULL;
}

FORCEINLINE http_ini_t *httpi_context(http_t *conn) {
	return (conn == NULL) ? (http_ini_t *)NULL : (conn->ctx);
}

FORCEINLINE void_t httpi_user_data(http_ini_t *ctx) {
	return (ctx == NULL) ? NULL : ctx->user_data;
}

FORCEINLINE void_t httpi_user_context_data(http_t *conn) {
	return httpi_user_data(httpi_context(conn));
}

FORCEINLINE string_t httpi_version(void) {
	return HTTPI_VERSION;
}
