#include "httpie_internal.h"

static bool check_bool(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, bool *config);
static bool check_dbg(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, enum lh_dbg_t *config);
static bool check_dir(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config);
static bool check_file(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config);
static bool check_int(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, int *config, int minval, int maxval);
static bool check_patt(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config);
static bool check_str(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config);

/* Returns true, if a file defined by a specific path is located in memory. */
bool http_is_file_in_memory(http_ini_t *ctx, http_t *conn, const char *path, struct file *filep) {
	size_t size;

	if (ctx == NULL || conn == NULL || filep == NULL)
		return false;

	size = 0;
	if (ctx->callbacks.open_file) {
		filep->membuf = ctx->callbacks.open_file(ctx, conn, path, &size);
		/*
		 * NOTE: override filep->size only on success. Otherwise, it might
		 * break constructs like if (!http_stat() || !http_fopen()) ...
		 */
		if (!is_empty(filep->membuf))
			filep->size = size;
	}

	return !is_empty(filep->membuf);
}

int http_stat(http_ini_t *ctx, http_t *conn, const char *path, struct file *filep) {
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

char *http_error_string(int error_code, char *buf, size_t buf_len) {
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

/*
 * Sets the global password file option for a context.
 * The function returns false when an error occurs and
 * true when successful. */
bool http_set_gpass_option(http_ini_t *ctx) {
	struct file file = STRUCT_FILE_INITIALIZER;
	const char *path;
	char error_string[ARRAY_SIZE];

	if (is_empty(ctx))
		return false;

	path = ctx->global_auth_file;
	if (!is_empty(path) && !http_stat(ctx, NULL, path, &file)) {
		http_logger(DEBUG_ERROR, NULL, "%s: cannot open %s: %s",
			__func__, path, http_error_string(os_geterror(), error_string, ARRAY_SIZE));
		return false;
	}

	return true;
}

/*
 * Convert a string value to its boolean representation. If no boolean representation can be
 * found, the function returns true to indicate that further processing should
 * be aborted. Otherwise false is returned and the bool parameter is set to the
 * determined value. */
bool http_option_value_to_bool(const char *value, bool *config) {
	if (value == NULL || config == NULL)
		return true;

	if (!str_is_case(value, "true")) { *config = true;  return false; }
	if (!str_is_case(value, "false")) { *config = false; return false; }
	if (!str_is_case(value, "on")) { *config = true;  return false; }
	if (!str_is_case(value, "off")) { *config = false; return false; }
	if (!str_is_case(value, "yes")) { *config = true;  return false; }
	if (!str_is_case(value, "no")) { *config = false; return false; }
	if (!str_is_case(value, "1")) { *config = true;  return false; }
	if (!str_is_case(value, "0")) { *config = false; return false; }
	if (!str_is_case(value, "y")) { *config = true;  return false; }
	if (!str_is_case(value, "n")) { *config = false; return false; }

	return true;
}

/*
 * Returns an integer value
 * represented by an option value in a location pointed to by a parameter.
 * If this succeeds, false is returned. True is returned when an error occurred. */
bool http_option_value_to_int(const char *value, int *config) {
	const char *ptr;
	int val, sign;

	if (value == NULL || config == NULL)
		return true;

	val = 0;
	sign = 1;
	ptr = value;
	if (*ptr == '-') {
		sign = -1; ptr++;
	}

	if (!isdigit(*ptr))
		return true;

	while (isdigit(*ptr)) {
		val *= 10;
		val += *ptr - '0';
		ptr++;
	}

	if (*ptr != '\0')
		return true;

	*config = sign * val;
	return false;
}

bool http_process_options(http_ini_t *ctx, const struct lh_opt_t *options) {
	if (ctx == NULL) return true;

	while (options != NULL && options->name != NULL) {
		if (check_str(ctx, options, "access_control_allow_origin", &ctx->access_control_allow_origin)) return true;
		if (check_str(ctx, options, "access_control_list", &ctx->access_control_list)) return true;
		if (check_file(ctx, options, "access_log_file", &ctx->access_log_file)) return true;
		if (check_bool(ctx, options, "allow_sendfile_call", &ctx->allow_sendfile_call)) return true;
		if (check_str(ctx, options, "authentication_domain", &ctx->authentication_domain)) return true;
		if (check_str(ctx, options, "cgi_environment", &ctx->cgi_environment)) return true;
		if (check_file(ctx, options, "cgi_interpreter", &ctx->cgi_interpreter)) return true;
		if (check_patt(ctx, options, "cgi_pattern", &ctx->cgi_pattern)) return true;
		if (check_dbg(ctx, options, "debug_level", &ctx->debug_level)) return true;
		if (check_bool(ctx, options, "decode_url", &ctx->decode_url)) return true;
		if (check_dir(ctx, options, "document_root", &ctx->document_root)) return true;
		if (check_bool(ctx, options, "enable_directory_listing", &ctx->enable_directory_listing)) return true;
		if (check_bool(ctx, options, "enable_keep_alive", &ctx->enable_keep_alive)) return true;
		if (check_file(ctx, options, "error_log_file", &ctx->error_log_file)) return true;
		if (check_dir(ctx, options, "error_pages", &ctx->error_pages)) return true;
		if (check_str(ctx, options, "extra_mime_types", &ctx->extra_mime_types)) return true;
		if (check_file(ctx, options, "global_auth_file", &ctx->global_auth_file)) return true;
		if (check_patt(ctx, options, "hide_file_pattern", &ctx->hide_file_pattern)) return true;
		if (check_str(ctx, options, "index_files", &ctx->index_files)) return true;
		if (check_str(ctx, options, "listening_ports", &ctx->listening_ports)) return true;
		if (check_int(ctx, options, "num_threads", &ctx->num_threads, 1, INT_MAX)) return true;
		if (check_str(ctx, options, "protect_uri", &ctx->protect_uri)) return true;
		if (check_file(ctx, options, "put_delete_auth_file", &ctx->put_delete_auth_file)) return true;
		if (check_int(ctx, options, "request_timeout", &ctx->request_timeout, 0, INT_MAX)) return true;
		if (check_str(ctx, options, "run_as_user", &ctx->run_as_user)) return true;
		if (check_int(ctx, options, "ssi_include_depth", &ctx->ssi_include_depth, 0, 20)) return true;
		if (check_patt(ctx, options, "ssi_pattern", &ctx->ssi_pattern)) return true;
		if (check_file(ctx, options, "ssl_ca_file", &ctx->ssl_ca_file)) return true;
		if (check_dir(ctx, options, "ssl_ca_path", &ctx->ssl_ca_path)) return true;
		if (check_file(ctx, options, "ssl_certificate", &ctx->ssl_certificate)) return true;
		if (check_str(ctx, options, "ssl_cipher_list", &ctx->ssl_cipher_list)) return true;
		if (check_int(ctx, options, "ssl_protocol_version", &ctx->ssl_protocol_version, 0, 4)) return true;
		if (check_bool(ctx, options, "ssl_short_trust", &ctx->ssl_short_trust)) return true;
		if (check_int(ctx, options, "ssl_verify_depth", &ctx->ssl_verify_depth, 0, 9)) return true;
		if (check_bool(ctx, options, "ssl_verify_paths", &ctx->ssl_verify_paths)) return true;
		if (check_bool(ctx, options, "ssl_verify_peer", &ctx->ssl_verify_peer)) return true;
		if (check_int(ctx, options, "static_file_max_age", &ctx->static_file_max_age, 0, INT_MAX)) return true;
		if (check_str(ctx, options, "throttle", &ctx->throttle)) return true;
		if (check_bool(ctx, options, "tcp_nodelay", &ctx->tcp_nodelay)) return true;
		if (check_str(ctx, options, "url_rewrite_patterns", &ctx->url_rewrite_patterns)) return true;
		if (check_dir(ctx, options, "websocket_root", &ctx->websocket_root)) return true;
		if (check_int(ctx, options, "websocket_timeout", &ctx->websocket_timeout, 0, INT_MAX)) return true;

		/*
		 * TODO: Currently silently ignoring unrecognized options
		 */
		options++;
	}

	return false;
}

/*
 * Checks if an option is equal to a boolean config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. If the value could be found, also
 * false is returned. */
static bool check_bool(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, bool *config) {
	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing boolean option");
		return true;
	}

	if (str_is_case(option->name, name)) return false;
	if (!http_option_value_to_bool(option->value, config)) return false;

	http_abort_start(ctx, "Invalid boolean value \"%s\" for option \"%s\"", option->value, option->name);
	return true;
}  /* check_bool */

/*
 * Checks if an option is equal to a directory config parameter and
 * stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned. */
static bool check_dir(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config) {
	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing directory option");
		return true;
	}

	if (str_is_case(option->name, name))
		return false;

	*config = http_free_ex(*config);

	if (option->value == NULL)
		return false;

	*config = str_dup_ex(option->value);
	if (*config != NULL)
		return false;

	http_abort_start(ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name);
	return true;
}  /* check_dir */

/*
 * Checks if an option is equal to a pattern config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned. */
static bool check_patt(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config) {
	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing pattern option");
		return true;
	}

	if (str_is_case(option->name, name))
		return false;

	*config = http_free_ex(*config);

	if (option->value == NULL)
		return false;

	*config = str_dup_ex(option->value);
	if (*config != NULL)
		return false;

	http_abort_start(ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name);
	return true;
}  /* check_patt */

/*
 * Checks if an option is equal to a filename config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned. */
static bool check_file(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config) {
	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing file option");
		return true;
	}

	if (str_is_case(option->name, name))
		return false;

	*config = http_free_ex(*config);

	if (option->value == NULL)
		return false;

	*config = str_dup_ex(option->value);
	if (*config != NULL)
		return false;

	http_abort_start(ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name);
	return true;
}  /* check_file */

/*
 * Checks if an option is equal to a string config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. IF the value could be found, also
 * false is returned. */
static bool check_str(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, char **config) {
	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing string option");
		return true;
	}

	if (str_is_case(option->name, name))
		return false;

	*config = http_free_ex(*config);

	if (option->value == NULL) return false;

	*config = str_dup_ex(option->value);
	if (*config != NULL)
		return false;

	http_abort_start(ctx, "Out of memory assigning value \"%s\" to option \"%s\"", option->value, option->name);
	return true;
}  /* check_str */

/*
 * Checks in an option is equal to an integer config
 * parameter and stores the value if that is the case. If the value cannot be
 * recognized, true is returned and the function performs a complete cleanup.
 * If the option name could not be found, the function returns false to
 * indicate that the search should go on. If the value could be found and is
 * valid, also false is returned. */
static bool check_int(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, int *config, int minval, int maxval) {
	int val;

	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing integer option");
		return true;
	}

	if (str_is_case(option->name, name)) return false;

	if (!http_option_value_to_int(option->value, &val)) {
		if (val < minval) {
			http_abort_start(ctx, "Integer \"%s\" too small for option \"%s\"", option->value, option->name);
			return true;
		}

		if (val > maxval) {
			http_abort_start(ctx, "Integer \"%s\" too large for option \"%s\"", option->value, option->name);
			return true;
		}

		*config = val;
		return false;
	}

	http_abort_start(ctx, "Invalid integer value \"%s\" for option \"%s\"", option->value, option->name);
	return true;
}  /* check_int */

/*
 * Checks if an option is equal to a debug level
 * config parameter and stores the value if that is the case. If the value
 * cannot be recognized, true is returned and the function performs a complete
 * cleanup. If the option name could not be found, the function returns false
 * to indicate that the search should go on. If the value could be found and is
 * valid, also false is returned. */
static bool check_dbg(http_ini_t *ctx, const struct lh_opt_t *option, const char *name, enum lh_dbg_t *config) {
	int val;

	if (ctx == NULL || option == NULL || option->name == NULL || name == NULL || config == NULL) {
		http_abort_start(ctx, "Internal error parsing debug level option");
		return true;
	}

	if (str_is_case(option->name, name)) return false;

	if (!http_option_value_to_int(option->value, &val)) {
		switch (val) {
			case DEBUG_NONE:
			case DEBUG_CRASH:
			case DEBUG_ERROR:
			case DEBUG_WARNING:
			case DEBUG_INFO:
				*config = val;
				return false;
		}
	}

	http_abort_start(ctx, "Invalid value \"%s\"  for option \"%s\"", option->value, option->name);
	return true;
}  /* check_dbg */
