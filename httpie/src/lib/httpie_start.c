#include "httpie_internal.h"

#define IP_ADDR_STR_LEN (50)

static http_ini_t *http_atexit_ctrl_c = null;

static void http_ctrl_c_exit(void) {
	if (is_empty(http_atexit_ctrl_c) || !is_ptr_usable(http_atexit_ctrl_c))
		return;

	http_ini_t *ctx = http_atexit_ctrl_c;
	http_atexit_ctrl_c = null;
	http_stop(ctx);
}

/* Verify given socket address against the ACL.
 * Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed. */
static int http_check_acl(http_ini_t *phys_ctx, const union usa *sa) {
	int allowed, flag, matched;
	struct vec vec;

	if (phys_ctx) {
		const char *list = phys_ctx->host.config[ACCESS_CONTROL_LIST];
		/* If any ACL is set, deny by default */
		allowed = (list == nullptr) ? '+' : '-';
		while ((list = http_next_option(list, &vec, nullptr)) != nullptr) {
			flag = vec.ptr[0];
			matched = -1;
			if ((vec.len > 0) && ((flag == '+') || (flag == '-'))) {
				vec.ptr++;
				vec.len--;
				matched = http_parse_match_net(&vec, sa, 1);
			}

			if (matched < 0) {
				http_logger(DEBUG_ERROR, nullptr,
					"%s: subnet must be [+|-]IP-addr[/x]",
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

static FORCEINLINE void http_handler(int client) {
	guard {
		http_t *conn = (http_t *)events_get_target_data(client);
	defer(http_free, conn);

	//http_get_request(conn, ebuf, ebuf_len, err);

	} guarded;
}

/* Process new incoming connections to the server. */
http_t *http_accept(const http_socket *listener, http_ini_t *ctx) {
	http_socket so;
	http_t *conn = nullptr;
	char src_addr[IP_ADDR_STR_LEN];
	char error_string[ERROR_STRING_LEN];
	socklen_t len = sizeof(so.rsa);
	int on = 1;

	if (is_empty(listener) || is_empty(ctx))
		return nullptr;

	memset(&so, 0, sizeof(so));
	async_wait(listener->sock, 'r');
	so.sock = accept(listener->sock, &so.rsa.sa, &len);
	if (so.sock == INVALID_SOCKET)
		return nullptr;

	if (!http_check_acl(ctx, (const union usa *)&so.rsa)) {
		sockaddr_to_str(src_addr, sizeof(src_addr), &so.rsa);
		http_logger(DEBUG_INFO, nullptr, "%s: %s is not allowed to connect",
			__func__, src_addr);
		close(so.sock);
		so.sock = INVALID_SOCKET;
	} else {
		/* Put so socket structure into the queue */
		so.has_ssl = listener->has_ssl;
		so.has_redir = listener->has_redir;
		if (getsockname(so.sock, &so.lsa.sa, &len) != 0) {
			http_logger(DEBUG_ERROR, nullptr, "%s: getsockname() failed: %s",
				__func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
		}

		/*
		 * Set TCP keep-alive. This is needed because if HTTP-level keep-alive
		 * is enabled, and client resets the connection, server won't get
		 * TCP FIN or RST and will keep the connection open forever. With
		 * TCP keep-alive, next keep-alive handshake will figure out that
		 * the client is down and will close the server end.
		 * Thanks to Igor Klopov who suggested the patch. */
		if ((so.lsa.sa.sa_family == AF_INET)
			|| (so.lsa.sa.sa_family == AF_INET6)) {
			if (setsockopt(so.sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on)) != 0) {
				http_logger(DEBUG_ERROR, nullptr, "%s: setsockopt(SOL_SOCKET SO_KEEPALIVE) failed: %s",
					__func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
			}
		}

		on = 1;
		if ((so.lsa.sa.sa_family == AF_INET)
			|| (so.lsa.sa.sa_family == AF_INET6)) {
			if (setsockopt(so.sock, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on)) != 0) {
				http_logger(DEBUG_ERROR, nullptr, "%s: setsockopt(IPPROTO_TCP TCP_NODELAY) failed: %s",
					__func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
			}
		}

		so.in_use = 0;
		events_set_nonblocking(so.sock);
		conn = calloc(1, sizeof(http_t));
		if (!is_empty(conn)) {
			conn->names = nullptr;
			conn->cookies = nullptr;
			conn->garbage = nullptr;
			conn->sessions = nullptr;
			conn->dispositions = nullptr;
			conn->is_multipart = false;
			conn->code = STATUS_OK;
			conn->status = STATUS_NO_CONTENT;
			conn->hostname = nullptr;
			conn->fd = so.sock;
			conn->client = so;
			conn->version = 1.1;
			conn->type = (data_types)DATA_HTTPINFO;
			events_set_target_data(so.sock, (void *)conn);
		} else {
			events_set_target_data(so.sock, null);
			tls_closer(socket2fd(so.sock));
		}
	}

	return conn;
}

void http_stop(http_ini_t *ctx) {
	if (is_empty(ctx))
		return;

	if (ctx->status == HTTP_STATUS_RUNNING)
		ctx->status = HTTP_STATUS_TERMINATED;

	events_shutdown_pool();
	/* Wait until everything has stopped. */
	os_sleep(5);
	http_free_ini(ctx);
}

static void http_free_ini(http_ini_t *ctx) {
	int i;
	struct http_cb_info *tmp_rh;

	if (is_empty(ctx))
		return;

	http_close_listening_sockets(ctx);
	atomic_flag_clear(&ctx->host.nonce_mutex);
	/* Deallocate config parameters */
	for (i = 0; i < NUM_OPTIONS; i++) {
		if (!is_empty(ctx->host.config[i]))
			free(ctx->host.config[i]);
	}

	/* Deallocate request handlers */
	while (ctx->host.handlers) {
		tmp_rh = ctx->host.handlers;
		ctx->host.handlers = tmp_rh->next;
		free(tmp_rh->uri);
		free(tmp_rh);
	}

	/* deallocate system name string */
	ctx->systemName = http_free_ex(ctx->systemName);

	/* Deallocate context itself */
	free(ctx);
	ctx = null;
}

http_ini_t *http_abort_start(http_ini_t *ctx, string_t fmt, ...) {
	va_list ap;
	char buf[Kb(2)] = {0};

	if (ctx == nullptr) return nullptr;

	if (fmt != nullptr) {
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
		va_end(ap);
		http_logger(DEBUG_CRASH, nullptr, "%s: %s", __func__, buf);
	}

	http_free_ini(ctx);
	return nullptr;
}

FORCEINLINE http_clb_t http_callbacks(log_message_cb message, log_access_cb log,
	open_file_cb file, http_error_cb error, init_context_cb init) {
	http_clb_t callbacks = {0};
	callbacks.http_error = error;
	callbacks.init_context = init;
	callbacks.log_access = log;
	callbacks.log_message = message;
	callbacks.open_file = file;
	return callbacks;
}

http_ini_t *http_start(int max_fd, http_clb_t *callbacks, void *user_data,
	const options_ini_t *options) {
	uint64_t nonce = 0;
	int i;

	/*
	 * No memory for the `http_ini_t` structure is the only error which we
	 * don't log through `http_logger()` for the simple reason that we do not
	 * have enough configured yet to make that function working. Having an
	 * OOM in this state of the process though should be noticed by the
	 * calling process in other parts of their execution anyway. */
	http_ini_t *ctx = calloc(1, sizeof(http_ini_t));
	if (is_empty(ctx))
		return nullptr;

	if (events_init(max_fd))
		return http_abort_start(ctx, "Error setting `events_init()`");

	/* Random number generator will initialize at the first call */
	if (!http_get_random(&nonce))
		return http_abort_start(ctx, "Cannot initialize random number generator");

	ctx->host.auth_nonce_mask = nonce ^ (uint64_t)(ptrdiff_t)(options);
	atomic_flag_clear(&ctx->host.nonce_mutex);
	ctx->user_data = user_data;
	ctx->handlers = nullptr;
	if (http_init_options(ctx, (string_t *)options))
		return nullptr;

	struct utsname name;
	memset(&name, 0, sizeof(name));
	uname(&name);
	ctx->systemName = str_dup_ex(name.sysname);

	/*
	 * NOTE(lsm): order is important here. SSL certificates must
	 * be initialized before listening ports. UID must be set last. */
	if (!http_set_gpass_option(ctx))
		return http_abort_start(ctx, "Error setting gpass option");

	//use_certificate(http_get_option(ctx, "ssl_ca_path"), 0);
	if (!http_set_ports_option(ctx))
		return http_abort_start(ctx, "Error setting ports option");

#if !defined(_WIN32) && !defined(__ZEPHYR__)
	if (!http_set_uid_option(ctx))
		return http_abort_start(ctx, "Error setting UID option");
#endif

	if (!http_set_acl_option(ctx))
		return http_abort_start(ctx, "Error setting ACL option");

	/*
	 * Context has been created - init user libraries
	 *
	 * Context has been properly setup. It is now safe to use exit_context
	 * in case the system needs a shutdown. */
	if (!is_empty(callbacks)) {
		ctx->callbacks = *callbacks;
		if (!is_empty(ctx->callbacks.init_context))
			ctx->callbacks.init_context(ctx);
	}

	ctx->http_type = HTTP_TYPE_SERVER;
	return ctx;
}

static void http_server_task(param_t args) {
	const http_socket *listener = (const http_socket *)args[0].object;
	http_ini_t *ctx = (http_ini_t *)args[1].object;
	http_t *conn = null;
	while (!is_empty(ctx) && ctx->status != HTTP_STATUS_TERMINATED) {
		if (!is_empty(conn = http_accept(listener, ctx))) {
			conn->ctx = ctx;
			accept_handler(http_handler, socket2fd(conn->fd));
		}
	}
}

int http_server(http_ini_t *ctx) {
	int i;
	events_t *loop = events_thread_init();
	if (!is_empty(ctx) && !is_empty(loop)) {
		ctx->status = HTTP_STATUS_RUNNING;
		for (i = 0; i < ctx->num_listening_sockets; i++)
			async_ex(Kb(32), http_server_task, 2, ctx->listening_sockets[i], ctx);

		http_atexit_ctrl_c = ctx;
		exception_ctrl_c_func = http_ctrl_c_exit;
		async_run(loop);
		return events_destroy(loop);
	}

	return EXIT_FAILURE;
}
