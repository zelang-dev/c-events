#include "httpi_internal.h"

#define IP_ADDR_STR_LEN (50)

static http_ini_t *http_atexit_ctrl_c = null;
static bool http_atexit_ctrl_c_flag = false;

static void http_ctrl_c_exit(void) {
	events_ctr_c_unwind();
	if (is_empty(http_atexit_ctrl_c) || !is_ptr_usable(http_atexit_ctrl_c))
		return;

	http_atexit_ctrl_c_flag = true;
	http_ini_t *ctx = http_atexit_ctrl_c;
	http_atexit_ctrl_c = null;
	http_stop(ctx);
	events_destroy(event_loop());
}

/*
 * Checks if the method in a request is a valid method.
 *
 * PTRACE is not supported for security reasons. Further more the following
 * WEBDAV methods have not been implemented:
 *
 * PROPPATCH, COPY, MOVE, LOCK, UNLOCK (RFC 2518)
 * + 11 methods from RFC 3253
 * ORDERPATCH (RFC 3648)
 * ACL (RFC 3744)
 * SEARCH (RFC 5323)
 * + MicroSoft extensions
 * https://msdn.microsoft.com/en-us/library/aa142917.aspx
 *
 * The PATCH method is only supported for CGI and other scripts and for callbacks. */
FORCEINLINE bool http_is_valid_method(string_t method) {
	return (!strcmp(method, "GET") || !strcmp(method, "POST") || !strcmp(method, "HEAD")
		|| !strcmp(method, "PUT")|| !strcmp(method, "DELETE") || !strcmp(method, "OPTIONS")
		|| !strcmp(method, "CONNECT") || !strcmp(method, "PROPFIND") || !strcmp(method, "MKCOL")
		|| !strcmp(method, "PATCH"));
}

/* Verify given socket address against the ACL.
 * Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed. */
static int http_check_acl(http_ini_t *phys_ctx, const union usa *sa) {
	int allowed, flag, matched;
	struct vec vec;

	if (phys_ctx) {
		string_t list = phys_ctx->host.config[ACCESS_CONTROL_LIST];
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
				http_log(DEBUG_ERROR, nullptr,
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

static void httpi_cleanup(void_t ptr) {
	http_t *conn = (http_t *)ptr;
	//recover_cb recover = (recover_cb)conn;
	string_t err = guard_message();
	if (!is_empty(conn)) {
		if (!is_empty(conn->req.buf))
			conn->req.buf = free_ex(conn->req.buf);

		if (!is_empty(conn->client))
			conn->client = free_ex(conn->client);

		http_free(conn);
	}

	if (!str_is_empty(err)) {
		cerr("Exception: %s"CLR_LN, err);
		//if (recover && guard_caught(err)) {
		//	recover(err);
		//}
	}
}

static void http_handler(int client) {
	guard {
		http_t *conn = (http_t *)events_get_target_data(client);
		defer(httpi_cleanup, conn);
		/* Request buffers are not pre-allocated. They are private to the
		 * request and do not contain any state information that might be
		 * of interest to anyone observing a server status.  */
		conn->req.buf = calloc(1, conn->ctx->max_request_size + 1);
		if (conn->req.buf == NULL) {
			http_log(DEBUG_CRASH, conn, "Out of memory: Cannot allocate buffer for task #%i", task_id());
		} else {
			conn->req.buf_size = (int)conn->ctx->max_request_size;
			conn->domain = &(conn->ctx->host); /* Use default domain and default host */
			conn->req.user_data = conn->ctx->user_data;
			conn->action = HTTP_REQUEST;
			http_process_connection(conn->ctx, conn);
		}
	} guarded;
}

/* Process new incoming connections to the server. */
http_t *http_accept(http_socket *listener, http_ini_t *ctx) {
	http_socket *so;
	http_t *conn = nullptr;
	time_t conn_birth_time;
	char src_addr[IP_ADDR_STR_LEN];
	char error_string[ERROR_STRING_LEN];
	fds_t sock;
	union usa *usa;
	socklen_t len;
	int on = 1;

	if (is_empty(listener) || is_empty(ctx))
		return nullptr;

	debug_info("\nhttp_accept waiting on: #%d socket"CLR_LN, socket2fd(listener->sock));
	if (listener->has_ssl) {
		sock = tls_accept(listener->sock, null, null);
	} else {
		sock = async_accept(socket2fd(listener->sock), null, null);
	}

	if (sock == INVALID_SOCKET
		|| is_empty(ctx)
		|| ctx->status != HTTP_STATUS_RUNNING) {
		return nullptr;
	}

	usa = events_get_sockaddr(sock);
	if (is_empty(so = (http_socket *)calloc(1, sizeof(http_socket)))) {
		http_log(DEBUG_INFO, nullptr, "%s: Out of memory", __func__);
		tls_closer(sock);
		sock = INVALID_SOCKET;
		return nullptr;
	}

	so->sock = sock;
	so->rsa.storage = usa->storage;
	memset(&so->lsa.sa, 0, sizeof(so->lsa.sa));
	len = sizeof(so->lsa.sa);
	conn_birth_time = time(null);
	if (!http_check_acl(ctx, (const union usa *)&so->rsa)) {
		sockaddr_to_str(src_addr, sizeof(src_addr), &so->rsa);
		http_log(DEBUG_INFO, nullptr, "%s: %s is not allowed to connect",
			__func__, src_addr);
		tls_closer(sock);
		sock = INVALID_SOCKET;
		free(so);
	} else {

		/* Put so socket structure into the queue */
		http_set_close_on_exec(so->sock);
		so->has_ssl = listener->has_ssl;
		so->has_redir = listener->has_redir;
		if (getsockname(so->sock, &so->lsa.sa, &len) != 0) {
			http_log(DEBUG_ERROR, nullptr, "%s: getsockname() failed: %s",
				__func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
		}

		on = 1;
		/*
		 * Set TCP keep-alive. This is needed because if HTTP-level keep-alive
		 * is enabled, and client resets the connection, server won't get
		 * TCP FIN or RST and will keep the connection open forever. With
		 * TCP keep-alive, next keep-alive handshake will figure out that
		 * the client is down and will close the server end.
		 * Thanks to Igor Klopov who suggested the patch. */
		if ((so->lsa.sa.sa_family == AF_INET)
			|| (so->lsa.sa.sa_family == AF_INET6)) {
			if (setsockopt(so->sock, SOL_SOCKET, SO_KEEPALIVE, (string_t)&on, sizeof(on)) != 0) {
				http_log(DEBUG_ERROR, nullptr, "%s: setsockopt(SOL_SOCKET SO_KEEPALIVE) failed: %s",
					__func__, http_error_string(os_geterror(), error_string, ERROR_STRING_LEN));
			}
		}

		if (ctx->request_timeout > 0)
			events_tcp_timeout(so->sock, ctx->request_timeout);

		so->in_use = 0;
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
			conn->client = so;
			conn->version = 1.1;
			conn->req.conn_birth_time = conn_birth_time;
			conn->req.remote_port =	ntohs(USA_IN_PORT_UNSAFE(&conn->client->rsa));
			conn->req.server_port =	ntohs(USA_IN_PORT_UNSAFE(&conn->client->lsa));
			sockaddr_to_str(conn->req.remote_addr, sizeof(conn->req.remote_addr), &conn->client->rsa);
			conn->type = (data_types)DATA_HTTPINFO;
			events_set_target_data(so->sock, (void *)conn);
		} else {
			events_set_target_data(so->sock, null);
			tls_closer(socket2fd(so->sock));
			so->sock = INVALID_SOCKET;
			free(so);
		}
	}

	return conn;
}

void http_stop(http_ini_t *ctx) {
	if (is_empty(ctx))
		return;

	http_atexit_ctrl_c = null;
	ctx->status = HTTP_STATUS_TERMINATED;
	http_free_ini(ctx);
}

void http_close_listening_sockets(http_ini_t *ctx) {
	if (is_empty(ctx) || is_empty(ctx->server_sockets))
		return;

	if ($size(ctx->server_sockets) > 0) {
		foreach(sockets in ctx->server_sockets) {
			http_socket *socket = (http_socket *)sockets.object;
			events_del(socket->sock);
			tls_closer(socket2fd(socket->sock));
			/* For unix domain sockets, the socket name represents a file that has
			 * to be deleted. */
			/* See https://stackoverflow.com/questions/15716302/so-reuseaddr-and-af-unix */
			if ((socket->lsa.sin.sin_family == AF_UNIX)
				&& (socket->sock != INVALID_SOCKET))
				(void)remove(socket->lsa.sun.sun_path);

			socket->sock = INVALID_SOCKET;
			if (http_atexit_ctrl_c_flag)
				events_task_unwind(socket->task);
			else if (!is_empty(socket->task))
				resume(socket->task);

			free(socket);
		}
	}

	$delete(ctx->server_sockets);
	ctx->server_sockets = null;
}

void http_free_ini(http_ini_t *ctx) {
	int i;
	struct http_cb_info *tmp_rh;

	if (is_empty(ctx))
		return;

	http_close_listening_sockets(ctx);
	atomic_flag_clear(&ctx->host.nonce_mutex);
	/* Deallocate config parameters is `deferred` to `main task` exit!
	for (i = 0; i < NUM_OPTIONS; i++) {
		if (!str_is_empty(ctx->host.config[i])) {
			str_free(ctx->host.config[i]);
		}
	}*/

	/* Deallocate request handlers */
	while (ctx->host.handlers) {
		tmp_rh = ctx->host.handlers;
		ctx->host.handlers = tmp_rh->next;
		free(tmp_rh->uri);
		free(tmp_rh);
	}

	ctx->host.handlers = null;
	/* deallocate system name string */
	if (!is_empty(ctx->systemName))
		ctx->systemName = free_ex(ctx->systemName);

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
		http_log(DEBUG_CRASH, nullptr, "%s: %s", __func__, buf);
	}

	http_free_ini(ctx);
	return nullptr;
}

FORCEINLINE http_clb_t http_callbacks(request_cb begin, log_msg_cb message,
	log_access_cb log, file_open_cb file, http_error_cb error, init_context_cb init) {
	http_clb_t callbacks = {0};
	callbacks.start = begin;
	callbacks.http_error = error;
	callbacks.init_context = init;
	callbacks.log_access = log;
	callbacks.log_message = message;
	callbacks.open_file = file;
	return callbacks;
}

int http_add_domain(http_ini_t *ctx, string_t *options, struct error_data *error) {
	string_t name;
	string_t value;
	string_t default_value;
	struct ini_domain_s *new_dom;
	struct ini_domain_s *dom;
	int idx, i;
	uint64_t nonce1 = 0, nonce2 = 0;
	const options_ini_t *config_options = http_get_valid_options();

	if (error != NULL) {
		error->code = 0;
		error->code_sub = 0;
		if (error->text_buffer_size > 0) {
			*error->text = 0;
		}
	}

	if ((ctx == NULL) || (options == NULL)) {
		if (error != NULL) {
			error->code = EINVAL;
			http_snprintf(NULL,
				NULL, /* No truncation check for error buffers */
				error->text,
				error->text_buffer_size,
				"%s",
				"Invalid parameters");
		}
		return -1;
	}

	if (ctx->status == HTTP_STATUS_STOPPING
		|| ctx->status == HTTP_STATUS_TERMINATED) {
		if (error != NULL) {
			error->code = ENOEXEC;
			http_snprintf(NULL,
				NULL, /* No truncation check for error buffers */
				error->text,
				error->text_buffer_size,
				"%s",
				"Server already stopped");
		}
		return -7;
	}

	new_dom = (struct ini_domain_s *)calloc(1, sizeof(struct ini_domain_s));
	if (!new_dom) {
		/* Out of memory */
		if (error != NULL) {
			error->code = ENOMEM;
			error->code_sub = (unsigned)sizeof(struct ini_domain_s);
			http_snprintf(NULL,
				NULL, /* No truncation check for error buffers */
				error->text,
				error->text_buffer_size,
				"%s",
				"Out or memory");
		}
		return -6;
	}

	/* Store options - TODO: unite duplicate code */
	while (options && (name = *options++) != NULL) {
		idx = http_get_option_index(name);
		if (idx == -1) {
			http_log(DEBUG_ERROR, null, "Invalid option: %s", name);
			if (error != NULL) {
				error->code = EINVAL;
				error->code_sub = (unsigned)-1;
				http_snprintf(NULL,
					NULL, /* No truncation check for error buffers */
					error->text,
					error->text_buffer_size,
					"Invalid option: %s",
					name);
			}
			free(new_dom);
			return -2;
		} else if ((value = *options++) == NULL) {
			http_log(DEBUG_ERROR, null, "%s: option value cannot be NULL", name);
			if (error != NULL) {
				error->code = EINVAL;
				error->code_sub = (unsigned)idx;
				http_snprintf(NULL,
					NULL, /* No truncation check for error buffers */
					error->text,
					error->text_buffer_size,
					"Invalid option value: %s",
					name);
			}
			free(new_dom);
			return -2;
		}
		if (new_dom->config[idx] != NULL) {
			/* Duplicate option: Later values overwrite earlier ones. */
			http_log(DEBUG_ERROR, null, "warning: %s: duplicate option", name);
			free(new_dom->config[idx]);
		}
		new_dom->config[idx] = str_dup_ex(value);
		debug_info("[%s] -> [%s]"CLR_LN, name, value);
	}

	/* Authentication domain is mandatory */
	/* TODO: Maybe use a new option hostname? */
	if (!new_dom->config[AUTHENTICATION_DOMAIN]) {
		http_log(DEBUG_ERROR, null, "%s", "authentication domain required");
		if (error != NULL) {
			error->code = EINVAL;
			error->code_sub = AUTHENTICATION_DOMAIN;
			http_snprintf(NULL,
				NULL, /* No truncation check for error buffers */
				error->text,
				error->text_buffer_size,
				"Mandatory option %s missing",
				config_options[AUTHENTICATION_DOMAIN].name);
		}
		free(new_dom);
		return -4;
	}

	/* Set default value if needed. Take the config value from
	 * ctx as a default value. */
	for (i = 0; config_options[i].name != NULL; i++) {
		default_value = ctx->host.config[i];
		if ((new_dom->config[i] == NULL) && (default_value != NULL)) {
			new_dom->config[i] = str_dup_ex(default_value);
		}
	}

	new_dom->handlers = ctx->host.handlers;
	new_dom->next = NULL;
	new_dom->nonce_count = 0;
	http_get_random(&nonce2);
	http_get_random(&nonce1);
	new_dom->auth_nonce_mask = nonce1 ^ (nonce2 << 31);

	foreach(sockets in ctx->server_sockets) {
		http_socket *socket = (http_socket *)sockets.object;
		if (socket->has_ssl) {
			char domain_cert[PATH_MAX + MAXHOSTNAMELEN + 4] = {0};
			char domain_pkey[PATH_MAX + MAXHOSTNAMELEN + 4] = {0};
			tls_config_t *config = tls_get_config(socket2fd(socket->sock));
			snprintf(domain_cert, sizeof(domain_cert), "%s%s.crt", default_cert_path(null), new_dom->config[AUTHENTICATION_DOMAIN]);
			snprintf(domain_pkey, sizeof(domain_pkey), "%s%s.key", default_cert_path(null), new_dom->config[AUTHENTICATION_DOMAIN]);
			if (!tls_config_add_keypair_file(config, domain_cert, domain_pkey)) {
				/* Init SSL failed */
				if (error != NULL) {
					error->code = tls_config_error_code(config);
					http_snprintf(NULL,
						NULL, /* No truncation check for error buffers */
						error->text,
						error->text_buffer_size,
						"%s: %s",
						"Initializing SSL context failed",
						tls_config_error(config));
				}
				free(new_dom);
				return -3;
			}
		}
	}

	/* Add element to linked list. */
	atomic_lock(&ctx->nonce_mutex);

	idx = 0;
	dom = &(ctx->host);
	for (;;) {
		if (str_is_case(new_dom->config[AUTHENTICATION_DOMAIN],
			dom->config[AUTHENTICATION_DOMAIN])) {
			/* Domain collision */
			http_log(DEBUG_ERROR, null,
				"domain %s already in use",
				new_dom->config[AUTHENTICATION_DOMAIN]);
			if (error != NULL) {
				error->code = EINVAL;
				http_snprintf(NULL,
					NULL, /* No truncation check for error buffers */
					error->text,
					error->text_buffer_size,
					"Domain %s specified by %s is already in use",
					new_dom->config[AUTHENTICATION_DOMAIN],
					config_options[AUTHENTICATION_DOMAIN].name);
			}
			free(new_dom);
			atomic_unlock(&ctx->nonce_mutex);
			return -5;
		}

		/* Count number of domains */
		idx++;

		if (dom->next == NULL) {
			dom->next = new_dom;
			break;
		}
		dom = dom->next;
	}

	atomic_unlock(&ctx->nonce_mutex);
	/* Return domain number */
	return idx;
}

http_ini_t *http_setup(int max_fd, http_clb_t *callbacks,
	void_t user_data, const options_ini_t **options) {
	uint64_t nonce = 0;
	int i;

	/*
	 * No memory for the `http_ini_t` structure is the only error which we
	 * don't log through `http_log()` for the simple reason that we do not
	 * have enough configured yet to make that function working. Having an
	 * OOM in this state of the process though should be noticed by the
	 * calling process in other parts of their execution anyway. */
	http_ini_t *ctx = calloc(1, sizeof(http_ini_t));
	if (is_empty(ctx))
		return nullptr;

	ctx->host.handlers = null;
	ctx->server_sockets = array();
	if (is_empty(ctx->server_sockets)) {
		free(ctx);
		return nullptr;
	}

	if (http_init_options(ctx, (string_t *)options))
		return nullptr;

	if (events_init((max_fd <= 0 ? atoi(ctx->host.config[MAX_FD]) : max_fd)))
		return http_abort_start(ctx, "Error setting `events_init()`");

	/* Random number generator will initialize at the first call */
	if (!http_get_random(&nonce))
		return http_abort_start(ctx, "Cannot initialize random number generator");

	ctx->host.auth_nonce_mask = nonce ^ (uint64_t)(ptrdiff_t)(options);
	atomic_flag_clear(&ctx->host.nonce_mutex);
	ctx->user_data = user_data;

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

	ctx->http_type = HTTP_INI_SERVER;
	ctx->status = HTTP_STATUS_STARTING;
	return ctx;
}

static void http_server_task(param_t args) {
	http_socket *listener = (http_socket *)args[0].object;
	http_ini_t *ctx = (http_ini_t *)args[1].object;
	http_t *conn = null;
	listener->task = active_scheduler_task();
	task_data_set(listener->task, (void_t)args);
	yield();
	while (!is_empty(ctx) && ctx->status == HTTP_STATUS_RUNNING) {
		if (!is_empty(conn = http_accept((http_socket *)listener, ctx))) {
			conn->ctx = ctx;
			accept_handler(http_handler, socket2fd(conn->client->sock));
		}
	}
}

int http_server(http_ini_t *ctx) {
	int i;
	events_t *loop = events_init_pool(2);
	if (!is_empty(ctx) && !is_empty(loop)) {
		ctx->status = HTTP_STATUS_RUNNING;
		foreach(socket in ctx->server_sockets) {
			async_ex(Kb(32), http_server_task, 2, socket.object, ctx);
		}

		http_atexit_ctrl_c = ctx;
		exception_ctrl_c_func = http_ctrl_c_exit;
		async_run(loop);
		return events_destroy(loop);
	}

	return EXIT_FAILURE;
}

static FORCEINLINE void *http_main_task(param_t args) {
	http_main_cb start = (http_main_cb)args[1].func;
	yield();
	if (!is_empty(start))
		start((http_ini_t *)args[0].object);

	return 0;
}

void httpi_start(http_ini_t *ctx, http_main_cb start) {
	events_t *loop = events_init_pool(thrd_cpu_count() / 2);
	if (is_empty(ctx) || is_empty(loop))
		exit(EXIT_FAILURE);

	int i;
	ctx->status = HTTP_STATUS_RUNNING;
	async_task(http_main_task, 2, ctx, start);
	foreach(socket in ctx->server_sockets) {
		async_ex(Kb(64), http_server_task, 2, socket.object, ctx);
	}

	http_atexit_ctrl_c = ctx;
	exception_ctrl_c_func = http_ctrl_c_exit;
	async_run(loop);
	events_destroy(loop);
	events_deinit();
}
