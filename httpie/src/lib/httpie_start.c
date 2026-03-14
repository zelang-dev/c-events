#include "httpie_internal.h"

#ifdef _WIN32
CRITICAL_SECTION global_log_file_lock = {0};
#endif /* _WIN32 */
static void *httpie_main(param_t args);

/* Use to stop an instance of a `httpie` server completely
 * and return all its resources. */
void http_stop(http_ini_t *ctx) {
	if (ctx == NULL)
		return;

	/*
	 * Set stop flag, so all threads know they have to exit. If for some
	 * reason the context was already stopping or terminated, we do not set
	 * the stopping request here again, just to be sure that we don't
	 * accidentally reset a terminated state back to a stopping state. In
	 * that case the context would never be flagged as terminated again.
	 */
	if (ctx->status == HTTP_STATUS_RUNNING)
		ctx->status = HTTP_STATUS_STOPPING;

	/*
	 * Wait until everything has stopped.
	 */
	while (ctx->status != HTTP_STATUS_TERMINATED)
		os_sleep(10);

	http_free_context(ctx);
}

void http_free_context(http_ini_t *ctx) {
	struct httplib_handler_info *tmp_rh;

	if (ctx == NULL) return;

	if (ctx->callbacks.exit_context != NULL) ctx->callbacks.exit_context(ctx);

	atomic_flag_clear(&ctx->nonce_mutex);
	http_free_config_options(ctx);

#if defined(_WIN32)
	DeleteCriticalSection(&global_log_file_lock);
#endif /* _WIN32 */

	/*
	 * deallocate system name string
	 */
	ctx->systemName = http_free_ex(ctx->systemName);

	/*
	 * Deallocate context itself
	 */
	free(ctx);
	ctx = null;
}

http_ini_t *http_abort_start(http_ini_t *ctx, const char *fmt, ...) {
	va_list ap;
	char buf[Kb(8)];

	if (ctx == NULL) return NULL;

	if (fmt != NULL) {
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);
		buf[sizeof(buf) - 1] = 0;
		http_logger(DEBUG_CRASH, NULL, "%s: %s", __func__, buf);
	}

	http_free_context(ctx);
	return NULL;
}

http_ini_t *http_start(const struct lh_clb_t *callbacks, void *user_data, const struct lh_opt_t *options) {
	http_ini_t *ctx;
	uint64_t nonce;
	int i;
	void (*exit_callback)(http_ini_t * ctx);

	/*
	 * No memory for the ctx structure is the only error which we
	 * don't log through httplib_cry() for the simple reason that we do not
	 * have enough configured yet to make that function working. Having an
	 * OOM in this state of the process though should be noticed by the
	 * calling process in other parts of their execution anyway.
	 */
	exit_callback = NULL;
	ctx = calloc(1, sizeof(http_ini_t));
	if (is_empty(ctx))
		return NULL;

	/*
	 * Setup callback functions very early. This is necessary to make the
	 * log_message() callback function available in case an error occurs.
	 *
	 * We first set the exit_context() callback to NULL becasue no proper
	 * context is available yet and we do not want to mess up things if the
	 * function exits and that callback is given a half-decent structure to
	 * work on and without a call to init_context() before.
	 */
	if (!is_empty(callbacks)) {
		ctx->callbacks = *callbacks;
		exit_callback = callbacks->exit_context;
		ctx->callbacks.exit_context = NULL;
	}

	/*
	 * Random number generator will initialize at the first call
	 */
	if (!http_get_random(nonce))
		return http_abort_start(ctx, "Cannot initialize random number generator");

	ctx->auth_nonce_mask = nonce ^ (uint64_t)(ptrdiff_t)(options);
#if defined(_WIN32)
	InitializeCriticalSection(&global_log_file_lock);
#endif  /* _WIN32 */

	atomic_flag_clear(&ctx->nonce_mutex);
	ctx->user_data = user_data;
	ctx->handlers = NULL;
	if (http_init_options(ctx))
		return NULL;

	if (http_process_options(ctx, options))
		return NULL;

	struct utsname name;
	memset(&name, 0, sizeof(name));
	uname(&name);
	ctx->systemName = str_dup_ex(name.sysname);

	/*
	 * NOTE(lsm): order is important here. SSL certificates must
	 * be initialized before listening ports. UID must be set last.
	 */
	if (!http_set_gpass_option(ctx))
		return http_abort_start(ctx, "Error setting gpass option");

	if (!http_set_ssl_option(ctx))
		return http_abort_start(ctx, "Error setting SSL option");

	if (!http_set_ports_option(ctx))
		return http_abort_start(ctx, "Error setting ports option");

	if (!http_set_uid_option(ctx))
		return http_abort_start(ctx, "Error setting UID option");

	if (!http_set_acl_option(ctx))
		return http_abort_start(ctx, "Error setting ACL option");

	/*
	 * Context has been created - init user libraries
	 *
	 * Context has been properly setup. It is now safe to use exit_context
	 * in case the system needs a shutdown.
	 */
	if (ctx->callbacks.init_context != NULL) ctx->callbacks.init_context(ctx);

	ctx->callbacks.exit_context = exit_callback;
	ctx->http_type = HTTP_TYPE_SERVER;

	if (!events_init(1024)) {
		events_t *loop = events_thread_init();
		async_task(httpie_main, 0);
		if (!is_empty(loop)) {
			async_run(loop);
			events_destroy(loop);
			return null;
		}
	}

	return http_abort_start(ctx, "Error setting `events_init()`");
}

static void *httpie_main(param_t args) {
	return 0;
}
