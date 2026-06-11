#include "../httpi_internal.h"

static void qjs_fatal_handler(JSContext *ctx, int code, string_t msg) {
	/* Script is called "protected" (duk_peval_file), so script errors should
	 * never yield in a call to this function. Maybe calls prior to executing
	 * the script could raise a fatal error. */

	http_t *conn = (http_t *)JS_GetContextOpaque(ctx);
	http_log(DEBUG_ERROR, conn, "JavaScript fatal (%u): %s", (unsigned)code, msg);
}

static JSValue qjs_write(JSContext *ctx, JSValue this_val,
	int argc, JSValue *argv) {
	size_t n;
	int res;
	string_t buf;
	http_t *conn = (http_t *)JS_GetContextOpaque(ctx);

	if (!conn) {
		http_log(DEBUG_ERROR, conn, "function not available without context object");
		return JS_EXCEPTION;
	}

	if (argc != 2)
		return JS_ThrowReferenceError(ctx, "[QuickJS] Wrong number of arguments for `qjs_write` launching");

	if (!JS_IsString(argv[0]))
		return JS_ThrowReferenceError(ctx, "[QuickJS] buf is not a string");

	if (!JS_IsNumber(argv[1]))
		return JS_ThrowTypeError(ctx, "[QuickJS] len is not a number");

	if (JS_ToBigUint64(ctx, (uint64_t *)&n, argv[1]))
		return JS_EXCEPTION;

	if (!(buf = JS_ToCString(ctx, argv[0])))
		return JS_EXCEPTION;

	res = http_write(conn, (const_t)buf, n);
	JS_FreeCString(ctx, buf);
	return JS_NewInt32(ctx, res);
}

static JSValue qjs_read(JSContext *ctx, JSValue this_val,
	int argc, JSValue *argv) {
	size_t n, buf_len;
	int res;
	http_t *conn = (http_t *)JS_GetContextOpaque(ctx);

	if (!conn) {
		http_log(DEBUG_ERROR, conn, "function not available without context object");
		return JS_EXCEPTION;
	}

	if (argc != 2)
		return JS_ThrowReferenceError(ctx, "[QuickJS] Wrong number of arguments for `qjs_read` launching");

	if (!JS_IsArray(argv[0]))
		return JS_ThrowReferenceError(ctx, "[QuickJS] buf is not a Uint8Array or ArrayBuffer");

	if (!JS_IsNumber(argv[1]))
		return JS_ThrowTypeError(ctx, "[QuickJS] len is not a number");

	if (JS_ToBigUint64(ctx, (uint64_t *)&n, argv[1]))
		return JS_EXCEPTION;

	uint8_t *buf = JS_GetUint8Array(ctx, &buf_len, argv[0]);
	if (!buf)
		return JS_EXCEPTION;

	res = http_read(conn, (void_t)buf, (n > buf_len ? buf_len : n));
	return JS_NewInt32(ctx, res);
}

static JSValue qjs_getoption(JSContext *ctx, JSValue this_val,
	int argc, JSValue *argv) {
	size_t len;
	string_t val, ret;
	JSValue result = JS_UNDEFINED;
	int optidx;
	http_t *conn = (http_t *)JS_GetContextOpaque(ctx);

	if (!conn) {
		http_log(DEBUG_ERROR, conn, "function not available without context object");
		return JS_EXCEPTION;
	}

	if (argc != 1)
		return JS_ThrowReferenceError(ctx, "[QuickJS] Wrong number of arguments for `qjs_getoption` launching");

	if (!JS_IsString(argv[0]))
		return JS_ThrowReferenceError(ctx, "[QuickJS] name is not a string");

	if (!(val = JS_ToCString(ctx, argv[0])))
		return JS_EXCEPTION;

	ret = NULL;
	optidx = http_get_option_index(val);
	if (optidx >= 0) {
		ret = conn->domain->config[optidx];
	}

	if (ret) {
		result = JS_NewString(ctx, ret);
	}

	return result;
}

static FORCEINLINE void qjs_add_http_headers(JSContext *ctx, JSValue this_obj, http_t *conn) {
	int i, counter = 0, count = (int)hash_count(conn->headers), cap = (int)hash_capacity(conn->headers);
	hash_pair_t *pair;
	if (cap > 0 && count > 0) {
		for (i = 0; i < cap; i++) {
			pair = hash_buckets(conn->headers, i);
			if (!hash_pair_is_null(pair)) {
				string_t key = hash_pair_key(pair);
				string_t value = hash_pair_value(pair).const_char_ptr;
				JS_DefinePropertyValueStr(ctx, this_obj, key, JS_NewString(ctx, value), JS_PROP_C_W_E);
				if (++counter == count)
					break;
			}
		}
	}
}

static FORCEINLINE void *my_malloc(void *opaque, size_t size) {
	return malloc(size);
}

static FORCEINLINE void my_free(void *opaque, void *ptr) {
	_free(ptr);
}

static FORCEINLINE void *my_realloc(void *opaque, void *ptr, size_t size) {
	return realloc(ptr, size);
}

static FORCEINLINE void *my_calloc(void *opaque, size_t count, size_t size) {
	return calloc(count, size);
}

static FORCEINLINE size_t my_malloc_usable_size(const void *ptr) {
	return malloc_usable_size((void_t)ptr); // Platform-specific implementation needed
}

void qjs_exec_script(http_t *conn, string_t script_name) {
	int i;
	JSContext *ctx = NULL;
	JSMallocFunctions mf = {
			.js_calloc = my_calloc,
			.js_malloc = my_malloc,
			.js_free = my_free,
			.js_realloc = my_realloc,
			.js_malloc_usable_size = my_malloc_usable_size
	};

	JSValue r_func = JS_UNDEFINED;
	JSValue o_func = JS_UNDEFINED;
	JSValue w_func = JS_UNDEFINED;
	JSValue wro_obj = JS_UNDEFINED;
	JSValue gl = JS_UNDEFINED;
	JSValue result = JS_UNDEFINED;
	JSValue httpObject = JS_UNDEFINED;
	JSValue headersObject = JS_UNDEFINED;

	conn->req.must_close = 1;

	/* Create QuickJS interpreter state */
	JSRuntime *runtime = JS_NewRuntime2(&mf, null);
	if (!runtime) {
		http_log(DEBUG_ERROR, conn, "%s", "Failed to create QuickJS runtime.");
		goto exec_quickjs_finished;
	}

	js_std_init_handlers(runtime);
	JS_SetModuleLoaderFunc(runtime, null, (JSModuleLoaderFunc *)&js_module_loader, null);

	ctx = JS_NewContext(runtime);
	if (!ctx) {
		http_log(DEBUG_ERROR, conn, "%s", "Failed to create QuickJS context.");
		goto exec_quickjs_finished;
	}

	js_init_module_std(ctx, "std");
	js_init_module_os(ctx, "os");
	js_std_add_helpers(ctx, 0, 0);

	/* Add `http_t` instance */
	JS_SetContextOpaque(ctx, conn);
	gl = JS_GetGlobalObject(ctx);
	wro_obj = JS_NewObject(ctx);

	/* add function http.write */
	w_func = JS_NewCFunction(ctx, qjs_write, "write", 2);
	/* add function http.read */
	r_func = JS_NewCFunction(ctx, qjs_read, "read", 2);
	/* add function http.get_option */
	o_func = JS_NewCFunction(ctx, qjs_getoption, "options", 1);

	if (JS_IsException(wro_obj) || JS_IsException(w_func)
		|| JS_IsException(r_func) || JS_IsException(o_func)) {
		goto exec_quickjs_finished;
	}

	if (JS_SetPropertyStr(ctx, wro_obj, "write", w_func) < 0) {
		w_func = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	w_func = JS_UNDEFINED;

	if (JS_SetPropertyStr(ctx, wro_obj, "read", r_func) < 0) {
		r_func = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	r_func = JS_UNDEFINED;

	if (JS_SetPropertyStr(ctx, wro_obj, "options", o_func) < 0) {
		o_func = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	o_func = JS_UNDEFINED;

	if (JS_SetPropertyStr(ctx, gl, "http", wro_obj) < 0) {
		wro_obj = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	wro_obj = JS_UNDEFINED;

	/* add request data (url, method, headers, ...) */
	httpObject = JS_NewObject(ctx);
	JS_DefinePropertyValueStr(ctx, httpObject, "request_method",
		JS_NewString(ctx, conn->method), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "request_uri",
		JS_NewString(ctx, conn->url_to), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "uri",
		JS_NewString(ctx, conn->req.local_uri), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "http_version",
		JS_NewString(ctx, conn->req.http_version), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "query_string",
		JS_NewString(ctx, conn->req.query_string), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "remote_addr",
		JS_NewString(ctx, conn->req.remote_addr), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "remote_port",
		JS_NewString(ctx, str_itoa(conn->req.remote_port)), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "server_port",
		JS_NewString(ctx, str_itoa(conn->req.server_port)), JS_PROP_C_W_E);
	JS_DefinePropertyValueStr(ctx, httpObject, "script_name",
		JS_NewString(ctx, script_name), JS_PROP_C_W_E);

	/* add system name */
	if (conn->ctx->systemName != NULL) {
		JS_DefinePropertyValueStr(ctx, httpObject, "system",
			JS_NewString(ctx, conn->ctx->systemName), JS_PROP_C_W_E);
	}

	headersObject = JS_NewObject(ctx);
	/* add all the headers */
	qjs_add_http_headers(ctx, headersObject, conn);
	if (JS_SetPropertyStr(ctx, httpObject, "headers", headersObject) < 0) {
		headersObject = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	headersObject = JS_UNDEFINED;

	if (JS_SetPropertyStr(ctx, gl, "http", httpObject) < 0) {
		httpObject = JS_UNDEFINED;
		goto exec_quickjs_finished;
	}
	httpObject = JS_UNDEFINED;

	string_t file = fs_readfile(script_name);
	if (!is_empty(file)) {
		result = JS_Eval(ctx, file, strlen(file),
			"<input>", JS_EVAL_TYPE_MODULE | JS_EVAL_TYPE_GLOBAL);
		int r = js_std_loop(ctx);
		if (JS_IsException(result) || r) {
			js_std_dump_error(ctx);
		}
	}

exec_quickjs_finished:
	JS_FreeValue(ctx, result);
	JS_FreeValue(ctx, r_func);
	JS_FreeValue(ctx, w_func);
	JS_FreeValue(ctx, o_func);
	JS_FreeValue(ctx, wro_obj);
	JS_FreeValue(ctx, httpObject);
	JS_FreeValue(ctx, gl);
	JS_FreeContext(ctx);
	js_std_free_handlers(runtime);
	JS_FreeRuntime(runtime);
}
