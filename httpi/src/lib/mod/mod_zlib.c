/* Experimental implementation for on-the-fly compression */
#include "../httpi_internal.h"

#if !defined(MEM_LEVEL)
#define MEM_LEVEL (8)
#endif

static void *zalloc(void *opaque, uInt items, uInt size) {
	http_t *conn = (http_t *)opaque;
	void *ret = calloc(items, size);
	(void)conn; /* macro might not need it */

	return ret;
}

static void zfree(void *opaque, void *address) {
	http_t *conn = (http_t *)opaque;
	(void)conn; /* not required */

	free(address);
}

void http_compressed_data(http_t *conn, struct file *filep) {
	int zret;
	z_stream zstream;
	int do_flush;
	unsigned bytes_avail;
	unsigned char in_buf[Kb(8)];
	unsigned char out_buf[Kb(8)];
	FILE *in_file = filep->fp;

	/* Prepare state buffer. User server context memory allocation. */
	memset(&zstream, 0, sizeof(zstream));
	zstream.zalloc = zalloc;
	zstream.zfree = zfree;
	zstream.opaque = (void *)conn;

	/* Initialize for GZIP compression (MAX_WBITS | 16) */
	zret = deflateInit2(&zstream,
		Z_BEST_COMPRESSION,
		Z_DEFLATED,
		MAX_WBITS | 16,
		MEM_LEVEL,
		Z_DEFAULT_STRATEGY);

	if (zret != Z_OK) {
		http_log(DEBUG_ERROR, conn,
			"GZIP init failed (%i): %s",
			zret,
			(zstream.msg ? zstream.msg : "<no error message>"));
		deflateEnd(&zstream);
		return;
	}

	/* Read until end of file */
	do {
		zstream.avail_in = fs_fread(in_buf, 1, Kb(8), in_file);
		if (ferror(in_file)) {
			http_log(DEBUG_ERROR, conn, "fread failed: %s", ex_strerror(os_geterror()));
			(void)deflateEnd(&zstream);
			return;
		}

		do_flush = (feof(in_file) ? Z_FINISH : Z_NO_FLUSH);
		zstream.next_in = in_buf;

		/* run deflate() on input until output buffer not full, finish
		 * compression if all of source has been read in */
		do {
			zstream.avail_out = Kb(8);
			zstream.next_out = out_buf;
			zret = deflate(&zstream, do_flush);

			if (zret == Z_STREAM_ERROR) {
				/* deflate error */
				zret = -97;
				break;
			}

			bytes_avail = Kb(8) - zstream.avail_out;
			if (bytes_avail) {
				if (http_chunk(conn, (char *)out_buf, bytes_avail) < 0) {
					zret = -98;
					break;
				}
			}
		} while (zstream.avail_out == 0);

		if (zret < -90) {
			/* Forward write error */
			break;
		}

		if (zstream.avail_in != 0) {
			/* all input will be used, otherwise GZIP is incomplete */
			zret = -99;
			break;
		}

		/* done when last data in file processed */
	} while (do_flush != Z_FINISH);

	if (zret != Z_STREAM_END) {
		/* Error: We did not compress everything. */
		http_log(DEBUG_ERROR, conn,
			"GZIP incomplete (%i): %s",
			zret,
			(zstream.msg ? zstream.msg : "<no error message>"));
	}

	deflateEnd(&zstream);

	/* Send "end of chunked data" marker */
	http_write(conn, "0\r\n\r\n", 5);
}

int http_websocket_deflate_init(http_t *conn, int server) {
	int zret =
		deflateInit2(&conn->req.websocket_deflate_state,
			Z_BEST_COMPRESSION,
			Z_DEFLATED,
			server
			? -1 * conn->req.websocket_deflate_server_max_windows_bits
			: -1 * conn->req.websocket_deflate_client_max_windows_bits,
			MEM_LEVEL,
			Z_DEFAULT_STRATEGY);
	if (zret != Z_OK) {
		http_log(DEBUG_ERROR, conn,
			"Websocket deflate init failed (%i): %s",
			zret,
			(conn->req.websocket_deflate_state.msg
				? conn->req.websocket_deflate_state.msg
				: "<no error message>"));
		deflateEnd(&conn->req.websocket_deflate_state);
		return zret;
	}

	zret = inflateInit2(
		&conn->req.websocket_inflate_state,
		server ? -1 * conn->req.websocket_deflate_client_max_windows_bits
		: -1 * conn->req.websocket_deflate_server_max_windows_bits);
	if (zret != Z_OK) {
		http_log(DEBUG_ERROR, conn,
			"Websocket inflate init failed (%i): %s",
			zret,
			(conn->req.websocket_inflate_state.msg
				? conn->req.websocket_inflate_state.msg
				: "<no error message>"));
		inflateEnd(&conn->req.websocket_inflate_state);
		return zret;
	}
	if ((conn->req.websocket_deflate_server_no_context_takeover && server)
		|| (conn->req.websocket_deflate_client_no_context_takeover && !server))
		conn->req.websocket_deflate_flush = Z_FULL_FLUSH;
	else
		conn->req.websocket_deflate_flush = Z_SYNC_FLUSH;

	conn->req.websocket_deflate_initialized = 1;
	return Z_OK;
}

void http_websocket_deflate_negotiate(http_t *conn) {
	string_t extensions = (string_t)hash_get(conn->headers, "Sec-WebSocket-Extensions");
	int val;
	if (extensions && str_has(extensions, "permessage-deflate")) {
		conn->req.accept_gzip = 1;
		conn->req.websocket_deflate_client_max_windows_bits = 15;
		conn->req.websocket_deflate_server_max_windows_bits = 15;
		conn->req.websocket_deflate_server_no_context_takeover = 0;
		conn->req.websocket_deflate_client_no_context_takeover = 0;
		extensions += 18;
		while (*extensions != '\0') {
			if (*extensions == ';' || *extensions == ' ')
				++extensions;
			else if (str_has(extensions, "server_no_context_takeover")) {
				extensions += 26;
				conn->req.websocket_deflate_server_no_context_takeover = 1;
			} else if (str_has(extensions, "client_no_context_takeover")) {
				extensions += 26;
				conn->req.websocket_deflate_client_no_context_takeover = 1;
			} else if (str_has(extensions, "server_max_window_bits")) {
				extensions += 22;
				if (*extensions == '=') {
					++extensions;
					if (*extensions == '"')
						++extensions;
					val = 0;
					while (*extensions >= '0' && *extensions <= '9') {
						val = val * 10 + (*extensions - '0');
						++extensions;
					}
					if (val < 9 || val > 15) {
						// The permessage-deflate spec specifies that a
						// value of 8 is also allowed, but zlib doesn't accept
						// that.
						http_log(DEBUG_ERROR, conn,
							"server-max-window-bits must be "
							"between 9 and 15. Got %i",
							val);
					} else
						conn->req.websocket_deflate_server_max_windows_bits = val;
					if (*extensions == '"')
						++extensions;
				}
			} else if (str_has(extensions, "client_max_window_bits")) {
				extensions += 22;
				if (*extensions == '=') {
					++extensions;
					if (*extensions == '"')
						++extensions;
					val = 0;
					while (*extensions >= '0' && *extensions <= '9') {
						val = val * 10 + (*extensions - '0');
						++extensions;
					}
					if (val < 9 || val > 15)
						// The permessage-deflate spec specifies that a
						// value of 8 is also allowed, but zlib doesn't
						// accept that.
						http_log(DEBUG_ERROR, conn,
							"client-max-window-bits must be "
							"between 9 and 15. Got %i",
							val);
					else
						conn->req.websocket_deflate_client_max_windows_bits = val;
					if (*extensions == '"')
						++extensions;
				}
			} else {
				http_log(DEBUG_ERROR, conn,
					"Unknown parameter %s for permessage-deflate",
					extensions);
				break;
			}
		}
	} else {
		conn->req.accept_gzip = 0;
	}
	conn->req.websocket_deflate_initialized = 0;
}

void http_websocket_deflate_response(http_t *conn) {
	if (conn->req.accept_gzip) {
		http_printf(conn,
			"Sec-WebSocket-Extensions: permessage-deflate; "
			"server_max_window_bits=%i; "
			"client_max_window_bits=%i"
			"%s%s\r\n",
			conn->req.websocket_deflate_server_max_windows_bits,
			conn->req.websocket_deflate_client_max_windows_bits,
			conn->req.websocket_deflate_client_no_context_takeover
			? "; client_no_context_takeover"
			: "",
			conn->req.websocket_deflate_server_no_context_takeover
			? "; server_no_context_takeover"
			: "");
	};
}
