#include "httpie_internal.h"

#if !defined(MAX_UNANSWERED_PING)
/* Configuration of the maximum number of websocket PINGs that might
 * stay unanswered before the connection is considered broken.
 * Note: The name of this define may still change (until it is
 * defined as a compile parameter in a documentation). */
#define MAX_UNANSWERED_PING (5)
#endif

/**
 * Checks the request headers to see if the connection is a valid websocket protocol.
 * A websocket protocol has the following HTTP headers:
 *
 * Connection: Upgrade
 * Upgrade: Websocket */
FORCEINLINE bool http_is_websocket(http_t *conn) {
	const char *upgrade;
	const char *connection;

	if (str_is_case((upgrade = http_get_header(conn, "Upgrade")), "websocket")
		&& str_is_case((connection = http_get_header(conn, "Connection")), "upgrade")) {
		/*
		* The headers "Host", "Sec-WebSocket-Key", "Sec-WebSocket-Protocol" and
		* "Sec-WebSocket-Version" are also required.
		* Don't check them here, since even an unsupported websocket protocol
		* request still IS a websocket request (in contrast to a standard HTTP
		* request). It will fail later in handle_websocket_request. */
		return true;
	}

	return false;
}

static int http_base64_encode(const unsigned char *src,
	size_t src_len,
	char *dst,
	size_t *dst_len) {
	static const char *b64 =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, j;
	int a, b, c;

	if (dst_len != NULL) {
		/* Expected length including 0 termination: */
		/* IN 1 -> OUT 5, IN 2 -> OUT 5, IN 3 -> OUT 5, IN 4 -> OUT 9,
		 * IN 5 -> OUT 9, IN 6 -> OUT 9, IN 7 -> OUT 13, etc. */
		size_t expected_len = ((src_len + 2) / 3) * 4 + 1;
		if (*dst_len < expected_len) {
			if (*dst_len > 0) {
				dst[0] = '\0';
			}
			*dst_len = expected_len;
			return 0;
		}
	}

	for (i = j = 0; i < src_len; i += 3) {
		a = src[i];
		b = ((i + 1) >= src_len) ? 0 : src[i + 1];
		c = ((i + 2) >= src_len) ? 0 : src[i + 2];

		dst[j++] = b64[a >> 2];
		dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
		if (i + 1 < src_len) {
			dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
		}
		if (i + 2 < src_len) {
			dst[j++] = b64[c & 63];
		}
	}

	while (j % 4 != 0) {
		dst[j++] = '=';
	}
	dst[j++] = '\0';

	if (dst_len != NULL) {
		*dst_len = (size_t)j;
	}

	/* Return -1 for "OK" */
	return -1;
}

static int http_send_websocket_handshake(http_t *conn, const char *websock_key) {
	static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	char buf[100], sha[20], b64_sha[sizeof(sha) * 2];
	size_t dst_len = sizeof(b64_sha);
#if !defined(OPENSSL_API_3_0)
	SHA_CTX sha_ctx;
#endif
	bool truncated;

	/* Calculate Sec-WebSocket-Accept reply from Sec-WebSocket-Key. */
	http_snprintf(conn, &truncated, buf, sizeof(buf), "%s%s", websock_key, magic);
	if (truncated) {
		conn->req.must_close = 1;
		return 0;
	}

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, (unsigned char *)buf, (uint32_t)strlen(buf));
	SHA1_Final((unsigned char *)sha, &sha_ctx);

	http_base64_encode((unsigned char *)sha, sizeof(sha), b64_sha, &dst_len);
	http_printf(conn,
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n",
		b64_sha);

	// Send negotiated compression extension parameters
	http_websocket_deflate_send(conn);

	if (conn->req.acceptedWebSocketSubprotocol) {
		http_printf(conn,
			"Sec-WebSocket-Protocol: %s\r\n\r\n",
			conn->req.acceptedWebSocketSubprotocol);
	} else {
		http_printf(conn, "%s", "\r\n");
	}

	return 1;
}

/* Reads from a websocket connection. */
void http_read_websocket(http_ini_t *ctx, http_t *conn, ws_data_cb ws_data_handler, void *callback_data) {
	/* Pointer to the beginning of the portion of the incoming websocket
	 * message queue.
	 * The original websocket upgrade request is never removed, so the queue
	 * begins after it. */
	unsigned char *buf = (unsigned char *)conn->req.buf + conn->req.request_len;
	int n, error, exit_by_callback, ret, ping_count = 0, enable_ping_pong = 0;

	/*
	 * body_len is the length of the entire queue in bytes
	 * len is the length of the current message
	 * data_len is the length of the current message's data payload
	 * header_len is the length of the current message's header */
	size_t i, len, mask_len = 0, data_len = 0, header_len, body_len;

	/* "The masking key is a 32-bit value chosen at random by the client."
	 * http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5 */
	unsigned char mask[4];

	/* data points to the place where the message is stored when passed to
	 * the websocket_data callback.  This is either mem on the stack, or a
	 * dynamically allocated buffer if it is too large. */
	char mem[4096];
	char *data;
	/* mask flag and opcode */
	unsigned char mop;
	/* Variables used for connection monitoring */
	double timeout = -1.0;

	if (ctx == NULL || conn == NULL) return;

	if (conn->ctx->host.config[ENABLE_WEBSOCKET_PING_PONG]) {
		enable_ping_pong = str_is_cast(conn->ctx->host.config[ENABLE_WEBSOCKET_PING_PONG], "yes");
	}

	data = mem;
	if (conn->ctx->host.config[WEBSOCKET_TIMEOUT]) {
		timeout = (double)atoi(conn->ctx->host.config[WEBSOCKET_TIMEOUT]) / 1000.0;
	}

	if ((timeout <= 0.0) && (conn->ctx->host.config[REQUEST_TIMEOUT])) {
		timeout = atoi(conn->ctx->host.config[REQUEST_TIMEOUT]) / 1000.0;
	}

	task_name("websocket #%d", task_id());

	/* Loop continuously, reading messages from the socket, invoking the
	 * callback, and waiting repeatedly until an error occurs. */
	while (ctx->status == HTTP_STATUS_RUNNING) {
		header_len = 0;
		if (conn->req.data_len < conn->req.request_len) {
			http_logger(DEBUG_ERROR, conn, "%s: websocket error: data len less than request len, closing connection", __func__);
			break;
		}

		body_len = (size_t)(conn->req.data_len - conn->req.request_len);
		if (body_len >= 2) {
			len = buf[1] & 127;
			mask_len = (buf[1] & 128) ? 4 : 0;
			if (len < 126 && body_len >= mask_len) {
				data_len = len;
				header_len = 2 + mask_len;
			} else if (len == 126 && body_len >= mask_len + 4) {
				header_len = mask_len + 4;
				data_len = (((size_t)buf[2]) << 8) + buf[3];
			} else if (body_len >= 10 + mask_len + 10) {
				header_len = mask_len + 10;
				data_len = (((uint64_t)ntohl(*(uint32_t *)(void *)&buf[2])) << 32) + ntohl(*(uint32_t *)(void *)&buf[6]);
			}
		}

		if (header_len > 0 && body_len >= header_len) {
			/* Allocate space to hold websocket payload */
			data = mem;
			if (data_len > sizeof(mem)) {
				data = malloc(data_len);
				if (data == NULL) {
					/* Allocation failed, exit the loop and then close the connection */
					http_logger(DEBUG_ERROR, conn, "%s: websocket out of memory; closing connection", __func__);
					break;
				}
			}

			/* Copy the mask before we shift the queue and destroy it */
			if (mask_len > 0)
				memcpy(mask, buf + header_len - mask_len, sizeof(mask));
			else
				memset(mask, 0, sizeof(mask));

			/* Read frame payload from the first message in the queue into
			 * data and advance the queue by moving the memory in place. */
			if (body_len < header_len) {
				http_logger(DEBUG_ERROR, conn, "%s: websocket error: body len less than header len, closing connection", __func__);
				break;
			}

			if (data_len + header_len > body_len) {
				 /* current mask and opcode */
				mop = buf[0];

				/* Overflow case */
				len = body_len - header_len;
				memcpy(data, buf + header_len, len);
				error = 0;
				while (len < data_len) {
					n = tls_reader(conn->fd, data + len, (int)(data_len - len));
					if (n <= 0) {
						error = 1;
						break;
					}

					len += (size_t)n;
				}

				if (error) {
					http_logger(DEBUG_ERROR, conn, "%s: websocket pull failed; closing connection", __func__);
					break;
				}
				conn->req.data_len = conn->req.request_len;
			} else {
				/* current mask and opcode, overwritten by memmove() */
				mop = buf[0];

				/* Length of the message being read at the front of the queue */
				len = data_len + header_len;

				/* Copy the data payload into the data pointer for the callback */
				memcpy(data, buf + header_len, data_len);

				/* Move the queue forward len bytes */
				memmove(buf, buf + len, body_len - len);

				/* Mark the queue as advanced */
				conn->req.data_len -= (int)len;
			}

			/* Apply mask if necessary */
			if (mask_len > 0)
				for (i = 0; i < data_len; i++)
					data[i] ^= mask[i % 4];

			/*
			 * Exit the loop if callback signals to exit (server side),
			 * or "connection close" opcode received (client side). */
			exit_by_callback = 0;
			if (enable_ping_pong && ((mop & 0xF) == WS_OPS_PONG)) {
				/* filter PONG messages */
				/* No unanswered PINGs left */
				ping_count = 0;
			} else if (enable_ping_pong
				&& ((mop & 0xF) == WS_OPS_PING)) {
		 		/* reply PING messages */
					ret = http_websocket_write(conn,
					WS_OPS_PONG,
					(char *)data,
					(size_t)data_len);
				if (ret <= 0) {
					/* Error: send failed */
					http_logger(DEBUG_WARNING, null, "Reply PONG failed (%i)", ret);
					break;
				}

			} else {
				/* Exit the loop if callback signals to exit (server side),
				 * or "connection close" opcode received (client side). */
				if (ws_data_handler != NULL) {
					if (mop & 0x40) {
						/* Inflate the data received if bit RSV1 is set. */
						if (!conn->req.websocket_deflate_initialized) {
							if (http_websocket_deflate_init(conn, 1) != Z_OK)
								exit_by_callback = 1;
						}
						if (!exit_by_callback) {
							size_t inflate_buf_size_old = 0;
							size_t inflate_buf_size =
								data_len
								* 4; // Initial guess of the inflated message
									 // size. We double the memory when needed.
							Bytef *inflated = NULL;
							Bytef *new_mem = NULL;
							conn->req.websocket_inflate_state.avail_in =
								(uInt)(data_len + 4);
							conn->req.websocket_inflate_state.next_in = data;
							// Add trailing 0x00 0x00 0xff 0xff bytes
							data[data_len] = '\x00';
							data[data_len + 1] = '\x00';
							data[data_len + 2] = '\xff';
							data[data_len + 3] = '\xff';
							do {
								if (inflate_buf_size_old == 0) {
									new_mem =
										(Bytef *)calloc(inflate_buf_size,
											sizeof(Bytef));
								} else {
									inflate_buf_size *= 2;
									new_mem =
										(Bytef *)realloc(inflated,
											inflate_buf_size);
								}
								if (new_mem == NULL) {
									http_logger(DEBUG_CRASH,
										conn,
										"Out of memory: Cannot allocate "
										"inflate buffer of %lu bytes",
										(unsigned long)inflate_buf_size);
									exit_by_callback = 1;
									break;
								}
								inflated = new_mem;
								conn->req.websocket_inflate_state.avail_out =
									(uInt)(inflate_buf_size
										- inflate_buf_size_old);
								conn->req.websocket_inflate_state.next_out =
									inflated + inflate_buf_size_old;
								ret = inflate(&conn->req.websocket_inflate_state,
									Z_SYNC_FLUSH);
								if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR
									|| ret == Z_MEM_ERROR) {
									http_logger(DEBUG_CRASH,
										conn,
										"ZLIB inflate error: %i %s",
										ret,
										(conn->req.websocket_inflate_state.msg
											? conn->req.websocket_inflate_state.msg
											: "<no error message>"));
									exit_by_callback = 1;
									break;
								}
								inflate_buf_size_old = inflate_buf_size;

							} while (conn->req.websocket_inflate_state.avail_out
								== 0);
							inflate_buf_size -=
								conn->req.websocket_inflate_state.avail_out;
							if (!ws_data_handler(conn,
								mop,
								(char *)inflated,
								inflate_buf_size,
								callback_data)) {
								exit_by_callback = 1;
							}
							free(inflated);
						}
					} else
						if (!ws_data_handler(conn,
							mop,
							(char *)data,
							(size_t)data_len,
							callback_data)) {
							exit_by_callback = 1;
						}
				}
			}

			/* It a buffer has been allocated, free it again */
			if (data != mem) {
				data = http_free_ex(data);
			}

			if (exit_by_callback) {
				break;
			}

			if ((mop & 0xf) == WS_OPS_CLOSE) {
				/* Opcode == 8, connection close */
				break;
			}

			/* Not breaking the loop, process next websocket frame. */
		} else {
			/* Read from the socket into the next available location in the
			 * message queue. */
			n = tls_reader(conn->fd, conn->req.buf + conn->req.data_len, conn->req.buf_size - conn->req.data_len);
			if (n <= -2) {
				/* Error, no bytes read */
				http_logger(DEBUG_WARNING, null, "PULL from %s:%u failed",
					conn->req.remote_addr,
					conn->req.remote_port);
				break;
			}

			if (n > 0) {
				conn->req.data_len += n;
				/* Reset open PING count */
				ping_count = 0;
			} else {
				if (ctx->status == HTTP_STATUS_RUNNING 	&& (!conn->req.must_close)) {
					if (ping_count > MAX_UNANSWERED_PING) {
						/* Stop sending PING */
						http_logger(DEBUG_WARNING, null, "Too many (%i) unanswered ping from %s:%u "
							"- closing connection",
							ping_count,
							conn->req.remote_addr,
							conn->req.remote_port);
						break;
					}

					if (enable_ping_pong) {
						/* Send Websocket PING message */
						ret = http_websocket_write(conn, WS_OPS_PING, NULL,	0);
						if (ret <= 0) {
							/* Error: send failed */
							http_logger(DEBUG_WARNING, null, "Send PING failed (%i)", ret);
							break;
						}
						ping_count++;
					}
				}
				/* Timeout: should retry */
				/* TODO: get timeout def */
			}

			/* Error, no bytes read */
			if (n <= 0)
				break;

			conn->req.data_len += n;
		}
	}

	task_name("webworker #%d", task_id());
}

/* Processes a websocket request on a connection. */
void http_websocket_request(http_ini_t *ctx, http_t *conn, int is_callback_resource, ws_connect_cb ws_connect_handler, ws_ready_cb ws_ready_handler, ws_data_cb ws_data_handler, ws_close_cb ws_close_handler, void *cbData) {
	const char *websock_key;
	const char *version;
	const char *key1;
	const char *key2;
	char key3[8];
	int lua_websock = 0;

	if (is_empty(conn))
		return;

	websock_key = http_get_header(conn, "Sec-WebSocket-Key");
	version = http_get_header(conn, "Sec-WebSocket-Version");

	/*
	 * Step 1: Check websocket protocol version.
	 * Step 1.1: Check Sec-WebSocket-Key. */
	if (is_empty(websock_key)) {
		/*
		 * The RFC standard version (https://tools.ietf.org/html/rfc6455)
		 * requires a Sec-WebSocket-Key header.
		 *
		 * It could be the hixie draft version
		 * (http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76). */
		key1 = http_get_header(conn, "Sec-WebSocket-Key1");
		key2 = http_get_header(conn, "Sec-WebSocket-Key2");

		if (!is_empty(key1) && !is_empty(key2)) {
			/* This version uses 8 byte body data in a GET request */
			conn->req.content_len = 8;
			if (http_read(conn, key3, 8) == 8) {
				/* This is the hixie version */
				http_error(conn, 426, "%s", "Protocol upgrade to RFC 6455 required");
				return;
			}
		}

		/* This is an unknown version */
		http_error(conn, 400, "%s", "Malformed websocket request");
		return;
	}

	/*
	 * Step 1.2: Check websocket protocol version.
	 * The RFC version (https://tools.ietf.org/html/rfc6455) is 13. */
	if (is_empty(version) || !str_is(version, "13")) {
		/* Reject wrong versions */
		http_error(conn, 426, "%s", "Protocol upgrade required");
		return;
	}

	/* Step 1.3: Could check for "Host", but we do not really need this
	 * value for anything, so just ignore it. */

	http_websocket_deflate_negotiate(conn);
	/* Step 2: If a callback is responsible, call it. */
	if (is_callback_resource) {
		if (ws_connect_handler != NULL && ws_connect_handler(conn, cbData) != 0) {
			/*
			 * C callback has returned non-zero, do not proceed with
			 * handshake.
			 *
			 * Note that C callbacks are no longer called when Lua is
			 * responsible, so C can no longer filter callbacks for Lua. */
			return;
		}
	}

	/* Step 4: Check if there is a responsible websocket handler. */
	if (!is_callback_resource && !lua_websock) {
		/*
		 * There is no callback, an Lua is not responsible either. */
		/* Reply with a 404 Not Found or with nothing at all?
		 * TODO (mid): check the websocket standards, how to reply to
		 * requests to invalid websocket addresses. */
		http_error(conn, 404, "%s", "Not found");
		return;
	}

	/* Step 5: The websocket connection has been accepted */
	if (!http_send_websocket_handshake(conn, websock_key)) {
		http_error(conn, 500, "%s", "Websocket handshake failed");
		return;
	}

	/* Step 6: Call the ready handler */
	if (is_callback_resource) {
		if (ws_ready_handler != NULL) ws_ready_handler(conn, cbData);
	}

	/* Step 7: Enter the read loop */
	if (is_callback_resource)
		http_read_websocket(ctx, conn, ws_data_handler, cbData);

	/* Step 8: Close the deflate & inflate buffers */
	if (conn->req.websocket_deflate_initialized) {
		deflateEnd(&conn->req.websocket_deflate_state);
		inflateEnd(&conn->req.websocket_inflate_state);
	}

	/* Step 9: Call the close handler */
	if (ws_close_handler != NULL)
		ws_close_handler(conn, cbData);
}

/* Use to mask data when writing data over a websocket client connection. */
static void mask_data(const char *_in, size_t in_len, uint32_t masking_key, char *out) {
	size_t i = 0;
	if (in_len > 3 && ((ptrdiff_t)_in % 4) == 0) {
		/* Convert in 32 bit words, if data is 4 byte aligned */
		while (i + 3 < in_len) {
			*(uint32_t *)(void *)(out + i) = *(const uint32_t *)(const void *)(_in + i) ^ masking_key;
			i += 4;
		}
	}

	if (i != in_len) {
		/* convert 1-3 remaining bytes if ((dataLen % 4) != 0) */
		while (i < in_len) {
			*(uint8_t *)(void *)(out + i) = *(const uint8_t *)(const void *)(_in + i) ^ *(((uint8_t *)&masking_key) + (i % 4));
			i++;
		}
	}
}

int http_websocket_client_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen) {
	int retval;
	char *masked_data;
	uint32_t masking_key;

	if (conn == NULL) return -1;

	retval = -1;
	masked_data = malloc(((dataLen + 7) / 4) * 4);
	if (masked_data == NULL) {
		http_logger(DEBUG_ERROR, conn, "%s: cannot allocate buffer for masked websocket response: Out of memory", __func__);
		return -1;
	}

	http_get_random((uint64_t*)&masking_key);
	mask_data(data, dataLen, masking_key, masked_data);
	retval = http_websocket_write_exec(conn, opcode, masked_data, dataLen, masking_key);
	free(masked_data);
	masked_data = null;
	return retval;
}

int http_websocket_write_exec(http_t *conn, websocket_type opcode, string_t data, size_t data_len, uint32_t masking_key) {
	unsigned char header[14];
	uint16_t len;
	uint32_t len1, len2;
	size_t header_len = 1, deflated_size = 0;
	Bytef *deflated = 0;
	int use_deflate, retval = -1;

	// Deflate websocket messages over 100kb
	if (use_deflate = (data_len > Kb(100)) && conn->req.accept_gzip) {
		if (!conn->req.websocket_deflate_initialized) {
			if (http_websocket_deflate_init(conn, 1) != Z_OK)
				return 0;
		}

		// Deflating the message
		header[0] = 0xC0u | (unsigned char)((unsigned)opcode & 0xf);
		conn->req.websocket_deflate_state.avail_in = (uInt)data_len;
		conn->req.websocket_deflate_state.next_in = (unsigned char *)data;
		deflated_size = (size_t)compressBound((uLong)data_len);
		deflated = calloc(deflated_size, sizeof(Bytef));
		if (deflated == NULL) {
			http_logger(DEBUG_CRASH, conn,
				"Out of memory: Cannot allocate deflate buffer of %lu bytes",
				(unsigned long)deflated_size);
			return -1;
		}
		conn->req.websocket_deflate_state.avail_out = (uInt)deflated_size;
		conn->req.websocket_deflate_state.next_out = deflated;
		deflate(&conn->req.websocket_deflate_state, conn->req.websocket_deflate_flush);
		data_len = deflated_size - conn->req.websocket_deflate_state.avail_out - 4; // Strip trailing 0x00 0x00 0xff 0xff bytes
	} else
		header[0] = 0x80 + (opcode & 0xF);

	/* Frame format: http://tools.ietf.org/html/rfc6455#section-5.2 */
	if (data_len < 126) {
		/* inline 7-bit length field */
		header[1] = (unsigned char)data_len;
		header_len = 2;
	} else if (data_len <= 65535) {
		/* 16-bit length field */
		len = htons((uint16_t)data_len);
		header[1] = 126;
		header_len = 4;
		memcpy(header + 2, &len, 2);
	} else {
		/* 64-bit length field */
		len1 = htonl((uint64_t)data_len >> 32);
		len2 = htonl(data_len & 0xFFFFFFFF);
		header[1] = 127;
		header_len = 10;
		memcpy(header + 2, &len1, 4);
		memcpy(header + 6, &len2, 4);
	}

	if (masking_key) {
		/* add mask */
		header[1] |= 0x80;
		memcpy(header + header_len, &masking_key, 4);
		header_len += 4;
	}

	retval = tls_writer(conn->fd, header, header_len);
	if (retval != (int)header_len) {
		/* Did not send complete header */
		retval = -1;
	} else {
		if (data_len > 0) {
			if (use_deflate) {
				retval = tls_writer(conn->fd, deflated, data_len);
				free(deflated);
			} else
				retval = tls_writer(conn->fd, (string)data, data_len);
		}
	}

	return retval;
}

FORCEINLINE int http_websocket_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, opcode, data, dataLen, 0);
}

FORCEINLINE int http_websocket_text(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_TEXT, data, dataLen, 0);
}

FORCEINLINE int http_websocket_binary(http_t *conn, const_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_BINARY, (string_t)data, dataLen, 0);
}

FORCEINLINE int http_websocket_close(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_CLOSE, data, dataLen, 0);
}

FORCEINLINE int http_websocket_ping(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_PING, data, dataLen, 0);
}

FORCEINLINE int http_websocket_pong(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_PONG, data, dataLen, 0);
}

FORCEINLINE int http_websocket_continuation(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, WS_OPS_CONTINUATION, data, dataLen, 0);
}