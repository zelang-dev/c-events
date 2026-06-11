#include "httpi_internal.h"

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
	string_t upgrade;
	string_t connection;

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

static int http_send_websocket_handshake(http_t *conn, string_t websock_key) {
	static string_t magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	char buf[100], sha[20], b64_sha[sizeof(sha) * 2];
	size_t dst_len = sizeof(b64_sha);
	SHA_CTX sha_ctx;
	int truncated;

	/* Calculate Sec-WebSocket-Accept reply from Sec-WebSocket-Key. */
	http_snprintf(&truncated, buf, sizeof(buf), "%s%s", websock_key, magic);
	if (truncated) {
		conn->req.must_close = 1;
		return 0;
	}

	debug_info("%s", "Send websocket handshake"CLR_LN);

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, (unsigned char *)buf, (uint32_t)strlen(buf));
	SHA1_Final((unsigned char *)sha, &sha_ctx);

	string sha_data = str_encode64((string_t)sha, b64_sha, dst_len);
	http_printf(conn,
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n",
		sha_data);

	// Send negotiated compression extension parameters
	http_websocket_deflate_response(conn);

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
static void http_read_websocket(http_t *conn, ws_data_cb ws_data_handler, void_t callback_data) {
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
	unsigned char mem[4096];
	/* mask flag and opcode */
	unsigned char mop;
	/* Variables used for connection monitoring */
	double timeout = -1.0;

	if (conn == NULL) return;

	if (conn->domain->config[ENABLE_WEBSOCKET_PING_PONG]) {
		enable_ping_pong = str_is_case(conn->domain->config[ENABLE_WEBSOCKET_PING_PONG], "yes");
	}

	if (conn->domain->config[WEBSOCKET_TIMEOUT]) {
		timeout = (double)atoi(conn->domain->config[WEBSOCKET_TIMEOUT]) / 1000.0;
	}

	if ((timeout <= 0.0) && (conn->domain->config[REQUEST_TIMEOUT])) {
		timeout = atoi(conn->domain->config[REQUEST_TIMEOUT]) / 1000.0;
	}

	/* Enter data processing loop */
	debug_info("Websocket connection %s:%u start data processing loop"CLR_LN,
		conn->req.remote_addr,
		conn->req.remote_port);
	conn->req.in_websocket_handling = 1;
	if (conn->ws.type == (data_types)DATA_WS_SERVER)
		task_name("Websocket server #%d", task_id());

	/* Loop continuously, reading messages from the socket, invoking the
	 * callback, and waiting repeatedly until an error occurs. */
	while (conn->ctx->status == HTTP_STATUS_RUNNING && !conn->req.must_close) {
		header_len = 0;
		if (conn->req.data_len < conn->req.request_len) {
			debug_info("%s: websocket error: data len less than request len, closing connection"CLR_LN, __func__);
			break;
		}

		if ((body_len = (size_t)(conn->req.data_len - conn->req.request_len)) >= 2) {
			len = buf[1] & 127;
			mask_len = (buf[1] & 128) ? 4 : 0;
			if ((len < 126) && (body_len >= mask_len)) {
				/* inline 7-bit length field */
				data_len = len;
				header_len = 2 + mask_len;
			} else if ((len == 126) && (body_len >= (4 + mask_len))) {
				/* 16-bit length field */
				header_len = 4 + mask_len;
				data_len = ((((size_t)buf[2]) << 8) + buf[3]);
			} else if (body_len >= (10 + mask_len)) {
				/* 64-bit length field */
				uint32_t l1, l2;
				memcpy(&l1, &buf[2], 4); /* Use memcpy for alignment */
				memcpy(&l2, &buf[6], 4);
				header_len = 10 + mask_len;
				data_len = (((uint64_t)ntohl(l1)) << 32) + ntohl(l2);
				if (data_len > (uint64_t)0x7FFF0000ul) {
					/* no can do */
					http_log(DEBUG_ERROR, conn, "%s", "websocket out of memory; closing connection");
					break;
				}
			}
		}

		if (header_len > 0 && ( body_len >= header_len)) {
			/* Allocate space to hold websocket payload */
			unsigned char *data = mem;
			size_t required_len = (size_t)data_len + 4;

			if (required_len > sizeof(mem)) {
				data = (unsigned char *)malloc(data_len);
				if (data == NULL) {
					/* Allocation failed, exit the loop and then close the connection */
					http_log(DEBUG_ERROR, conn, "%s: websocket out of memory; closing connection", __func__);
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
				http_log(DEBUG_ERROR, conn, "%s: websocket error: body len less than header len, closing connection", __func__);
				break;
			}
			if (data_len + (uint64_t)header_len > (uint64_t)body_len) {
				mop = buf[0]; /* current mask and opcode */
							  /* Overflow case */
				len = body_len - header_len;
				memcpy(data, buf + header_len, len);
				error = 0;
				while ((uint64_t)len < data_len) {
					n = tls_reader(socket2fd(conn->client->sock), (void_t)(data + len), (data_len - len));
					if (n < 0) {
						error = 1;
						break;
					} else if (n > 0) {
						len += (size_t)n;
					} else {
						/* Timeout: should retry */
						/* TODO: retry condition */
					}
				}

				if (error) {
					http_log(DEBUG_ERROR, conn, "%s: websocket pull failed; closing connection", __func__);
					if (data != mem) {
						free_ex(data);
					}
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
				debug_info("PONG from %s:%u"CLR_LN, conn->req.remote_addr, conn->req.remote_port);
				/* No unanswered PINGs left */
				ping_count = 0;
			} else if (enable_ping_pong
				&& ((mop & 0xF) == WS_OPS_PING)) {
		 			/* reply PING messages */
					debug_info("Reply PING from %s:%u"CLR_LN,	conn->req.remote_addr, conn->req.remote_port);
					ret = http_websocket_write(conn, WS_OPS_PONG, (string_t)data, (size_t)data_len);
				if (ret <= 0) {
					/* Error: send failed */
					debug_info("Reply PONG failed (%i)"CLR_LN, ret);
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
									http_log(DEBUG_CRASH,
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
									http_log(DEBUG_CRASH,
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
								(string)inflated,
								inflate_buf_size,
								callback_data)) {
								exit_by_callback = 1;
							}
							free(inflated);
						}
					} else
						if (!ws_data_handler(conn,
							mop,
							(string)data,
							(size_t)data_len,
							callback_data)) {
							exit_by_callback = 1;
						}
					conn->ws.is_data_ready = true;
				}
			}

			/* It a buffer has been allocated, free it again */
			if (data != mem) {
				data = free_ex(data);
			}

			if (exit_by_callback) {
				debug_info("Callback requests to close connection from %s:%u"CLR_LN,
					conn->req.remote_addr,
					conn->req.remote_port);
				break;
			}

			if ((mop & 0xf) == WS_OPS_CLOSE) {
				/* Opcode == 8, connection close */
				debug_info("Message requests to close connection from %s:%u"CLR_LN,
					conn->req.remote_addr,
					conn->req.remote_port);
				break;
			}

			/* Not breaking the loop, process next websocket frame. */
		} else {
			/* Read from the socket into the next available location in the
			 * message queue. */
			n = tls_reader(socket2fd(conn->client->sock), conn->req.buf + conn->req.data_len, conn->req.buf_size - conn->req.data_len);
			if (n < 0) {
				/* Error, no bytes read */
				debug_info("PULL from %s:%u failed, error: %s"CLR_LN,
					conn->req.remote_addr,
					conn->req.remote_port, (conn->client->has_ssl
						? ERR_reason_error_string(ERR_get_error())
						: ex_strerror(os_geterror())));
				break;
			}

			if (n > 0) {
				conn->req.data_len += n;
				/* Reset open PING count */
				ping_count = 0;
			} else {
				if (conn->ctx->status == HTTP_STATUS_RUNNING && (!conn->req.must_close)) {
					if (ping_count > MAX_UNANSWERED_PING) {
						/* Stop sending PING */
						debug_info("Too many (%i) unanswered ping from %s:%u "
							"- closing connection"CLR_LN,
							ping_count,
							conn->req.remote_addr,
							conn->req.remote_port);
						break;
					}

					if (enable_ping_pong) {
						/* Send Websocket PING message */
						debug_info("PING to %s:%u"CLR_LN,
							conn->req.remote_addr,
							conn->req.remote_port);
						ret = http_websocket_write(conn, WS_OPS_PING, NULL,	0);
						if (ret <= 0) {
							/* Error: send failed */
							debug_info("Send PING failed (%i)"CLR_LN, ret);
							break;
						}
						ping_count++;
					}
				}
				/* Timeout: should retry */
				/* TODO: get timeout def */
			}
		}
		yield_active_info();
	}

	/* Leave data processing loop */
	task_name("webworker #%d", task_id());
	conn->req.in_websocket_handling = 0;
	debug_info("Websocket connection %s:%u left data processing loop"CLR_LN,
	            conn->req.remote_addr,
	            conn->req.remote_port);
}

void http_websocket_request(http_ini_t *ctx,
	http_t *conn,
	int is_callback_resource,
	struct ws_subprotocols_s *subprotocols,
	ws_connect_cb ws_connect_handler,
	ws_ready_cb ws_ready_handler,
	ws_data_cb ws_data_handler,
	ws_close_cb ws_close_handler,
	void_t cbData) {
	string_t websock_key;
	string_t version;
	string_t key1;
	string_t key2;
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

	/* Step 2: If a callback is responsible, call it. */
	if (is_callback_resource) {
		int nbSubprotocolHeader = 0;
		/* Step 2.1 check and select subprotocol */
		string protocol = http_get_header(conn, "Sec-WebSocket-Protocol");
		if (!is_empty(protocol)) {
			conn->req.acceptedWebSocketSubprotocol = protocol;
			string *protocols = str_has(protocol, ",") ? str_split_ex(protocol, ",", &nbSubprotocolHeader) : nullptr;
			if (!is_empty(protocols) && (nbSubprotocolHeader > 0) && subprotocols) {
				int headerNo, idx;
				string_t acceptedWebSocketSubprotocol = NULL;

				/* look for matching subprotocol */
				for (headerNo = 0; headerNo < nbSubprotocolHeader; headerNo++) {
					/* There might be multiple headers ... */
					protocol = protocols[headerNo];
					for (idx = 0; idx < subprotocols->nb_subprotocols; idx++) {
						if (str_is(protocol, subprotocols->subprotocols[idx])) {
							acceptedWebSocketSubprotocol = 	subprotocols->subprotocols[idx];
							break;
						}
					}

					if (!is_empty(acceptedWebSocketSubprotocol)) {
						conn->req.acceptedWebSocketSubprotocol = acceptedWebSocketSubprotocol;
						break;
					}
				}
			}

			if (!is_empty(protocols))
				free(protocols);
		}

		http_websocket_deflate_negotiate(conn);
		if ((ws_connect_handler != NULL)
			&& (ws_connect_handler(conn, cbData) != 0)) {
			/* C callback has returned non-zero, do not proceed with
			 * handshake.
			 */
			/* Note that C callbacks are no longer called when Lua is
			 * responsible, so C can no longer filter callbacks for Lua. */
			return;
		}
	}

	/* Step 4: Check if there is a responsible websocket handler. */
	if (!is_callback_resource) {
		/* There is no callback, and Lua is not responsible either. */
		/* Reply with a 404 Not Found. We are still at a standard
		 * HTTP request here, before the websocket handshake, so
		 * we can still send standard HTTP error replies. */
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
		if (ws_ready_handler != NULL)
			ws_ready_handler(conn, cbData);
	}

	/* Step 7: Enter the read loop */
	if (is_callback_resource) {
		conn->ws.type = (data_types)DATA_WS_SERVER;
		http_read_websocket(conn, ws_data_handler, cbData);
	}

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
void mask_data(string_t _in, size_t in_len, uint32_t masking_key, string out) {
	size_t i = 0;

	i = 0;
	if ((in_len > 3) && ((ptrdiff_t)_in % 4) == 0) {
		/* Convert in 32 bit words, if data is 4 byte aligned */
		while (i < (in_len - 3)) {
			*(uint32_t *)(void_t)(out + i) =
				*(uint32_t *)(void_t)(_in + i) ^ masking_key;
			i += 4;
		}
	}

	if (i != in_len) {
		/* convert 1-3 remaining bytes if ((dataLen % 4) != 0)*/
		while (i < in_len) {
			*(uint8_t *)(void_t)(out + i) =
				*(uint8_t *)(void_t)(_in + i)
				^ *(((uint8_t *)&masking_key) + (i % 4));
			i++;
		}
	}
}

/* Get a random number (independent of C rand function) */
static uint64_t get_random(void) {
	static uint64_t lfsr = 0; /* Linear feedback shift register */
	static uint64_t lcg = 0;  /* Linear congruential generator */
	uint64_t now = events_now();

	if (lfsr == 0) {
		/* lfsr will be only 0 if has not been initialized,
		 * so this code is called only once. */
		lfsr = events_now();
		lcg = events_now();
	} else {
		/* Get the next step of both random number generators. */
		lfsr = (lfsr >> 1)
			| ((((lfsr >> 0) ^ (lfsr >> 1) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1)
				<< 63);
		lcg = lcg * 6364136223846793005LL + 1442695040888963407LL;
	}

	/* Combining two pseudo-random number generators and a high resolution
	 * part
	 * of the current server time will make it hard (impossible?) to guess
	 * the
	 * next number. */
	return (lfsr ^ lcg ^ now);
}


int http_websocket_client_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen) {
	int retval = -1;
	string masked_data = null;
	uint32_t masking_key = 0;

	if (conn == NULL) return -1;

	masked_data = malloc(((dataLen + 7) / 4) * 4);
	if (masked_data == NULL) {
		http_log(DEBUG_ERROR, conn, "%s: cannot allocate buffer for masked websocket response: Out of memory", __func__);
		return -1;
	}

	do {
		/* Get a masking key - but not 0 */
		masking_key = (uint32_t)get_random();
	} while (masking_key == 0);
	mask_data(data, dataLen, masking_key, masked_data);
	retval = http_websocket_write_exec(conn, opcode, masked_data, dataLen, masking_key);
	free(masked_data);
	return retval;
}

int http_websocket_write_exec(http_t *conn, websocket_type opcode, string_t data, size_t data_len, uint32_t masking_key) {
	unsigned char header[14];
	uint16_t len;
	uint32_t len1, len2;
	size_t headerLen, deflated_size = 0;
	Bytef *deflated = 0;
	int use_deflate, retval = -1;

	atomic_lock(&conn->req.mutex);
	// Deflate websocket messages over 100kb
	if ((use_deflate = (data_len > Kb(100))) && conn->req.accept_gzip) {
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
			http_log(DEBUG_CRASH, conn,
				"Out of memory: Cannot allocate deflate buffer of %lu bytes",
				(unsigned long)deflated_size);
			atomic_unlock(&conn->req.mutex);
			return -1;
		}
		conn->req.websocket_deflate_state.avail_out = (uInt)deflated_size;
		conn->req.websocket_deflate_state.next_out = deflated;
		deflate(&conn->req.websocket_deflate_state, conn->req.websocket_deflate_flush);
		data_len = deflated_size - conn->req.websocket_deflate_state.avail_out - 4; // Strip trailing 0x00 0x00 0xff 0xff bytes
	} else
		header[0] = 0x80u | (unsigned char)((unsigned)opcode & 0xf);

	/* Frame format: http://tools.ietf.org/html/rfc6455#section-5.2 */
	if (data_len < 126) {
		/* inline 7-bit length field */
		header[1] = (unsigned char)data_len;
		headerLen = 2;
	} else if (data_len <= 0xFFFF) {
		/* 16-bit length field */
		uint16_t len = htons((uint16_t)data_len);
		header[1] = 126;
		memcpy(header + 2, &len, 2);
		headerLen = 4;
	} else {
		/* 64-bit length field */
		uint32_t len1 = htonl((uint32_t)((uint64_t)data_len >> 32));
		uint32_t len2 = htonl((uint32_t)(data_len & 0xFFFFFFFFu));
		header[1] = 127;
		memcpy(header + 2, &len1, 4);
		memcpy(header + 6, &len2, 4);
		headerLen = 10;
	}

	if (masking_key) {
		/* add mask */
		header[1] |= 0x80;
		memcpy(header + headerLen, &masking_key, 4);
		headerLen += 4;
	}

	retval = http_write(conn, (const_t)header, headerLen);
	if (retval != (int)headerLen) {
		/* Did not send complete header */
		retval = -1;
	} else {
		if (data_len > 0) {
			if (use_deflate) {
				retval = http_write(conn, (const_t)deflated, data_len);
				free(deflated);
			} else
				retval = http_write(conn, (const_t)data, data_len);
		}
		/* if dataLen == 0, the header length (2) is returned */
	}

	atomic_unlock(&conn->req.mutex);
	return retval;
}

FORCEINLINE int http_websocket_write(http_t *conn, websocket_type opcode, string_t data, size_t dataLen) {
	return http_websocket_write_exec(conn, opcode, data, dataLen, 0);
}

FORCEINLINE int http_websocket_text(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_TEXT, data, dataLen);
}

FORCEINLINE int http_websocket_binary(http_t *conn, const_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_BINARY, (string_t)data, dataLen);
}

FORCEINLINE int http_websocket_close(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_CLOSE, data, dataLen);
}

FORCEINLINE int http_websocket_ping(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_PING, data, dataLen);
}

FORCEINLINE int http_websocket_pong(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_PONG, data, dataLen);
}

FORCEINLINE int http_websocket_continuation(http_t *conn, string_t data, size_t dataLen) {
	return http_websocket_client_write(conn, WS_OPS_CONTINUATION, data, dataLen);
}

FORCEINLINE void http_websocket_wait(http_t *conn) {
	while (is_type(conn, (data_types)DATA_HTTPINFO) && !conn->ws.is_data_ready)
		yield_active_info();

	conn->ws.is_data_ready = false;
}

static void websocket_client_thread_close(void_t data) {
	string_t err = guard_message();
	if (!str_is_empty(err) && guard_caught(err))
		cerr("Exception: %s caught, closing normally!"CLR_LN, err);
}

static void websocket_client_thread(opaque_t data) {
	http_t *conn = (http_t *)data->object;
	http_ini_t *ctx = conn->ctx;

	if (is_type(conn, (data_types)DATA_HTTPINFO)) {
		ctx->status = HTTP_STATUS_RUNNING;
		ctx->worker_taskid = task_id();
		conn->ws.type = (data_types)DATA_WS_CLIENT;
		task_name("Websocket client #%d", ctx->worker_taskid);
		http_read_websocket(conn, conn->ws.data_handler, conn->ws.callback_data);
		debug_info("%s", "Websocket client exited"CLR_LN);
	}
}

static void generate_websocket_magic(string magic25) {
	uint64_t rnd = 0;
	unsigned char buffer[(2 * sizeof(rnd)) + 1] = {0};

	http_get_random(&rnd);
	memcpy(buffer, &rnd, sizeof(rnd));
	http_get_random(&rnd);
	memcpy(buffer + sizeof(rnd), &rnd, sizeof(rnd));

	size_t dst_len = 24 + 1;
	str_encode64((string_t)buffer, magic25, dst_len);
}

static http_t *http_websocket_connect_impl(struct client_options *client_options,
	int use_ssl, string error_buffer, size_t error_buffer_size, string_t path,
	string_t origin, string_t extensions, ws_data_cb data_func, ws_close_cb close_func, void_t user_data) {
	http_t *conn = NULL;
	char magic[32] = {0};
	generate_websocket_magic(magic);

	string_t host = client_options->host;
	int i;

	struct init_data init;
	struct error_data error;

	memset(&init, 0, sizeof(init));
	memset(&error, 0, sizeof(error));
	error.text_buffer_size = error_buffer_size;
	error.text = error_buffer;

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

	/* Establish the client connection and request upgrade */
	conn = http_connect_impl(client_options, use_ssl, &error);

	/* Connection object will be null if something goes wrong */
	if (conn == NULL) {
		/* error_buffer should be already filled ... */
		if (!error_buffer[0]) {
			/* ... if not add an error message */
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error_buffer,
				error_buffer_size,
				"Unexpected error");
		}
		return NULL;
	}

	if (origin != NULL) {
		if (extensions != NULL) {
			i = http_printf(conn,
				"GET %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: %s\r\n"
				"Sec-WebSocket-Version: 13\r\n"
				"Sec-WebSocket-Extensions: %s\r\n"
				"Origin: %s\r\n"
				"\r\n",
				path,
				host,
				magic,
				extensions,
				origin);
		} else {
			i = http_printf(conn,
				"GET %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: %s\r\n"
				"Sec-WebSocket-Version: 13\r\n"
				"Origin: %s\r\n"
				"\r\n",
				path,
				host,
				magic,
				origin);
		}
	} else {
		if (extensions != NULL) {
			i = http_printf(conn,
				"GET %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: %s\r\n"
				"Sec-WebSocket-Version: 13\r\n"
				"Sec-WebSocket-Extensions: %s\r\n"
				"\r\n",
				path,
				host,
				magic,
				extensions);
		} else {
			i = http_printf(conn,
				"GET %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: %s\r\n"
				"Sec-WebSocket-Version: 13\r\n"
				"\r\n",
				path,
				host,
				magic);
		}
	}

	if (i <= 0) {
		http_snprintf(
			NULL, /* No truncation check for ebuf */
			error_buffer,
			error_buffer_size,
			"%s",
			"Error sending request");
		http_close_connection(conn);
		return NULL;
	}

	conn->req.data_len = 0;
	conn->action = HTTP_RESPONSE;
	if (!get_request_response(conn, error_buffer, error_buffer_size, &i)) {
		http_close_connection(conn);
		return NULL;
	}
	conn->req.local_uri = conn->uri;

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

	if (conn->code != 101) {
		/* We sent an "upgrade" request. For a correct websocket
		 * protocol handshake, we expect a "101 Continue" response.
		 * Otherwise it is a protocol violation. Maybe the HTTP
		 * Server does not know websockets. */
		if (!*error_buffer) {
			/* set an error, if not yet set */
			http_snprintf(
				NULL, /* No truncation check for ebuf */
				error_buffer,
				error_buffer_size,
				"Unexpected server reply");
		}

		debug_info("Websocket client connect error: %s, status: %s"CLR_LN, error_buffer, http_status_str(conn->code));
		http_close_connection(conn);
		return NULL;
	}

	conn->ws.type = (data_types)DATA_WS_CLIENT;
	conn->ws.is_data_ready = false;
	conn->ws.data_handler = data_func;
	conn->ws.close_handler = close_func;
	conn->ws.callback_data = user_data;

	/* Now upgrade to ws/wss client context */
	conn->ctx->user_data = user_data;
	atomic_flag_clear(&conn->req.mutex);
	conn->ctx->http_type = HTTP_INI_WEBSOCKET;

	/* Start a ~threaded~ `task` to read the websocket client connection
	 * This `task` will automatically stop when http_disconnect is
	 * called on the client connection */
	go_guard(Kb(48), websocket_client_thread, websocket_client_thread_close, conn);
	return conn;
}

http_t *http_websocket_connect(string_t host, int port, int use_ssl,
	string_t path, string_t origin, ws_data_cb data_func, ws_close_cb close_func, void_t user_data) {
	struct client_options client_options;
	memset(&client_options, 0, sizeof(client_options));
	client_options.host = host;
	client_options.port = port;

	return http_websocket_connect_impl(&client_options, use_ssl,
		task_erred_str(), ERR_BUF, path, origin, NULL, data_func, close_func, user_data);
}

http_t *http_websocket_connect_secure(struct client_options *client_options, string_t path, string_t origin,
	ws_data_cb data_func, ws_close_cb close_func, void_t user_data) {
	if (!client_options) {
		return NULL;
	}

	string error_buffer = task_erred_str();
	size_t error_buffer_size = ERR_BUF;
	return http_websocket_connect_impl(client_options,
		1,
		error_buffer,
		error_buffer_size,
		path,
		origin,
		NULL,
		data_func,
		close_func,
		user_data);
}

http_t *http_websocket_connect_extensions(string_t host, int port, int use_ssl,
	string_t path, string_t origin, string_t extensions, ws_data_cb data_func,
	ws_close_cb close_func, void_t user_data) {
	struct client_options client_options;
	memset(&client_options, 0, sizeof(client_options));
	client_options.host = host;
	client_options.port = port;

	string error_buffer = task_erred_str();
	size_t error_buffer_size = ERR_BUF;
	return http_websocket_connect_impl(&client_options,
		use_ssl,
		error_buffer,
		error_buffer_size,
		path,
		origin,
		extensions,
		data_func,
		close_func,
		user_data);
}

http_t *http_websocket_connect_secure_extensions(struct client_options *client_options,
	string_t path, string_t origin, string_t extensions, ws_data_cb data_func,
	ws_close_cb close_func, void_t user_data) {
	if (!client_options) {
		return NULL;
	}

	string error_buffer = task_erred_str();
	size_t error_buffer_size = ERR_BUF;
	return http_websocket_connect_impl(client_options,
		1,
		error_buffer,
		error_buffer_size,
		path,
		origin,
		extensions,
		data_func,
		close_func,
		user_data);
}
