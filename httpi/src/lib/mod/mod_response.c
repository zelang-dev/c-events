/* response.inl
 *
 * No bufferring for HTTP headers for HTTP response,
 * which is optional for HTTP/1.0 and HTTP/1.1
 *
 * Note bufferring is mandatory for HTTP/2.
 *
 * These functions are only intended to be used at the server side.
 */

#include "../httpi_internal.h"

/* Send first line of HTTP/1.x response */
static int send_http1_response_status_line(http_t *conn) {
	string_t status_txt;
	string_t http_version = conn->req.http_version;
	int status_code = conn->status;

	if ((status_code < 100) || (status_code > 999)) {
		/* Set invalid status code to "500 Internal Server Error" */
		status_code = 500;
	}
	if (!http_version) {
		http_version = "1.0";
	}

	status_txt = http_status_str(conn->status);
	if (http_printf(conn, "HTTP/%s %i %s\r\n", http_version, status_code, status_txt) < 10) {
		/* Network sending failed */
		return 0;
	}
	return 1;
}

int http_response_start(http_t *conn, int status) {
	int ret = 0;
	if ((conn == NULL) || (status < 100) || (status > 999)) {
		/* Parameter error */
		return -1;
	}
	if ((conn->action != HTTP_REQUEST)
	    || (conn->req.proto == PROTOCOL_WEBSOCKET)) {
		/* Only allowed in server context */
		return -2;
	}
	if (conn->req.state != 0) {
		/* only allowed if nothing was sent up to now */
		return -3;
	}
	conn->status = (http_status)status;
	conn->req.state = 1;

	/* Buffered response is stored, unbuffered response will be sent directly,
	 * but we can only send HTTP/1.x response here */
	if (!send_http1_response_status_line(conn)) {
		ret = -4;
	};

	conn->req.state = 1; /* Reset from 10 to 1 */
	return ret;
}

int http_response_add(http_t *conn, string_t header, string_t value, int value_len) {
	if ((conn == NULL) || (header == NULL) || (value == NULL)) {
		/* Parameter error */
		return -1;
	}

	if ((conn->action != HTTP_REQUEST)
	    || (conn->req.proto == PROTOCOL_WEBSOCKET)) {
		/* Only allowed in server context */
		return -2;
	}

	if (conn->req.state != 1) {
		/* only allowed if http_response_start has been called before */
		return -3;
	}

	if (value_len >= 0) {
		http_printf(conn, "%s: %.*s\r\n", header, (int)value_len, value);
	} else {
		http_printf(conn, "%s: %s\r\n", header, value);
	}

	conn->req.state = 1; /* Reset from 10 to 1 */
	return 0;
}

int http_response_multi(http_t *conn, string_t additional_headers) {
	if (is_empty(additional_headers))
		return -1;

	int ret, x, s_pos, count = 0;
	string key, value, line, *lines = null;
	lines = str_has(additional_headers, "\n") ? str_split_ex(additional_headers, "\n", &count) : nullptr;
	if (is_empty(lines))
		return -4;

	ret = count;
	if (count > 0) {
		for (x = 0; x < count; x++) {
			// clean the line
			line = lines[x];
			s_pos = str_pos(line, ":");
			if (s_pos != DATA_INVALID) {
				line[s_pos] = '\0';
				key = trim(line);
				value = trim(trim_at(line, s_pos + 1));
				int lret = http_response_add(conn, word_toupper(key, '-'), value, -1);
				if ((ret > 0) && (lret < 0)) {
					/* Store error return value */
					ret = lret;
				}
			}
		}
	}

	free(lines);
	return ret;
}

int http_response_send(http_t *conn) {
	if (conn == NULL) {
		/* Parameter error */
		return -1;
	}
	if ((conn->action != HTTP_REQUEST)
	    || (conn->req.proto == PROTOCOL_WEBSOCKET)) {
		/* Only allowed in server context */
		return -2;
	}
	if (conn->req.state != 1) {
		/* only allowed if http_response_start has been called before */
		return -3;
	}

	/* State: 2 */
	conn->req.state = 2;

	http_write(conn, "\r\n", 2);
	conn->req.state = 3;

	return 0;
}

int http_get_response(http_t *conn, string ebuf, size_t ebuf_len, int timeout) {
	int err, ret;
	char txt[32]; /* will not overflow */
	string save_timeout, new_timeout;

	if (ebuf_len > 0) {
		ebuf[0] = '\0';
	}

	if (!conn) {
		http_snprintf(
			NULL, /* No truncation check for ebuf */
			ebuf,
			ebuf_len,
			"%s",
			"Parameter error");
		return -1;
	}

	/* Reset the previous responses */
	conn->req.data_len = 0;

	/* Implementation of API function for HTTP clients */
	save_timeout = conn->domain->config[REQUEST_TIMEOUT];

	if (timeout >= 0) {
		events_tcp_timeout(conn->client->sock, timeout);
		http_snprintf(NULL, txt, sizeof(txt), "%i", timeout);
		new_timeout = txt;
	} else {
		new_timeout = NULL;
	}

	conn->action = HTTP_RESPONSE;
	conn->domain->config[REQUEST_TIMEOUT] = new_timeout;
	ret = get_request_response(conn, ebuf, ebuf_len, &err);
	conn->domain->config[REQUEST_TIMEOUT] = save_timeout;

	/* TODO: here, the URI is the http response code */
	conn->req.local_uri = conn->url_to;

	/* TODO (mid): Define proper return values - maybe return length?
	 * For the first test use <0 for error and >0 for OK */
	return (ret == 0) ? -1 : +1;
}
