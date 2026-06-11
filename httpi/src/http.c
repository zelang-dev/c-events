#include "lib/httpi_internal.h"

static string_t method_strings[] = {
"DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "PATCH", "PURGE"
};

static string_t const mon_short_names[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static string_t const day_short_names[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static char http_server_name[NAME_MAX] = HTTP_SERVER;
static char http_agent_name[NAME_MAX] = HTTP_AGENT;
static char http_timestamp[81] = {0};

/*
 * Returns a converted time to tm structure.
 * No timezone conversion takes place. UTC as zone is assumed.
 */
struct tm *http_gmtime_r(const time_t *clk, struct tm *result) {
#if defined(_WIN32)
	if (gmtime_s(result, clk) == 0) return result;
	return nullptr;
#else
	return gmtime_r(clk, result);
#endif
}

void http_gmt_time_str(char *buf, size_t buf_len, time_t *t) {
	struct tm _tm;
	struct tm *tm = &_tm;

	if (t != NULL) {
		http_gmtime_r(t, tm);
		strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", tm);
	} else {
		str_lcpy(buf, "Thu, 01 Jan 1970 00:00:00 GMT", buf_len);
	}
}

static void http_clear(http_t *this) {
	if (is_data(this->garbage)) {
		foreach_back(arr in this->garbage) {
			free(arr.object);
		}

		$delete(this->garbage);
		this->garbage = nullptr;
	}
}

string word_toupper(string str, char sep) {
	size_t i, length = 0;

	length = strlen(str);
	for (i = 0;i < length;i++) {// capitalize the first most letter
		if (i == 0) {
			str[i] = toupper(str[i]);
		} else if (str[i] == sep) {//check if the charater is the separator
			str[i + 1] = toupper(str[i + 1]);
			i += 1;  // skip the next charater
		} else {
			str[i] = tolower(str[i]); // lowercase reset of the characters
		}
	}

	return str;
}

static FORCEINLINE void_t concat_headers(void_t line, string_t key, const_t value) {
	void_t lines = line;
	lines = str_cat_ex(5, (string)lines, key, ": ", value, CRLF);
	free(line);

    return lines;
}

static FORCEINLINE void_t concat_cookies(void_t line, string_t key, const_t value) {
	void_t lines = line;
	cookie_t *cookie = (cookie_t *)value;
	lines = str_cat_ex(5, (string)lines, key, "=", cookie->value, "; ");
	free(line);

    return lines;
}

/* Return date string ahead in standard format for `Set-Cookie` headers */
string http_date_ahead(u32 days, u32 hours, u32 minutes, u32 seconds) {
	time_t time_ahead, current_time;
	u32 date_ahead = 0;

	if (days) date_ahead = (24 * 3600 * days);
	if (hours) date_ahead = date_ahead + (hours * 3600);
	if (minutes) date_ahead = date_ahead + (minutes * 60);
	if (seconds) date_ahead = date_ahead + seconds;

	// Get the current time in seconds since the epoch
	time(&current_time);

	// Add time ahead
	time_ahead = current_time + date_ahead;
	return http_std_date(time_ahead);
}

/* Return date string in standard format for http headers */
string http_std_date(time_t t) {
	struct tm *tm1, tm_buf;
	if (t == 0) {
		time_t timer;
		t = time(&timer);
	}

	tm1 = http_gmtime_r(&t, &tm_buf);
	if (!tm1) {
		return http_timestamp;
	}

	snprintf(http_timestamp, sizeof(http_timestamp), "%s, %02d %s %04d %02d:%02d:%02d GMT",
		day_short_names[tm1->tm_wday],
		tm1->tm_mday,
		mon_short_names[tm1->tm_mon],
		tm1->tm_year + 1900,
		tm1->tm_hour, tm1->tm_min, tm1->tm_sec);

	return http_timestamp;
}

string_t http_status_str(uint16_t const status) {
    switch (status) {
        // Informational 1xx
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 102: return "Processing"; // RFC 2518, obsoleted by RFC 4918
        case 103: return "Early Hints";

            // Success 2xx
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status"; // RFC 4918
        case 208: return "Already Reported";
        case 226: return "IM Used";

            // Redirection 3xx
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Moved Temporarily";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "Reserved";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";

            // Client Error 4xx
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Time-out";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Large";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";               // RFC 2324
		case 419: return "Authentication Timeout";		/* common use							*/
		case 420: return "Enhance Your Calm";			/* common use							*/
		case 421: return "Misdirected Request";		/* RFC7540 Section 9.1.2					*/
        case 422: return "Unprocessable Entity";       // RFC 4918
        case 423: return "Locked";                     // RFC 4918
        case 424: return "Failed Dependency";          // RFC 4918
        case 425: return "Unordered Collection";       // RFC 4918
        case 426: return "Upgrade Required";           // RFC 2817
        case 428: return "Precondition Required";      // RFC 6585
        case 429: return "Too Many Requests";          // RFC 6585
		case 431: return "Request Header Fields Too Large";// RFC 6585			*/
		case 440: return "Login Timeout";			/* common use							*/
        case 444: return "Connection Closed Without Response";
        case 451: return "Unavailable For Legal Reasons";
        case 499: return "Client Closed Request";

            // Server Error 5xx
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Time-out";
        case 505: return "HTTP Version Not Supported";
        case 506: return "Variant Also Negotiates";    // RFC 2295
		case 507: return "Insufficient Storage";       // RFC 4918
		case 508: return "Loop Detected";			/* RFC5842 Section 7.1						*/
		case 509: return "Bandwidth Limit Exceeded";
        case 510: return "Not Extended";               // RFC 2774
        case 511: return "Network Authentication Required"; // RFC 6585
        case 599: return "Network Connect Timeout Error";
		default:
			/*
			* Return at least a category according to RFC 2616 Section 10.
			*/
			if (status >= 100 && status < 200) return "Information";
			if (status >= 200 && status < 300) return "Success";
			if (status >= 300 && status < 400) return "Redirection";
			if (status >= 400 && status < 500) return "Client Error";
			if (status >= 500 && status < 600) return "Server Error";

			return "";
    }
}

/* rfc1738:

   ...The characters ";",
   "/", "?", ":", "@", "=" and "&" are the characters which may be
   reserved for special meaning within a scheme...

   ...Thus, only alphanumerics, the special characters "$-_.+!*'(),", and
   reserved characters used for their reserved purposes may be used
   unencoded within a URL...

   For added safety, we only leave -_. unencoded.
 */
static unsigned char hex_chars[] = "0123456789ABCDEF";

string url_encode(char const *s, size_t len) {
	register unsigned char c;
	unsigned char *to;
	unsigned char const *from, *end;
	string start, ret;

	from = (unsigned char *)s;
	end = (unsigned char *)s + len;
	start = calloc(1, 3 * len);
	if (is_empty(start))
		return null;

	to = (unsigned char *)start;

	while (from < end) {
		c = *from++;

		if (c == ' ') {
			*to++ = '+';
		} else if ((c < '0' && c != '-' && c != '.') ||
			(c < 'A' && c > '9') ||
			(c > 'Z' && c < 'a' && c != '_') ||
			(c > 'z')) {
			to[0] = '%';
			to[1] = hex_chars[c >> 4];
			to[2] = hex_chars[c & 15];
			to += 3;
		} else {
			*to++ = c;
		}
	}

	*to = '\0';
	size_t rlen = to - (unsigned char *)start;
	if (defer_free(ret = calloc(1, rlen)))
		memcpy(ret, start, rlen + 1);

	free(start);
	return ret;
}

string url_decode(string str) {
	if (is_empty(str))
		return "";

	int len2 = (int)strlen(str);
	(void)http_url_decode(str, len2, str, len2 + 1, 1);
	return str;
}

hash_http_t *http_extract_var(string_t query, string delim, string sep) {
	hash_http_t *this = null;
	if (!str_is_empty(query) && defer_free(this = hash_create_auto(ARRAY_SIZE))) {
		if (is_empty(sep))
			sep = "=";

		int i = 0, x;
		string *token = str_split_ex(query, delim, &i);
		if (!is_empty(token)) {
			for (x = 0; x < i; x++) {
				string *parts = str_split_ex(token[x], sep, nullptr);
				if (!is_empty(parts)) {
					if (!str_is_empty(parts[0]))
						(void)hash_put_str(this, parts[0], (is_empty(parts[1]) ? "" : parts[1]));

					free(parts);
				}
			}

			free(token);
		}
	}

	return this;
}

FORCEINLINE string http_get_decoded(hash_http_t *this, string key) {
	void_t value = hash_get(this, key);
	return is_empty(value)
		? null
		: (strlen(value) == 0
			? ""
			: (str_has_either(value, "%", "+")
				? url_decode(value)
				: value));
}

FORCEINLINE int http_pattern_match(string pattern, string match) {
	if (pattern == NULL)
		return -1;

	return http_match_prefix(pattern, strlen(pattern), match);
}

void parse_str(http_t *this, string lines, string sep, string part) {
	if (is_empty(this->parameters)) {
		this->parameters = hash_create_auto(ARRAY_SIZE);
		defer_free(this->parameters);
	}

	if (is_empty(part))
        part = "=";

    int i = 0, x;
	string *token = str_split_ex(lines, sep, &i);
	if (!is_empty(token)) {
		for (x = 0; x < i; x++) {
			string *parts = str_split_ex(token[x], part, nullptr);
			if (!is_empty(parts)) {
				hash_pair_t *p = hash_put_str(this->parameters, trim(parts[0]), trim(parts[1]));
				free(parts);
			}
		}

		free(token);
	}
}

void parse_multipart(http_t *this) {
	if (this->is_multipart) {
		string key, value, line, delim = nullptr, keyname = nullptr,
			*boundary = nullptr, *boundaries = nullptr, *params = nullptr,
			*lines = nullptr, *filenames = nullptr, *filename = nullptr;
		int s_pos, s_pos1, x, y, sects = 0, names = 0, count = 0, pieces = 0;
		form_data_t *multipart;
		char scrape[ARRAY_SIZE];
		bool found;

		snprintf(scrape, ARRAY_SIZE, "--%s", this->boundary);
		if (this->content_length == -1) {
			if (!is_empty(value = http_get_header(this, "Content-Length"))) {
				this->content_length = atoi(value);
			}
		}

		boundary = (string *)mem_split_ex(this->body, this->content_length, this->boundary, &count);
		if (is_empty(boundary))
			return;

		$append(this->garbage, boundary);
		if (--count >= 1 && str_case_equal(boundary[count], "--", 2)) {
			if (!is_empty(this->dispositions)) {
				hash_free(this->dispositions);
				this->dispositions = nullptr;
			}

			this->dispositions = hashtable_init(key_ops_auto, val_ops_value, hash_lp_idx, ARRAY_SIZE);
			if (!is_data(this->names))
				this->names = array();
			else
				$reset(this->names);

			for (x = 1; x < count; x++) {
				size_t boundarysize = ((uintptr_t)boundary[x + 1] - (uintptr_t)boundary[x]);
				boundaries = (string *)mem_split_ex(boundary[x],
					boundarysize, (this->is_valid == 2 ? LFLF : CRLF CRLF),	&pieces);
				$append(this->garbage, boundaries);
				if (pieces > 1) {
					multipart = calloc(1, sizeof(form_data_t));
					if (is_empty(multipart))
						break;

					$append(this->garbage, multipart);
					// Calculate each multipart body size by memory region used
					size_t headsize = ((uintptr_t)boundaries[1] - (uintptr_t)boundaries[0]);
					multipart->bodysize = (boundarysize - headsize) - (strlen(scrape) - this->is_valid);
					s_pos = mempos_str(boundaries[1],
						multipart->bodysize, (this->is_valid == 2 ? "\n--" : "\r\n--"));

					multipart->bodysize -= (this->is_valid == 2 ? 3 : 4);
					multipart->body = boundaries[1];
					multipart->body[s_pos] = '\0';
					lines = str_split_ex(trim(boundaries[0]), "\n", &sects);
					if (sects >= 1) {
						for (y = 0; y < sects; y++) {
							line = lines[y];
							found = false;
							s_pos = str_pos(line, ":");
							if (s_pos != DATA_INVALID) {
								found = true;
								line[s_pos] = '\0';
								key = trim(line);
								value = trim(trim_at(line, s_pos + 1));
							}

							if (found) {
								if (str_is(key, "Content-Disposition")) {
									params = str_split_ex(value, "; ", &names);
									if (!is_empty(params)) {
										$append(this->garbage, params);
										multipart->disposition = params[0];
										filenames = str_split_ex(params[1], "\"", nullptr);
										if (!is_empty(filenames)) {
											$append(this->garbage, filenames);
											keyname = trim(filenames[1]);
											$append_string(this->names, keyname);
											if (names > 2) {
												filename = str_split_ex(params[2], "\"", nullptr);
												if (!is_empty(filename)) {
													$append(this->garbage, filename);
													if (!is_empty(filename[1]))
														multipart->filename = trim(filename[1]);
												}
											}
										}
									}
								} else if (str_is(key, "Content-Type")) {
									multipart->type = value;
								} else if (str_is(key, "Content-Transfer-Encoding")) {
									multipart->encoding = value;
								}
							}
						}

						if (keyname) {
							hash_put(this->dispositions, keyname, multipart);
							keyname = nullptr;
						}
					}

					if (!is_empty(lines)) {
						free(lines);
						lines = null;
					}
				}
			}
		}
	}
}

static FORCEINLINE bool is_valid_http_method(string method) {
	return str_has("GET,HEAD,POST,PUT,PATCH,PURGE,PROPPATCH,DELETE,OPTIONS,CONNECT,PROPFIND,"
		"TRACE,MKCOL,COPY,LOCK,MKCOL,MOVE,PROPFIND,UNLOCK,REPORT,"
		"MKACTIVITY,CHECKOUT,MERGE,M-SEARCH,NOTIFY,SUBSCRIBE,"
		"UNSUBSCRIBE,SEARCH", method);
}

int parse_http(http_parser_type action, http_t *this, string raw) {
	string messages, key, value, line, parameters, *sessions = nullptr, *lines = nullptr;
	int i = 0, x = 0, z = 0, s_pos = 0, count = 0;
	bool is_multi_set = false, is_cookie_set = false, found = false;
	if (is_data(this->garbage))
		http_clear(this);

	if (is_data(this->cookies))
		$reset(this->cookies);

	if (!is_empty(this->sessions)) {
		hash_free(this->sessions);
		this->sessions = nullptr;
	}

	this->num_headers = 0;
	if (str_is_empty(raw))
		return DATA_INVALID;

	this->is_valid = 4;
	if ((s_pos = (!this->req.request_len
		? str_pos(raw, CRLF CRLF)
		: mempos_str(raw, this->req.request_len, CRLF CRLF))) == DATA_INVALID) {
		this->is_valid = 2;
		if ((s_pos = (!this->req.request_len
			? str_pos(raw, LFLF)
			: mempos_str(raw, this->req.request_len, LFLF))) == DATA_INVALID)
			return DATA_INVALID;
	}

	this->action = action;
	this->raw = raw;
	this->raw_pos = s_pos;
	this->raw[s_pos] = '\0';
	messages = this->raw;
	this->body = trim_at(messages, s_pos + this->is_valid);
	lines = str_has(messages, "\n") ? str_split_ex(messages, "\n", &count) : nullptr;
	this->raw[this->raw_pos] = (this->is_valid == 2) ? '\n' : '\r';
	if (count >= 0) {
		if (is_empty(this->headers)) {
			this->headers = hashtable_init(key_ops_auto, val_ops_auto, hash_lp_idx, ARRAY_SIZE);
			defer_free(this->headers);
		}

		if (is_empty(lines))
			count++;

		for (x = 0; x < count; x++) {
			// clean the line
			if (is_empty(lines))
				line = trim(messages);
			else
				line = trim(lines[x]);
			found = false;
			is_cookie_set = false;
			s_pos = str_pos(line, ":");
			if (s_pos != DATA_INVALID && x != 0) {
				found = true;
				line[s_pos] = '\0';
				key = trim(line);
				value = trim(trim_at(line, s_pos + 1));
				this->num_headers++;
			} else if (str_has(line, "HTTP/") && !x) {
				s_pos = str_pos(line, " ");
				line[s_pos] = '\0';
				string params1 = trim_at(line, (s_pos + 1));
				s_pos = str_pos(params1, " ");
				params1[s_pos] = '\0';
				string params2 = trim_at(params1, (s_pos + 1));
				if (this->action == HTTP_REQUEST) {
					snprintf(this->method, sizeof(this->method), "%s", trim(line));
					if (!is_valid_http_method(this->method)) {
						if (!is_empty(lines))
							free(lines);
						return DATA_INVALID;
					}

					this->url_to = str_dup(trim(params1));
					this->path = this->url_to;
					// split path and parameters string
					if (str_has(this->url_to, "?")) {
						s_pos = str_pos(this->url_to, "?");
						this->url_to[s_pos] = '\0';
						this->path = str_dup(this->url_to);
						this->query_string = trim_at(this->url_to, (s_pos));
						parameters = trim_at(this->url_to, (s_pos + 1));
						// parse the parameters
						if (str_has(parameters, "&"))
							parse_str(this, parameters, "&", nullptr);

						this->url_to[s_pos] = '?';
					}
					snprintf(this->protocol, sizeof(this->protocol), "%s", trim(params2));
					this->req.http_version = (const char *)trim_at(this->protocol, 5);
				} else if (this->action == HTTP_RESPONSE) {
					snprintf(this->protocol, sizeof(this->protocol), "%s", trim(line));
					this->req.http_version = (const char *)trim_at(this->protocol, 5);
					this->code = (http_status)atoi(params1);
					snprintf(this->message, sizeof(this->message), "%s", trim(params2));
				}
			}

			if (found) {
				if (!is_multi_set && str_is_case(key, "Content-Type")
					&& str_case_equal(value, "multipart/form-data; boundary=", 30)) {
					if (!is_data(this->garbage))
						this->garbage = array();

					is_multi_set = true;
					string *para = str_split_ex(value, "; boundary=", nullptr);
					this->is_multipart = true;
					this->boundary = para[1];
					$append(this->garbage, para);
				} else if (str_is_case(key, "Set-Cookie")) {
					if (is_empty(this->sessions))
						this->sessions = hashtable_init(key_ops_auto, val_ops_value, hash_lp_idx, ARRAY_SIZE);

					is_cookie_set = true;
					cookie_t *cookie = calloc(1, sizeof(cookie_t));
					if (is_empty(cookie))
						return -1;

					defer_free(cookie);
					if (str_has(value, "Secure"))
						cookie->secure = true;

					if (str_has(value, "HttpOnly"))
						cookie->httpOnly = true;

					string *sess = str_split_ex(value, "; ", &z);
					string session_name = nullptr;
					for (i = 0; i < z; i++) {
						sessions = str_split_ex(sess[i], "=", nullptr);
						if (!is_empty(sessions) && !is_empty(sessions[0])) {
							if (str_is(sessions[0], "Path")) {
								snprintf(cookie->path, sizeof(cookie->path), "%s", trim(sessions[1]));
							} else if (str_is(sessions[0], "Expires")) {
								snprintf(cookie->expiries, sizeof(cookie->expiries), "%s", trim(sessions[1]));
							} else if (str_is(sessions[0], "Max-Age")) {
								cookie->maxAge = atoi(sessions[1]);
							} else if (str_is(sessions[0], "SameSite")) {
								snprintf(cookie->sameSite, sizeof(cookie->sameSite), "%s", trim(sessions[1]));
							} else if (str_is(sessions[0], "Domain")) {
								snprintf(cookie->domain, sizeof(cookie->domain), "%s", trim(sessions[1]));
							} else if (!is_empty(sessions[1]) && is_empty(session_name)) {
								session_name = str_dup((string_t)sessions[0]);
								snprintf(cookie->value, sizeof(cookie->value), "%s", trim(sessions[1]));
								if (!is_data(this->cookies))
									this->cookies = array();

								$append_string(this->cookies, session_name);
							}
						}

						if (!is_empty(sessions)) {
							free(sessions);
							sessions = nullptr;
						}
					}

					if (session_name)
						hash_put(this->sessions, session_name, cookie);

					if (!is_empty(sess)) {
						free(sess);
						sess = nullptr;
					}
				}

				char keyaddr[ARRAY_SIZE] = {0};
				snprintf(keyaddr, sizeof(keyaddr), "%s", key);
				hash_put_str(this->headers, str_tolower(keyaddr), value);
			}
		}

		if (!is_empty(lines))
			free(lines);

		return this->req.request_len;
	}

	return DATA_INVALID;
}

void http_free(http_t *this) {
	if (is_ptr_usable(this) && is_type(this, (data_types)DATA_HTTPINFO)) {
		this->type = DATA_INVALID;
		if (is_data(this->cookies)) {
			$delete(this->cookies);
			this->cookies = nullptr;
		}

		if (is_data(this->names)) {
			$delete(this->names);
			this->names = nullptr;
		}

		if (!is_empty(this->sessions)) {
			hash_free(this->sessions);
			this->sessions = nullptr;
		}

		if (is_data(this->garbage))
			http_clear(this);

		if (!is_empty(this->dispositions)) {
			hash_free(this->dispositions);
			this->dispositions = nullptr;
		}

		free(this);
	}
}

http_t *http_for(string hostname, double protocol) {
	http_t *this = fence(calloc(1, sizeof(http_t)), (func_t)http_free);
	if (!is_empty(this)) {
		this->names = nullptr;
		this->cookies = nullptr;
		this->garbage = nullptr;
		this->sessions = nullptr;
		this->dispositions = nullptr;
		this->is_multipart = false;
		this->code = STATUS_OK;
		this->status = STATUS_NO_CONTENT;
		this->hostname = hostname;
		this->version = protocol;
		this->req.content_len = -1;
		this->content_length = -1;
		this->req.http_version = "1.1";
		this->type = (data_types)DATA_HTTPINFO;
	}

	return this;
}

FORCEINLINE void http_user_agent(string name) {
	if (snprintf(http_agent_name, sizeof(http_agent_name), "%s", name))	return;
}

FORCEINLINE void http_server_agent(string name) {
	if (snprintf(http_server_name, sizeof(http_server_name), "%s", name)) return;
}

string http_response_str(http_t *this, string body, http_status status,
	string type, u32 header_pairs, ...) {
	va_list extras;
	header_types k;
	string key, val, lines, body_data;
	bool found, force_cap;
	char scrape[ARRAY_SIZE];
	char scrape2[ARRAY_SIZE];
	char auth[NAME_MAX];
	int i = 0;

	if (!is_empty(this->headers)) {
		hash_delete(this->headers, "Date");
		hash_delete(this->headers, "Content-Length");
		hash_delete(this->headers, "Content-Type");
		hash_delete(this->headers, "Host");
		hash_delete(this->headers, "Accept");
		hash_delete(this->headers, "User-Agent");
		hash_delete(this->headers, "Server");
	}

	if (status != 0) {
		this->status = status;
	}

	if (is_empty(body) && status == 0) {
		this->status = status = STATUS_NOT_FOUND;
	}

	body_data = is_empty(body)
		? str_cat_ex(7,
			"<h1>", http_server_name, ": ", str_itoa(status), " - ", http_status_str(status), "</h1>")
		: body;

	snprintf(scrape, ARRAY_SIZE, "%d", this->status);
	snprintf(scrape2, ARRAY_SIZE, "%zu", strlen(body_data));
	// Create a string out of the response data
	lines = str_cat_ex(15,
		// response status
		"HTTP/", (str_is_empty(this->protocol) ? gcvt(this->version, 2, this->protocol) : this->protocol), " ",
		scrape, " ", http_status_str(this->status), CRLF
		// set initial headers
		"Date: ", http_std_date(0), CRLF
		"Content-Type: ", (is_empty(type) ? "text/html" : type), "; charset=utf-8" CRLF
		"Content-Length: ", scrape2, CRLF
		"Server: ", http_server_name, CRLF
	);

	if (header_pairs > 0) {
		va_start(extras, header_pairs);
		for (i = 0; i < (int)header_pairs; i++) {
			found = false;
			force_cap = false;
			k = va_arg(extras, header_types);
			val = va_arg(extras, string);
			switch (k) {
				case head_cookie:
					found = true;
					key = "Set-Cookie";
					break;
				case head_secure:
					found = true;
					key = "Strict-Transport-Security";
					break;
				case head_conn:
					found = true;
					key = "Connection";
					break;
				case head_bearer:
					found = true;
					key = "Authorization";
					snprintf(auth, NAME_MAX, "Bearer %s", val);
					val = auth;
					break;
				case head_auth_basic:
					found = true;
					key = "Authorization";
					snprintf(auth, NAME_MAX, "Basic %s", val);
					val = auth;
					break;
				case head_by:
					found = true;
					key = "X-Powered-By";
					break;
				case head_custom:
					found = true;
					force_cap = true;
					key = val;
					val = va_arg(extras, string);
					break;
			}

			if (found) {
				http_put_header(this, key, val, force_cap);
			}
		}
		va_end(extras);
	}

	// add the current stored response headers
	lines = hash_iter(this->headers, lines, concat_headers);

	// Build a response header string based on the current line data.
	string resp = str_cat_ex(3, (string)lines, CRLF, body_data);
	free(lines);
	if (is_empty(body))
		free(body_data);

	if (is_empty(this->garbage))
		this->garbage = arrays(1, resp);
	else
		$append(this->garbage, resp);

	return resp;
}

string http_request_str(http_t *this, http_method_type method, string path, string type,
	string body_data, u32 header_pairs, ...) {
	va_list extras;
	header_types k;
	string key, val;
	char scrape[ARRAY_SIZE];
	char auth[NAME_MAX] = {0};
	bool found = true;
	int x, count = 0;
	string localpath = path;

	this->uri = path;
	if (!str_has(path, "://")) {
		found = false;
		this->uri = str_cat_ex(2, (is_empty(this->hostname) ? "http://" : this->hostname), path);
	}

	if (!found)
		defer_free(this->uri);

	uri_t *url_array = parse_uri(this->uri);
	string hostname = !is_empty(url_array->host) ? url_array->host : this->hostname;
	if (!is_empty(url_array->path)) {
		localpath = url_array->path;
		if (!is_empty(url_array->query)) {
			free(url_array->path);
			url_array->path = str_cat_ex(3, localpath, "?", url_array->query);
			free(localpath);
			localpath = url_array->path;
		}

		if (!is_empty(url_array->fragment)) {
			free(url_array->path);
			url_array->path = str_cat_ex(3, localpath, "#", url_array->fragment);
			free(localpath);
		}
	}

	string headers, header = str_cat_ex(10, method_strings[method], " ",
		(is_empty(path) ? "/" : url_array->path),
		" HTTP/", gcvt(this->version, 2, scrape), CRLF
		"Host: ", hostname, CRLF
		"Accept: */*" CRLF
		"User-Agent: ", http_agent_name, CRLF
	);

	if (!is_empty(body_data)) {
		headers = str_cat_ex(6, header,
			"Content-Type: ", (is_empty(type) ? "text/html" : type), "; charset=utf-8" CRLF
			"Content-Length: ", str_itoa(strlen(body_data)), CRLF
		);
		free(header);
		header = headers;
	}

	if (header_pairs > 0) {
		va_start(extras, header_pairs);
		for (x = 0; x < (int)header_pairs; x++) {
			found = false;
			k = va_arg(extras, header_types);
			val = va_arg(extras, string);
			switch (k) {
				case head_cookie:
					found = true;
					key = "Cookie";
					break;
				case head_secure:
					found = true;
					key = "Strict-Transport-Security";
					break;
				case head_conn:
					found = true;
					key = "Connection";
					break;
				case head_bearer:
					found = true;
					key = "Authorization";
					snprintf(auth, NAME_MAX, "Bearer %s", val);
					val = auth;
					break;
				case head_auth_basic:
					found = true;
					key = "Authorization";
					snprintf(auth, NAME_MAX, "Basic %s", val);
					val = auth;
					break;
				case head_by:
					found = true;
					key = "X-Powered-By";
					break;
				case head_custom:
					found = true;
					key = word_toupper(val, '-');
					val = va_arg(extras, string);
					break;
			}

			if (found) {
				headers = str_cat_ex(5, header, key, ": ", val, CRLF);
				free(header);
				header = headers;
			}
		}
		va_end(extras);
	}

	// add the current stored `set-cookie` response headers
	if (!is_empty(this->sessions) && is_data(this->cookies) && $size(this->cookies) >= 1) {
		headers = str_cat_ex(2, header, CRLF "Cookie: ");
		free(header);
		header = headers;
		headers = hash_iter(this->sessions, header, concat_cookies);
		headers[strlen(headers) - 2] = ' ';
		header = headers;
		headers = str_cat_ex(2, header, CRLF);
		free(header);
		header = headers;
	}

	headers = str_cat_ex(2, header, CRLF);
	free(header);
	header = headers;

	if (!is_empty(body_data)) {
		headers = str_cat_ex(2, header, body_data);
		free(header);
	}

	uri_free(url_array);
	if (!is_data(this->garbage))
		this->garbage = arrays(1, headers);
	else
		$append(this->garbage, headers);

	defer(http_clear, this);
	return headers;
}

FORCEINLINE bool http_multi_has(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return false;

	return hash_has(this->dispositions, name);
}

FORCEINLINE size_t http_multi_length(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return 0;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? 0 : form->bodysize;
}

FORCEINLINE string http_multi_body(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return nullptr;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? nullptr : form->body;
}

FORCEINLINE string http_multi_disposition(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return nullptr;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? nullptr : form->disposition;
}

FORCEINLINE string http_multi_type(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return nullptr;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? nullptr : form->type;
}

FORCEINLINE bool http_multi_is_file(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return false;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? false : !is_empty(form->filename);
}

FORCEINLINE string http_multi_filename(http_t *this, string name) {
	if (is_empty(this->dispositions))
		return nullptr;

	form_data_t *form = (form_data_t *)hash_get_value(this->dispositions, name)->object;
	return is_empty(form) ? nullptr : form->filename;
}

FORCEINLINE size_t http_multi_count(http_t *this) {
	return $size(this->names);
}

FORCEINLINE array_t http_multi_names(http_t *this) {
	return this->names;
}

FORCEINLINE bool http_is_multipart(http_t *this) {
	return this->is_multipart;
}

FORCEINLINE bool http_cookie_is_multi(http_t *this) {
	return !is_data(this->cookies) ? false : $size(this->cookies) > 1;
}

FORCEINLINE array_t http_cookie_names(http_t *this) {
	return !is_data(this->cookies) ? nullptr : this->cookies;
}

FORCEINLINE size_t http_cookie_count(http_t *this) {
	return !is_data(this->cookies) ? 0 : $size(this->cookies);
}

FORCEINLINE bool http_cookie_is_secure(http_t *this, string name) {
	if (is_empty(this->sessions))
		return false;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? false : cookie->secure;
}

FORCEINLINE bool http_cookie_is_httpOnly(http_t *this, string name) {
	if (is_empty(this->sessions))
		return false;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? false : cookie->httpOnly;
}

FORCEINLINE size_t http_cookie_maxAge(http_t *this, string name) {
	if (is_empty(this->sessions))
		return 0;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? 0 : (size_t)cookie->maxAge;
}

FORCEINLINE string http_get_cookie(http_t *this, string name) {
	if (is_empty(this->sessions))
		return nullptr;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? nullptr : cookie->value;
}

FORCEINLINE string http_cookie_expiries(http_t *this, string name) {
	if (is_empty(this->sessions))
		return nullptr;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? nullptr : cookie->expiries;
}

FORCEINLINE string http_cookie_domain(http_t *this, string name) {
	if (is_empty(this->sessions))
		return nullptr;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? nullptr : cookie->domain;
}

FORCEINLINE string http_cookie_sameSite(http_t *this, string name) {
	if (is_empty(this->sessions))
		return nullptr;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? nullptr : cookie->sameSite;
}

FORCEINLINE string http_cookie_path(http_t *this, string name) {
	if (is_empty(this->sessions))
		return nullptr;

	cookie_t *cookie = (cookie_t *)hash_get_value(this->sessions, name)->object;
	return is_empty(cookie) ? nullptr : cookie->path;
}

void http_vsnprintf(int *truncated, string buf, size_t buflen, string_t fmt, va_list ap) {
	int n;
	bool ok;

	if (is_empty(buf) || buflen < 1) return;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
/* Using fmt as a non-literal is intended here, since it is mostly called
 * indirectly by http_snprintf */
#endif
	n = (int)vsnprintf(buf, buflen, fmt, ap);
	ok = (n >= 0) && ((size_t)n < buflen);

#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if (ok) {
		if (!is_empty(truncated))
			*truncated = false;
	} else {
		if (!is_empty(truncated))
			*truncated = true;
		n = (int)buflen - 1;
	}
	buf[n] = '\0';
}

void http_snprintf(int *truncated, string buf, size_t buflen, string_t fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	http_vsnprintf(truncated, buf, buflen, fmt, ap);
	va_end(ap);
}

void http_credentials(http_t *conn, string user, size_t userlen, string pass, size_t passlen) {
	user[0] = pass[0] = '\0';
	string v = http_get_header(conn, "Authorization");
	if (v != NULL && str_case_equal(v, "Basic ", 6)) {
		char buf[256];
		string auth = str_decode64(trim_at(v, 6), buf, sizeof(buf));
		int s_pos = str_pos(auth, ":");
		if (s_pos != DATA_INVALID) {
			auth[s_pos] = '\0';
			http_snprintf(null, user, userlen, "%s", auth);
			http_snprintf(null, pass, passlen, "%s", trim_at(auth, s_pos + 1));
		}
	} else if (v != NULL && str_case_equal(v, "Bearer ", 7)) {
		http_snprintf(null, pass, passlen, "%s", v[7]);
	} else if ((v = http_get_var(conn, "Cookie", "access_token")) != NULL) {
		http_snprintf(null, pass, passlen, "%s", v);
	} else if ((v = http_get_param(conn, "access_token")) != NULL) {
		http_snprintf(null, pass, passlen, "%s", v);
	}
}

FORCEINLINE string http_get_protocol(http_t *this) {
	return is_empty(this) ? "" : this->protocol;
}

FORCEINLINE string http_get_boundary(http_t *this) {
	return is_empty(this) ? "" : this->boundary;
}

FORCEINLINE string http_get_path(http_t *this) {
	return is_empty(this) ? "" : this->path;
}

FORCEINLINE string_t http_get_query(http_t *this) {
	return str_is_empty(this->req.query_string) ? this->query_string : this->req.query_string;
}

FORCEINLINE double http_get_version(http_t *this) {
	return is_empty(this) ? (double)DATA_ERR : this->version;
}

FORCEINLINE string_t http_version(http_t *this) {
	return is_empty(this) ? "" : this->req.http_version;
}

FORCEINLINE string http_get_method(http_t *this) {
	return is_empty(this) ? "" : this->method;
}

FORCEINLINE http_status http_get_code(http_t *this) {
	return !is_empty(this) ? this->code : DATA_ERR;
}

FORCEINLINE long long http_get_length(http_t *this) {
	return !is_empty(this) ? this->req.content_len : DATA_ERR;
}

FORCEINLINE int http_header_count(http_t *this) {
	return !is_empty(this) ? this->num_headers : DATA_ERR;
}

FORCEINLINE http_status http_get_status(http_t *this) {
	return !is_empty(this) ? this->status : DATA_ERR;
}

FORCEINLINE string http_get_message(http_t *this) {
	return is_empty(this) ? "" : this->message;
}

FORCEINLINE string http_get_body(http_t *this) {
	return is_empty(this) ? "" : trim(this->body);
}

FORCEINLINE string http_get_url(http_t *this) {
	return is_empty(this) ? "" : this->uri;
}

FORCEINLINE string http_get_uri(http_t *this) {
	return is_empty(this) ? "" : this->url_to;
}

FORCEINLINE string http_get_header(http_t *this, string key) {
	char keyaddr[ARRAY_SIZE] = {0};
	snprintf(keyaddr, sizeof(keyaddr), "%s", key);
	return is_empty(this) || is_empty(this->headers) ? nullptr : (string)hash_get(this->headers, str_tolower(keyaddr));
}

string http_get_var(http_t *this, string key, string var) {
	if (is_empty(this))
		return null;

	int x, has_sect = 0, count = 1;
	string *sections, line;
	if (http_has_var(this, key, var)) {
		line = http_get_header(this, key);
		if (str_has(line, "; ")) {
			sections = str_split_ex(line, "; ", &count);
			has_sect = 1;
		} else {
			sections = (string *)line;
		}

		for (x = 0; x < count; x++) {
			string parts = sections[x], *variable = str_split_ex(parts, "=", nullptr);
			if (str_is(variable[0], var)) {
				if (has_sect)
					free(sections);

				bool found = !is_empty(variable[1]);
				if (found)
					snprintf(this->variable, sizeof(this->variable), "%s", variable[1]);

				free(variable);
				return found ? this->variable : nullptr;
			}
			free(variable);
		}
	}

	if (has_sect)
		free(sections);

	return "";
}

FORCEINLINE string http_get_param(http_t *this, string key) {
	return is_empty(this) ? "" : (string)hash_get(this->parameters, key);
}

void http_put_header(http_t *this, string key, string value, bool force_cap) {
    if (is_empty(this->headers)) {
		this->headers = hashtable_init(key_ops_auto, val_ops_auto, hash_lp_idx, ARRAY_SIZE);
        defer_free(this->headers);
    }

	hash_pair_t *kv = hash_put_str(this->headers, key, value);
}

FORCEINLINE bool http_has_header(http_t *this, string key) {
	char keyaddr[ARRAY_SIZE] = {0};
	snprintf(keyaddr, sizeof(keyaddr), "%s", key);
	return is_empty(this) || is_empty(this->headers) ? false : hash_has((hash_t *)this->headers, str_tolower(keyaddr));
}

FORCEINLINE bool http_has_var(http_t *this, string key, string var) {
    char temp[ARRAY_SIZE] = {0};

    snprintf(temp, ARRAY_SIZE, "%s%s", var, "=");
	return is_empty(this) || is_empty(this->headers) ? false : str_has(http_get_header(this, key), temp);
}

bool http_has_flag(http_t *this, string key, string flag) {
	char flag1[64] = {0};
	char flag2[64] = {0};
	char flag3[64] = {0};
    string value = http_get_header(this, key);

	snprintf(flag1, 64, "%s%s", flag, ";");
	snprintf(flag2, 64, "%s%s", flag, ",");
	snprintf(flag3, 64, "%s%s", flag, "\r\n");
	return is_empty(this) || is_empty(this->headers) ? false : str_has(value, flag1) || str_has(value, flag2) || str_has(value, flag3);
}

FORCEINLINE bool http_has_param(http_t *this, string key) {
	return is_empty(this) || is_empty(this->parameters) ? false : hash_has(this->parameters, key);
}

string http_cookie(http_t *this, string_t key, string_t value, string_t path,
	string_t expire, int64_t maxage, string_t samesite, string_t domain, bool secure) {
	char maxage_str[22] = {0};
	string cookie, cookies = str_cat_ex(4, key, "=", value, (this->action == HTTP_RESPONSE ? "; " : ", "));

	cookie = cookies;
	if (path) {
		cookies = str_cat_ex(4, cookie, "Path=", path, "; ");
		free(cookie);
		cookie = cookies;
	}

	if (expire) {
		cookies = str_cat_ex(4, cookie, "Expires=", expire, "; ");
		free(cookie);
		cookie = cookies;
	}

	if (maxage) {
		cookies = str_cat_ex(4, cookie, "Max-Age=", str_itoa(maxage), "; ");
		free(cookie);
		cookie = cookies;
	}

	if (domain) {
		cookies = str_cat_ex(4, cookie, "Domain=", domain, "; ");
		free(cookie);
		cookie = cookies;
	}

	if (samesite) {
		cookies = str_cat_ex(4, cookie, "SameSite=", samesite, "; ");
		free(cookie);
		cookie = cookies;
	}

	cookies = str_cat_ex(3, cookie, "HttpOnly", (secure ? "; Secure" CRLF : CRLF));
	free(cookie);
	$append(this->garbage, cookies);

	return cookies;
}
