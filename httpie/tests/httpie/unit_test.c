#include "../../src/lib/httpie_internal.h"
#include "../test_assert.h"

#if defined(_WIN32)
#   define TESTDIR "../../httpie/tests/httpie"
#else
#   define TESTDIR "../httpie/tests/httpie"
#endif

void check_func(int condition, const char *cond_txt, unsigned line);

static int s_total_tests = 0;
static int s_failed_tests = 0;

void check_func(int condition, const char *cond_txt, unsigned line)
{
	++s_total_tests;
	if (!condition) {
		printf("Fail on line %d: [%s]\n", line, cond_txt);
		++s_failed_tests;
	}
}

#define ASSERT(expr)                                                           \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
	} while (0)

#define REQUIRE(expr)                                                          \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
		if (!(expr)) {                                                         \
			exit(EXIT_FAILURE);                                                \
		}                                                                      \
	} while (0)

#define HTTP_PORT "8080"
#ifdef NO_SSL
#define HTTPS_PORT HTTP_PORT
#define LISTENING_ADDR "127.0.0.1:" HTTP_PORT
#else
#define HTTP_REDIRECT_PORT "8088"
#define HTTPS_PORT "8443"
#define LISTENING_ADDR                                                         \
	"127.0.0.1:" HTTP_PORT ",127.0.0.1:" HTTP_REDIRECT_PORT "r"                \
	",127.0.0.1:" HTTPS_PORT "s"
#endif

TEST(parse_http) {
	http_t *conn = http_for(null, 1.1);
	http_ini_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	conn->ctx = &ctx;
	char req1[] = "GET / HTTP/1.1\r\n\r\n";
	char req2[] = "BLAH / HTTP/1.1\r\n\r\n";
	char req3[] = "GET / HTTP/1.1\r\nBah\r\n";
	char req4[] = "GET / HTTP/1.1\r\nA: foo bar\r\nB: bar\r\nbaz:\r\n\r\n";
	char req5[] = "GET / HTTP/1.1\r\n\r\n";
	char req6[] = "G";
	char req7[] = " blah ";
	char req8[] = " HTTP/1.1 200 OK \n\n";
	char req9[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";

	conn->req.request_len = sizeof(req9);
	ASSERT_EQ(parse_http(HTTP_RESPONSE, conn, req9), sizeof(req9));
	ASSERT_EQ(conn->num_headers, 1);

	conn->req.request_len = sizeof(req1);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req1), sizeof(req1));
	ASSERT_EQ(strcmp(conn->req.http_version, "1.1"), 0);
	ASSERT_EQ(conn->num_headers, 0);

	conn->req.request_len = sizeof(req2);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req2), DATA_INVALID);
	conn->req.request_len = sizeof(req3);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req3), DATA_INVALID);
	conn->req.request_len = sizeof(req6);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req6), DATA_INVALID);
	conn->req.request_len = sizeof(req7);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req7), DATA_INVALID);
	conn->req.request_len = 0;
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, ""), DATA_INVALID);
	conn->req.request_len = sizeof(req8);
	ASSERT_EQ(parse_http(HTTP_RESPONSE, conn, req8), sizeof(req8));

	/* TODO(lsm): Fix this. Header value may span multiple lines. */
	conn->req.request_len = sizeof(req4);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req4), sizeof(req4));
	ASSERT_EQ(strcmp(conn->req.http_version, "1.1"), 0);

	ASSERT_EQ(conn->num_headers, 3);
	ASSERT_TRUE(str_is(http_get_header(conn, "A"),"foo bar"));
	ASSERT_TRUE(str_is(http_get_header(conn, "B"), "bar"));
	ASSERT_TRUE(str_is(http_get_header(conn, "baz"), ""));

	conn->req.request_len = sizeof(req5);
	ASSERT_EQ(parse_http(HTTP_REQUEST, conn, req5), sizeof(req5));
	ASSERT_EQ(strcmp(conn->method, "GET"), 0);
	ASSERT_EQ(strcmp(conn->req.http_version, "1.1"), 0);

	return 0;
}

TEST(should_keep_alive) {
	http_t *conn = http_for(null, 1.1);
	http_ini_t ctx;
	char req1[] = "GET / HTTP/1.1\r\n\r\n";
	char req2[] = "GET / HTTP/1.0\r\n\r\n";
	char req3[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
	char req4[] = "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

	memset(&ctx, 0, sizeof(ctx));
	conn->ctx = &ctx;
	conn->req.request_len = sizeof(req1);
	int len = parse_http(HTTP_REQUEST, conn, req1);
	ASSERT_EQ(len, sizeof(req1));

	ctx.host.config[ENABLE_KEEP_ALIVE] = "no";
	ASSERT_EQ(should_keep_alive(conn), 0);

	ctx.host.config[ENABLE_KEEP_ALIVE] = "yes";
	ASSERT_EQ(should_keep_alive(conn), 1);

	conn->req.must_close = 1;
	ASSERT_EQ(should_keep_alive(conn), 0);

	conn->req.must_close = 0;
	conn->req.request_len = sizeof(req2);
	parse_http(HTTP_REQUEST, conn, req2);
	ASSERT_EQ(should_keep_alive(conn), 0);

	conn->req.request_len = sizeof(req3);
	parse_http(HTTP_REQUEST, conn, req3);
	ASSERT_EQ(should_keep_alive(conn), 0);

	conn->req.request_len = sizeof(req4);
	parse_http(HTTP_REQUEST, conn, req4);
	ASSERT_EQ(should_keep_alive(conn), 1);

	conn->code = 401;
	ASSERT_EQ(should_keep_alive(conn), 0);

	conn->code = 200;
	conn->req.must_close = 1;
	ASSERT_EQ(should_keep_alive(conn), 0);
	return 0;
}

TEST(http_match_prefix) {
	ASSERT_EQ(http_match_prefix("/api", 4, "/api"), 4);
	ASSERT_EQ(http_match_prefix("/a/", 3, "/a/b/c"), 3);
	ASSERT_EQ(http_match_prefix("/a/", 3, "/ab/c"), -1);
	ASSERT_EQ(http_match_prefix("/*/", 3, "/ab/c"), 4);
	ASSERT_EQ(http_match_prefix("**", 2, "/a/b/c"), 6);
	ASSERT_EQ(http_match_prefix("/*", 2, "/a/b/c"), 2);
	ASSERT_EQ(http_match_prefix("*/*", 3, "/a/b/c"), 2);
	ASSERT_EQ(http_match_prefix("**/", 3, "/a/b/c"), 5);
	ASSERT_EQ(http_match_prefix("**.foo|**.bar", 13, "a.bar"), 5);
	ASSERT_EQ(http_pattern_match("a|b|c?", "cdef"), 2);
	ASSERT_EQ(http_pattern_match("a|b|cd", "cdef"), 2);
	ASSERT_EQ(http_match_prefix("a|?|cd", 6, "cdef"), 1);
	ASSERT_EQ(http_match_prefix("/a/**.cgi", 9, "/foo/bar/x.cgi"), -1);
	ASSERT_EQ(http_match_prefix("/a/**.cgi", 9, "/a/bar/x.cgi"), 12);
	ASSERT_EQ(http_match_prefix("**/", 3, "/a/b/c"), 5);
	ASSERT_EQ(http_match_prefix("**/$", 4, "/a/b/c"), -1);
	ASSERT_EQ(http_match_prefix("**/$", 4, "/a/b/"), 5);
	ASSERT_EQ(http_match_prefix("$", 1, ""), 0);
	ASSERT_EQ(http_match_prefix("$", 1, "x"), -1);
	ASSERT_EQ(http_match_prefix("*$", 2, "x"), 1);
	ASSERT_EQ(http_match_prefix("/$", 2, "/"), 1);
	ASSERT_EQ(http_match_prefix("**/$", 4, "/a/b/c"), -1);
	ASSERT_EQ(http_match_prefix("**/$", 4, "/a/b/"), 5);
	ASSERT_EQ(http_match_prefix("*", 1, "/hello/"), 0);
	ASSERT_EQ(http_match_prefix("**.a$|**.b$", 11, "/a/b.b/"), -1);
	ASSERT_EQ(http_match_prefix("**.a$|**.b$", 11, "/a/b.b"), 6);
	ASSERT_EQ(http_match_prefix("**.a$|**.b$", 11, "/a/B.A"), 6);
	ASSERT_EQ(http_match_prefix("**o$", 4, "HELLO"), 5);

	return 0;
}

TEST(remove_double_dots_slashes) {
	struct {
		char before[20], after[20];
	} data[] = {
		{"////a", "/a"},
		{"/.....", "/."},
		{"/......", "/"},
		{"...", "..."},
		{"/...///", "/./"},
		{"/a...///", "/a.../"},
		{"/.x", "/.x"},
		{"/\\", "/"},
		{"/a\\", "/a\\"},
		{"/a\\\\...", "/a\\."},
	};
	size_t i;

	for (i = 0; i < get_array_size(data); i++) {
		remove_double_dots_slashes(data[i].before);
		ASSERT_EQ(strcmp(data[i].before, data[i].after), 0);
	}

	return 0;
}

static char *read_file(const char *path, int *size)
{
	FILE *fp;
	struct stat st;
	char *data = NULL;
	if ((fp = fopen(path, "rb")) != NULL && !fstat(fileno(fp), &st)) {
		*size = (int)st.st_size;
		data = malloc(*size);
		ASSERT(data != NULL);
		ASSERT(fread(data, 1, *size, fp) == (size_t)*size);
		fclose(fp);
	}
	return data;
}

static long fetch_data_size = 1024 * 1024;
static char *fetch_data;
static const char *inmemory_file_data = "hi there";
static const char *upload_filename = "upload_test.txt";
#if 0
static const char *upload_filename2 = "upload_test2.txt";
#endif
static const char *upload_ok_message = "upload successful";

static const char *open_file_cb(http_t *conn, const char *path, size_t *size)
{
	(void)conn;
	if (!strcmp(path, "./blah")) {
		*size = strlen(inmemory_file_data);
		return inmemory_file_data;
	}
	return NULL;
}

static void upload_cb(http_t *conn, const char *path) {
	char *p1, *p2;
	int len1, len2;

	if (atoi(conn->req.query_string) == 1) {
		ASSERT(!strcmp(path, "./upload_test.txt"));
		ASSERT((p1 = read_file("../src/app/url.c", &len1)) != NULL);
		ASSERT((p2 = read_file(path, &len2)) != NULL);
		ASSERT(len1 == len2);
		ASSERT(memcmp(p1, p2, len1) == 0);
		free_ex(p1);
		free_ex(p2);
		remove(upload_filename);
	} else if (atoi(conn->req.query_string) == 2) {
		if (!strcmp(path, "./upload_test.txt")) {
			ASSERT((p1 = read_file("include/civetweb.h", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			free_ex(p1);
			free_ex(p2);
			remove(upload_filename);
		} else if (!strcmp(path, "./upload_test2.txt")) {
			ASSERT((p1 = read_file("README.md", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			free_ex(p1);
			free_ex(p2);
			remove(upload_filename);
		} else {
			ASSERT(0);
		}
	} else {
		ASSERT(0);
	}

	http_printf(conn, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", (int)strlen(upload_ok_message), upload_ok_message);
}

static int begin_request_handler_cb(http_t *conn) {
	int req_len = (int)(conn->content_length);
	const char *s_req_len = http_get_header(conn, "Content-Length");
	char *data;
	long to_write, write_now;
	int bytes_read, bytes_written;

	ASSERT(((req_len == -1) && (s_req_len == NULL)) ||
	       ((s_req_len != NULL) && (req_len = atol(s_req_len))));

	if (!strncmp(conn->url_to, "/data/", 6)) {
		if (!strcmp(conn->url_to + 6, "all")) {
			to_write = fetch_data_size;
		} else {
			to_write = atol(conn->uri + 6);
		}
		http_printf(conn,
		          "HTTP/1.1 200 OK\r\n"
		          "Connection: close\r\n"
		          "Content-Length: %li\r\n"
		          "Content-Type: text/plain\r\n\r\n",
		          to_write);
		while (to_write > 0) {
			write_now = to_write > fetch_data_size ? fetch_data_size : to_write;
			bytes_written = http_write(conn, fetch_data, write_now);
			ASSERT(bytes_written == write_now);
			if (bytes_written < 0) {
				ASSERT(0);
				break;
			}
			to_write -= bytes_written;
		}
		http_close_connection(conn);
		return 1;
	}

	if (!strcmp(conn->uri, "/content_length")) {
		if (req_len > 0) {
			data = malloc(req_len);
			assert(data != NULL);
			bytes_read = http_read(conn, data, req_len);
			ASSERT(bytes_read == req_len);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
			          "Content-Length: %d\r\n" /* The official definition */
			          "Content-Type: text/plain\r\n\r\n",
			          bytes_read);
			http_write(conn, data, bytes_read);
			free_ex(data);
		} else {
			data = malloc(1024);
			assert(data != NULL);
			bytes_read = http_read(conn, data, 1024);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
			          "Content-Type: text/plain\r\n\r\n");
			http_write(conn, data, bytes_read);

			free_ex(data);
		}
		http_close_connection(conn);
		return 1;
	}

	if (!strcmp(conn->uri, "/upload")) {
		ASSERT(conn->req.query_string != NULL);
		ASSERT(http_upload(conn, ".") == atoi(conn->req.query_string));
	}

	return 0;
}

static int log_message_cb(const http_t *conn, const char *msg)
{
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

int (*begin_request)(http_t *);
void (*end_request)(const http_t *, int reply_status_code);
int (*log_message)(const http_t *, const char *message);
int (*init_ssl)(void *ssl_context, void *user_data);
int (*websocket_connect)(const http_t *);
void (*websocket_ready)(http_t *);
int (*websocket_data)(http_t *, int bits, char *data, size_t data_len);
void (*connection_close)(http_t *);
const char *(*open_file)(const http_t *, const char *path, size_t *data_len);
void (*init_lua)(http_t *, void *lua_context);
void (*upload)(http_t *, const char *file_name);

static struct http_clb_s CALLBACKS;
static struct init_data init_ini;
static const char *OPTIONS[] = {
    "document_root",
    ".",
    "listening_ports",
    LISTENING_ADDR,
    "enable_keep_alive",
    "yes",
#ifndef NO_SSL
    "ssl_certificate",
    "../resources/ssl_cert.pem",
#endif
    NULL,
};

static void init_CALLBACKS() {
	memset(&CALLBACKS, 0, sizeof(CALLBACKS));
	memset(&init_ini, 0, sizeof(init_ini));
	CALLBACKS.start = begin_request_handler_cb;
	CALLBACKS.log_message = log_message_cb;
	CALLBACKS.open_file = open_file_cb;
	CALLBACKS.upload = upload_cb;
	init_ini.callbacks = &CALLBACKS;
	init_ini.configuration_options = OPTIONS;
};

static char *read_conn(http_t *conn, int *size)
{
	char buf[100], *data = NULL;
	int len;
	*size = 0;
	while ((len = http_read(conn, buf, sizeof(buf))) > 0) {
		*size += len;
		data = realloc(data, *size);
		ASSERT(data != NULL);
		memcpy(data + *size - len, buf, len);
	}
	return data;
}

static void ut_http_stop(http_ini_t *ctx) {
	http_stop(ctx);

	os_sleep(31000); /* This is required to ensure the operating system already
	                    allows to use the port again */
}

TEST_WITH(http_download, use_ssl) {
	const char *test_data = "123456789A123456789B";

	char *p1, *p2, ebuf[100];
	const char *h;
	int i, len1, len2, port;
	http_t *conn;
	http_ini_t *ctx;

	if (use_ssl) {
		port = atoi(HTTPS_PORT);
	} else {
		port = atoi(HTTP_PORT);
	}

	ctx = http_start(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS);

	ASSERT(ctx != NULL);

	ASSERT(http_download(NULL, port, use_ssl, ebuf, sizeof(ebuf), "%s", "") ==
	       NULL);
	ASSERT(http_download("localhost", 0, use_ssl, ebuf, sizeof(ebuf), "%s", "") ==
	       NULL);
	ASSERT(
	    http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "") ==
	    NULL);

	/* Fetch nonexistent file, should see 404 */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /gimbec HTTP/1.0\r\n\r\n")) != NULL);
	ASSERT(conn->code == (http_status)404);
	http_close_connection(conn);

	if (use_ssl) {
		ASSERT((conn = http_download("google.com", 443, 1, ebuf, sizeof(ebuf), "%s", "GET / HTTP/1.0\r\n\r\n")) != NULL);
		http_close_connection(conn);
	} else {
		ASSERT((conn = http_download("google.com", 80, 0, ebuf, sizeof(ebuf), "%s", "GET / HTTP/1.0\r\n\r\n")) != NULL);
		http_close_connection(conn);
	}

	/* Fetch unit_test.c, should succeed */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /unit_test.c HTTP/1.0\r\n\r\n")) != NULL);
	ASSERT(conn->code == (http_status)200);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT((p2 = read_file("unit_test.c", &len2)) != NULL);
	ASSERT(len1 == len2);
	ASSERT(memcmp(p1, p2, len1) == 0);
	free_ex(p1);
	free_ex(p2);
	http_close_connection(conn);

	/* Fetch in-memory file, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /blah HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(inmemory_file_data));
	ASSERT(memcmp(p1, inmemory_file_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Fetch in-memory data with no Content-Length, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /data/all HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT(conn->content_length == fetch_data_size);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)fetch_data_size);
	ASSERT(memcmp(p1, fetch_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Fetch in-memory data with no Content-Length, should succeed. */
	for (i = 0; i <= 1024 * /* 1024 * */ 8; i += (i < 2 ? 1 : i)) {
		ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "GET /data/%i HTTP/1.1\r\n\r\n", i)) != NULL);
		ASSERT(conn->content_length == i);
		len1 = -1;
		p1 = read_conn(conn, &len1);
		if (i == 0) {
			ASSERT(len1 == 0);
			ASSERT(p1 == 0);
		} else if (i <= fetch_data_size) {
			ASSERT(p1 != NULL);
			ASSERT(len1 == i);
			ASSERT(memcmp(p1, fetch_data, len1) == 0);
		} else {
			ASSERT(p1 != NULL);
			ASSERT(len1 == i);
			ASSERT(memcmp(p1, fetch_data, fetch_data_size) == 0);
		}

		free_ex(p1);
		http_close_connection(conn);
	}

	/* Fetch data with Content-Length, should succeed and return the defined
	 * length. */
	ASSERT((conn = http_download(
	            "localhost",
	            port,
	            use_ssl,
	            ebuf,
	            sizeof(ebuf),
	            "POST /content_length HTTP/1.1\r\nContent-Length: %u\r\n\r\n%s",
	            (unsigned)strlen(test_data),
	            test_data)) != NULL);
	h = http_get_header(conn, "Content-Length");
	ASSERT((h != NULL) && (atoi(h) == (int)strlen(test_data)));
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(conn->content_length == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	ASSERT(strcmp(conn->protocol, "HTTP/1.1") == 0);
	ASSERT(conn->code == 200);
	ASSERT(strcmp(conn->req.http_version, "1.1") == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* A POST request without Content-Length set is only valid, if the request
	 * used Transfer-Encoding: chunked. Otherwise, it is an HTTP protocol
	 * violation. Here we send a chunked request, the reply is not chunked. */
	ASSERT((conn = http_download("localhost",
	                           port,
	                           use_ssl,
	                           ebuf,
	                           sizeof(ebuf),
	                           "POST /content_length "
	                           "HTTP/1.1\r\n"
	                           "Transfer-Encoding: chunked\r\n"
	                           "\r\n%x\r\n%s\r\n0\r\n\r\n",
	                           (uint32_t)strlen(test_data),
	                           test_data)) != NULL);
	h = http_get_header(conn, "Content-Length");
	ASSERT(h == NULL);
	ASSERT(conn->content_length == -1);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Another chunked POST request with different chunk sizes. */
	ASSERT((conn = http_download("localhost",
	                           port,
	                           use_ssl,
	                           ebuf,
	                           sizeof(ebuf),
	                           "POST /content_length "
	                           "HTTP/1.1\r\n"
	                           "Transfer-Encoding: chunked\r\n\r\n"
	                           "2\r\n%c%c\r\n"
	                           "1\r\n%c\r\n"
	                           "2\r\n%c%c\r\n"
	                           "2\r\n%c%c\r\n"
	                           "%x\r\n%s\r\n"
	                           "0\r\n\r\n",
	                           test_data[0],
	                           test_data[1],
	                           test_data[2],
	                           test_data[3],
	                           test_data[4],
	                           test_data[5],
	                           test_data[6],
	                           (uint32_t)strlen(test_data + 7),
	                           test_data + 7)) != NULL);
	h = http_get_header(conn, "Content-Length");
	ASSERT(h == NULL);
	ASSERT(conn->content_length == -1);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Test non existent */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /non_exist HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT(strcmp(conn->protocol, "HTTP/1.1") == 0);
	ASSERT((conn->code == 404));
	ASSERT(strcmp(conn->message, "Not Found") == 0);
	http_close_connection(conn);

	if (use_ssl) {
		/* Test SSL redirect */
		ASSERT((conn = http_download("localhost", atoi(HTTP_REDIRECT_PORT), 0, ebuf, sizeof(ebuf), "%s", "GET /data/4711 HTTP/1.1\r\n\r\n")) != NULL);
		ASSERT((conn->code == 302));
		h = http_get_header(conn, "Location");
		ASSERT(h != NULL);
		ASSERT(strcmp(h, "https://127.0.0.1:" HTTPS_PORT "/data/4711") == 0);
		http_close_connection(conn);
	}

	/* Test new API */
	ebuf[0] = 1;
	conn = http_connect_client("localhost", port, use_ssl, ebuf, sizeof(ebuf));
	ASSERT(conn != NULL);
	ASSERT(ebuf[0] == 0);
	ASSERT(conn->content_length == 0);
	i = http_get_response(conn, ebuf, sizeof(ebuf), 1000);
	ASSERT(ebuf[0] != 0);
	ASSERT(conn->content_length == -1);
	http_printf(conn, "GET /index.html HTTP/1.1\r\n");
	http_printf(conn, "Host: www.example.com\r\n");
	http_printf(conn, "\r\n");
	i = http_get_response(conn, ebuf, sizeof(ebuf), 1000);
	ASSERT(ebuf[0] == 0);
	ASSERT(conn->content_length > 0);
	http_read(conn, ebuf, sizeof(ebuf));
	ASSERT(!strncmp(ebuf, "Error 404", 9));

	http_close_connection(conn);

	/* Stop the test server */
	ut_http_stop(ctx);
	return 0;
}

static int websocket_data_handler(const http_t *conn, int flags, char *data, size_t data_len, void *cbdata)
{
	(void)conn;
	(void)flags;
	(void)data;
	(void)data_len;
	(void)cbdata;
	return 1;
}

TEST_WITH(http_connect_websocket_client, use_ssl) {
	http_t *conn;
	char ebuf[100];
	int port;
	http_ini_t *ctx;

	if (use_ssl)
		port = atoi(HTTPS_PORT);
	else
		port = atoi(HTTP_PORT);
	ASSERT((ctx = http_start(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);

	/* Try to connect to our own server */
	/* Invalid port test */
	conn = http_connect_websocket_client("localhost",
	                                   0,
	                                   use_ssl,
	                                   ebuf,
	                                   sizeof(ebuf),
	                                   "/",
	                                   "http://localhost",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn == NULL);

	/* Should succeed, the default civetweb server should complete the handshake
	 */
	conn = http_connect_websocket_client("localhost",
	                                   port,
	                                   use_ssl,
	                                   ebuf,
	                                   sizeof(ebuf),
	                                   "/",
	                                   "http://localhost",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn != NULL);

	/* Try an external server test */
	port = 80;
	if (use_ssl) {
		port = 443;
	}

	/* Not a websocket server path */
	conn = http_connect_websocket_client("websocket.org",
	                                   port,
	                                   use_ssl,
	                                   ebuf,
	                                   sizeof(ebuf),
	                                   "/",
	                                   "http://websocket.org",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn == NULL);

	/* Invalid port test */
	conn = http_connect_websocket_client("echo.websocket.org",
	                                   0,
	                                   use_ssl,
	                                   ebuf,
	                                   sizeof(ebuf),
	                                   "/",
	                                   "http://websocket.org",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn == NULL);

	/* Should succeed, echo.websocket.org echos the data back */
	conn = http_connect_websocket_client("echo.websocket.org",
	                                   port,
	                                   use_ssl,
	                                   ebuf,
	                                   sizeof(ebuf),
	                                   "/",
	                                   "http://websocket.org",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn != NULL);

	ut_http_stop(ctx);
	return 0;
}

static int alloc_printf(char **out_buf, char *buf, size_t size, char *fmt, ...)
{
	va_list ap;
	int ret = 0;
	va_start(ap, fmt);
	ret = alloc_vprintf(out_buf, buf, size, fmt, ap);
	va_end(ap);
	return ret;
}

TEST(http_upload) {
	static const char *boundary = "OOO___MY_BOUNDARY___OOO";
	http_ini_t *ctx;
#if 0
    http_t *conn;
    char ebuf[100], buf[20], *file2_data;
    int file2_len;
#endif
	char *file_data, *post_data;
	int file_len, post_data_len;

	struct init_data init = {0};

	init.callbacks = &CALLBACKS;
	init.configuration_options = OPTIONS;
	ASSERT((ctx = http_start(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);

	/* Upload one file */
	ASSERT((file_data = read_file("unit_test.c", &file_len)) != NULL);
	post_data = NULL;
	post_data_len = alloc_printf(&post_data,
                                 NULL,
	                             0,
	                             "--%s\r\n"
	                             "Content-Disposition: form-data; "
	                             "name=\"file\"; "
	                             "filename=\"%s\"\r\n\r\n"
	                             "%.*s\r\n"
	                             "--%s--\r\n",
	                             boundary,
	                             upload_filename,
	                             file_len,
	                             file_data,
	                             boundary);
	ASSERT(post_data_len > 0);

#if 0 /* TODO (bel): ... */
    ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1,
        ebuf, sizeof(ebuf),
        "POST /upload?1 HTTP/1.1\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: multipart/form-data; "
        "boundary=%s\r\n\r\n"
        "%.*s", post_data_len, boundary,
        post_data_len, post_data)) != NULL);
    http_free(file_data), http_free(post_data);
    ASSERT(http_read(conn, buf, sizeof(buf)) == (int) strlen(upload_ok_message));
    ASSERT(memcmp(buf, upload_ok_message, strlen(upload_ok_message)) == 0);
    http_close_connection(conn);

    /* Upload two files */
    ASSERT((file_data = read_file("include/civetweb.h", &file_len)) != NULL);
    ASSERT((file2_data = read_file("README.md", &file2_len)) != NULL);
    post_data = NULL;
    post_data_len = alloc_printf(&post_data, 0,
        /* First file */
        "--%s\r\n"
        "Content-Disposition: form-data; "
        "name=\"file\"; "
        "filename=\"%s\"\r\n\r\n"
        "%.*s\r\n"

        /* Second file */
        "--%s\r\n"
        "Content-Disposition: form-data; "
        "name=\"file\"; "
        "filename=\"%s\"\r\n\r\n"
        "%.*s\r\n"

        /* Final boundary */
        "--%s--\r\n",
        boundary, upload_filename,
        file_len, file_data,
        boundary, upload_filename2,
        file2_len, file2_data,
        boundary);
    ASSERT(post_data_len > 0);
    ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1,
        ebuf, sizeof(ebuf),
        "POST /upload?2 HTTP/1.1\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: multipart/form-data; "
        "boundary=%s\r\n\r\n"
        "%.*s", post_data_len, boundary,
        post_data_len, post_data)) != NULL);
    http_free(file_data), http_free(file2_data), http_free(post_data);
    ASSERT(http_read(conn, buf, sizeof(buf)) == (int) strlen(upload_ok_message));
    ASSERT(memcmp(buf, upload_ok_message, strlen(upload_ok_message)) == 0);
    http_close_connection(conn);
#endif

	ut_http_stop(ctx);

	return 0;
}

TEST(set_throttle) {
	ASSERT(set_throttle(NULL, 0x0a000001, "/") == 0);
	ASSERT(set_throttle("10.0.0.0/8=20", 0x0a000001, "/") == 20);
	ASSERT(set_throttle("10.0.0.0/8=0.5k", 0x0a000001, "/") == 512);
	ASSERT(set_throttle("10.0.0.0/8=17m", 0x0a000001, "/") == 1048576 * 17);
	ASSERT(set_throttle("10.0.0.0/8=1x", 0x0a000001, "/") == 0);
	ASSERT(set_throttle("10.0.0.0/8=5,0.0.0.0/0=10", 0x0a000001, "/") == 10);
	ASSERT(set_throttle("10.0.0.0/8=5,/foo/**=7", 0x0a000001, "/index") == 5);
	ASSERT(set_throttle("10.0.0.0/8=5,/foo/**=7", 0x0a000001, "/foo/x") == 7);
	ASSERT(set_throttle("10.0.0.0/8=5,/foo/**=7", 0x0b000001, "/foxo/x") == 0);
	ASSERT(set_throttle("10.0.0.0/8=5,*=1", 0x0b000001, "/foxo/x") == 1);

	return 0;
}

TEST(http_next_option) {
	const char *p, *list = "x/8,/y**=1;2k,z";
	struct vec a, b;
	int i;

	ASSERT(http_next_option(NULL, &a, &b) == NULL);
	for (i = 0, p = list; (p = http_next_option(p, &a, &b)) != NULL; i++) {
		ASSERT(i != 0 || (a.ptr == list && a.len == 3 && b.len == 0));
		ASSERT(i != 1 || (a.ptr == list + 4 && a.len == 4 &&
		                  b.ptr == list + 9 && b.len == 4));
		ASSERT(i != 2 || (a.ptr == list + 14 && a.len == 1 && b.len == 0));
	}
	return 0;
}

TEST(http_stat) {
	static http_ini_t ctx;
	http_t fc;
	struct file file = STRUCT_FILE_INITIALIZER;
	ASSERT(!http_stat(fake_conn(&fc, &ctx), " does not exist ", &file));
	return 0;
}

TEST(alloc_vprintf) {
	char buf[BUF_LEN], *p = buf;

	ASSERT(alloc_printf(&p, buf, sizeof(buf), "%s", "hi") == 2);
	ASSERT(p == buf);
	ASSERT(alloc_printf(&p, buf, sizeof(buf), "%s", "") == 0);
	ASSERT(alloc_printf(&p, buf, sizeof(buf), "") == 0);

	/* Pass small buffer, make sure alloc_printf allocates */
	ASSERT(alloc_printf(&p, buf, 1, "%s", "hello") == 5);
	ASSERT(p != buf);
	free(p);

	return 0;
}

TEST(request_replies) {
	char ebuf[100];
	int i;
	http_t *conn;
	http_ini_t *ctx;
	static struct {
		const char *request, *reply_regex;
	} tests[] = {
	    {"GET hello.txt HTTP/1.0\r\nRange: bytes=3-5\r\n\r\n",
	     "^HTTP/1.1 206 Partial Content"},
	    {NULL, NULL},
	};

	ASSERT((ctx = http_start(1024, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);
	for (i = 0; tests[i].request != NULL; i++) {
		ASSERT((conn = http_download("localhost", atoi(HTTP_PORT), 0, ebuf, sizeof(ebuf), "%s", tests[i].request)) != NULL);
		http_close_connection(conn);
	}
	ut_http_stop(ctx);

	ASSERT((ctx = http_start(1024, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);
	for (i = 0; tests[i].request != NULL; i++) {
		ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1, ebuf, sizeof(ebuf), "%s", tests[i].request)) != NULL);
		http_close_connection(conn);
	}
	ut_http_stop(ctx);
	return 0;
}

static int request_test_handler(http_t *conn, void *cbdata) {
	int i;
	char chunk_data[32];

	ASSERT(cbdata == (void *)7);
	strcpy(chunk_data, "123456789A123456789B123456789C");

	http_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Transfer-Encoding: chunked\r\n"
	          "Content-Type: text/plain\r\n\r\n");

	for (i = 0; i < 20; i++) {
		http_printf(conn, "%x\r\n", i);
		http_write(conn, chunk_data, i);
		http_printf(conn, "\r\n");
	}

	http_printf(conn, "0\r\n\r\n");

	return 1;
}

TEST(http_route) {
	char ebuf[100];
	http_ini_t *ctx;
	http_t *conn;
	char uri[64];
	int i;
	const char *request = "GET /U7 HTTP/1.0\r\n\r\n";

	ctx = http_start(0, NULL, NULL, (const options_ini_t **)OPTIONS);
	ASSERT(ctx != NULL);

	for (i = 0; i < 1000; i++) {
		sprintf(uri, "/U%u", i);
		http_route(ctx, uri, request_test_handler, NULL);
	}

	for (i = 500; i < 800; i++) {
		sprintf(uri, "/U%u", i);
		http_route(ctx, uri, NULL, (void *)1);
	}

	for (i = 600; i >= 0; i--) {
		sprintf(uri, "/U%u", i);
		http_route(ctx, uri, NULL, (void *)2);
	}

	for (i = 750; i <= 1000; i++) {
		sprintf(uri, "/U%u", i);
		http_route(ctx, uri, NULL, (void *)3);
	}

	for (i = 5; i < 9; i++) {
		sprintf(uri, "/U%u", i);
		http_route(ctx, uri, request_test_handler, (void *)(intptr_t)i);
	}

	conn = http_download( "localhost", atoi(HTTP_PORT), 0, ebuf, sizeof(ebuf), "%s", request);
	ASSERT(conn != NULL);
	delay(10000);
	http_close_connection(conn);

	ut_http_stop(ctx);
	return 0;
}

static int api_callback(http_t *conn) {
	char post_data[100] = "";

	ASSERT(conn->client.protocol == 123);
	ASSERT(conn->num_headers == 2);
	ASSERT(strcmp(http_get_header(conn, "host"), "blah.com") == 0);
	ASSERT(http_read(conn, post_data, sizeof(post_data)) == 3);
	ASSERT(memcmp(post_data, "b=1", 3) == 0);
	ASSERT(conn->req.query_string != NULL);
	ASSERT(conn->req.remote_addr[0] != 0);
	ASSERT(conn->req.remote_port > 0);
	ASSERT(strcmp(conn->req.http_version, "1.0") == 0);

	http_printf(conn, "HTTP/1.0 200 OK\r\n\r\n");
	return 1;
}

TEST(api_calls) {
	char ebuf[100];
	struct http_clb_s callbacks;
	http_t *conn;
	http_ini_t *ctx;
	static const char *request =
	    "POST /?a=%20&b=&c=xx HTTP/1.0\r\n"
	    "Host:  blah.com\n"     /* More spaces before */
	    "content-length: 3\r\n" /* Lower case header name */
	    "\r\nb=123456"; /* Content size > content-length, test for http_read() */

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.start = api_callback;
	ASSERT((ctx = http_start(0, &callbacks, (void *)123, (const options_ini_t **)OPTIONS)) != NULL);
	ASSERT((conn = http_download("localhost", atoi(HTTP_PORT), 0, ebuf, sizeof(ebuf), "%s", request)) != NULL);
	http_close_connection(conn);
	ut_http_stop(ctx);
	return 0;
}

TEST(http_url_decode) {
	char buf[100];

	ASSERT(http_url_decode("foo", 3, buf, 3, 0) == -1); /* No space for \0 */
	ASSERT(http_url_decode("foo", 3, buf, 4, 0) == 3);
	ASSERT(strcmp(buf, "foo") == 0);

	ASSERT(http_url_decode("a+", 2, buf, sizeof(buf), 0) == 2);
	ASSERT(strcmp(buf, "a+") == 0);

	ASSERT(http_url_decode("a+", 2, buf, sizeof(buf), 1) == 2);
	ASSERT(strcmp(buf, "a ") == 0);

	ASSERT(http_url_decode("%61", 1, buf, sizeof(buf), 1) == 1);
	ASSERT(strcmp(buf, "%") == 0);

	ASSERT(http_url_decode("%61", 2, buf, sizeof(buf), 1) == 2);
	ASSERT(strcmp(buf, "%6") == 0);

	ASSERT(http_url_decode("%61", 3, buf, sizeof(buf), 1) == 1);
	ASSERT(strcmp(buf, "a") == 0);
	return 0;
}

TEST(parse_port_string) {
	static const char *valid[] = {
		"0",
		"1",
		"1s",
		"1r",
		"1.2.3.4:1",
		"1.2.3.4:1s",
		"1.2.3.4:1r",
		"[::1]:123",
		"[3ffe:2a00:100:7031::1]:900",
		NULL,
	};
	static const char *invalid[] = {
	    "99999", "1k", "1.2.3", "1.2.3.4:", "1.2.3.4:2p", NULL};
	struct server_socket_s so;
	int ip_family;
	struct vec vec;
	int i;

	ip_family = 123;
	for (i = 0; valid[i] != NULL; i++) {
		vec.ptr = valid[i];
		vec.len = strlen(vec.ptr);
		ASSERT(parse_port_string(&vec, &so, &ip_family) != 0);
	}

	for (i = 0; invalid[i] != NULL; i++) {
		vec.ptr = invalid[i];
		vec.len = strlen(vec.ptr);
		ASSERT(parse_port_string(&vec, &so, &ip_family) == 0);
	}

	return 0;
}

TEST(list) {
	char buffer[512];
	FILE *f;
	http_ini_t *ctx;
	int i, unused, result = 0;

#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
	unused = chdir(TESTDIR);

	/* print headline */
	cout("HttPie %s unit test\n\n", httpie_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */
	f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("unit_test.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain unit_test.c\n");
	}

	/* test local functions */
	EXEC_TEST(http_match_prefix);
	EXEC_TEST(remove_double_dots_slashes);
	EXEC_TEST(should_keep_alive);
	EXEC_TEST(parse_http);
	EXEC_TEST(http_next_option);
	EXEC_TEST(set_throttle);
	EXEC_TEST(http_url_decode);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
	return result;

	/* start stop server */
	ctx = http_start(0, NULL, NULL, NULL);
	REQUIRE(ctx != NULL);
	os_sleep(10000);
	ut_http_stop(ctx);

	/* create test data */
	fetch_data = (char *)malloc(fetch_data_size);
	for (i = 0; i < fetch_data_size; i++) {
		fetch_data[i] = 'a' + i % 10;
	}

	/* tests with network access */
	init_CALLBACKS();
	EXEC_TEST(parse_port_string);
	EXEC_TEST_WITH(http_download, 0);
	EXEC_TEST_WITH(http_download, 1);

	EXEC_TEST_WITH(http_connect_websocket_client, 0);
	EXEC_TEST_WITH(http_connect_websocket_client, 1);

	EXEC_TEST(http_upload);
	EXEC_TEST(http_stat);
	EXEC_TEST(request_replies);
	EXEC_TEST(api_calls);
	EXEC_TEST(http_route);

	/* test completed */
	free(fetch_data);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
