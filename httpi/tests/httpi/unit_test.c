#include "../../src/lib/httpi_internal.h"
#include "../test_assert.h"
#include <openssl/md5.h>

#if defined(_WIN32)
#   define TESTDIR "../../httpi/tests/httpi"
#else
#   define TESTDIR "../httpi/tests/httpi"
#endif

static string_t const mon_short_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

void check_func(int condition, string_t cond_txt, unsigned line);

static int s_total_tests = 0;
static int s_failed_tests = 0;

void check_func(int condition, string_t cond_txt, unsigned line)
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

static char *read_file(string_t path, int *size) {
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
static string_t inmemory_file_data = "hi there";
static string_t upload_filename = "upload_test.txt";
#if 0
static string_t upload_filename2 = "upload_test2.txt";
#endif
static string_t upload_ok_message = "upload successful";

static string_t open_file_cb(http_t *conn, string_t path, size_t *size)
{
	(void)conn;
	if (!strcmp(path, "./blah")) {
		*size = strlen(inmemory_file_data);
		return inmemory_file_data;
	}
	return NULL;
}

static void upload_cb(http_t *conn, string_t path) {
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
			ASSERT((p1 = read_file("include/httpi.h", &len1)) != NULL);
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
	string_t s_req_len = http_get_header(conn, "Content-Length");
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

static int log_message_cb(const http_t *conn, string_t msg)
{
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

int (*begin_request)(http_t *);
void (*end_request)(const http_t *, int reply_status_code);
int (*log_message)(const http_t *, string_t message);
int (*init_ssl)(void *ssl_context, void *user_data);
int (*websocket_connect)(const http_t *);
void (*websocket_ready)(http_t *);
int (*websocket_data)(http_t *, int bits, char *data, size_t data_len);
void (*connection_close)(http_t *);
string_t (*open_file)(const http_t *, string_t path, size_t *data_len);
void (*init_lua)(http_t *, void *lua_context);
void (*upload)(http_t *, string_t file_name);

static struct http_clb_s CALLBACKS;
static string_t OPTIONS[] = {
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
	CALLBACKS.start = begin_request_handler_cb;
	CALLBACKS.log_message = log_message_cb;
	CALLBACKS.open_file = open_file_cb;
	CALLBACKS.upload = upload_cb;
};

static char *read_conn(http_t *conn, int *size) {
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

TEST_WITH(http_download, use_ssl) {
	string_t test_data = "123456789A123456789B";

	char *p1, *p2, ebuf[100];
	string_t h;
	int i, len1, len2, port;
	http_t *conn;
	http_ini_t *ctx;

	if (use_ssl) {
		port = atoi(HTTPS_PORT);
	} else {
		port = atoi(HTTP_PORT);
	}

	ctx = http_setup(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS);

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

	/* Fetch _in-memory file, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /blah HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(inmemory_file_data));
	ASSERT(memcmp(p1, inmemory_file_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Fetch _in-memory data with no Content-Length, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, ebuf, sizeof(ebuf), "%s", "GET /data/all HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT(conn->content_length == fetch_data_size);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)fetch_data_size);
	ASSERT(memcmp(p1, fetch_data, len1) == 0);
	free_ex(p1);
	http_close_connection(conn);

	/* Fetch _in-memory data with no Content-Length, should succeed. */
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
	http_stop(ctx);
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
	ASSERT((ctx = http_setup(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);

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

	/* Should succeed, the default `HttPi` server should complete the handshake
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

	http_stop(ctx);
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
	static string_t boundary = "OOO___MY_BOUNDARY___OOO";
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
	ASSERT((ctx = http_setup(0, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);

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
    ASSERT((file_data = read_file("include/httpi.h", &file_len)) != NULL);
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

	http_stop(ctx);

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
	string_t p, list = "x/8,/y**=1;2k,z";
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
	ASSERT_EQ(http_stat(fake_conn(&fc, &ctx), " does not exist ", &file), 0);
	ASSERT_EQ(http_stat(fake_conn(&fc, &ctx), "hello.txt", &file), 1);
	return 0;
}

TEST(mask_data) {
	char _in[1024] = {0};
	char out[1024] = {0};
	int i;

	uint32_t mask = 0x61626364;
	/* TODO: adapt test for big endian */
	ASSERT_EQ((*(unsigned char *)&mask), 0x64u);

	memset(_in, 0, sizeof(_in));
	memset(out, 99, sizeof(out));

	mask_data(_in, sizeof(out), mask, out);
	ASSERT_EQ(!memcmp(out, _in, sizeof(out)), 0);

	for (i = 0; i < 1024; i++) {
		_in[i] = (char)((unsigned char)i);
	}

	mask_data(_in, 107, mask, out);
	ASSERT_EQ(!memcmp(out, _in, 107), 0);

	memset(out, 0, sizeof(out));
	mask_data(_in, 256, 0x01010101, out);
	for (i = 0; i < 256; i++) {
		ASSERT((int)((unsigned char)out[i]) ==
			(int)(((unsigned char)_in[i]) ^ (char)1u));
	}

	for (i = 256; i < (int)sizeof(out); i++) {
		ASSERT((int)((unsigned char)out[i]) == (int)0);
	}

	/* TODO: check this for big endian */
	mask_data(_in, 5, 0x01020304, out);
	ASSERT_UEQ((unsigned char)out[0], 0u ^ 4u);
	ASSERT_UEQ((unsigned char)out[1], 1u ^ 3u);
	ASSERT_UEQ((unsigned char)out[2], 2u ^ 2u);
	ASSERT_UEQ((unsigned char)out[3], 3u ^ 1u);
	ASSERT_UEQ((unsigned char)out[4], 4u ^ 4u);

	return 0;
}

TEST(parse_date_str) {
	time_t now = time(0);
	struct tm *tm = gmtime(&now);
	char date[64] = {0};
	unsigned long i;

	ASSERT_UEQ((unsigned long)parse_date_str("1/Jan/1970 00:01:02"),
		62ul);
	ASSERT_UEQ((unsigned long)parse_date_str("1 Jan 1970 00:02:03"),
		123ul);
	ASSERT_UEQ((unsigned long)parse_date_str("1-Jan-1970 00:03:04"),
		184ul);
	ASSERT_UEQ((unsigned long)parse_date_str(
		"Xyz, 1 Jan 1970 00:04:05"),
		245ul);

	http_gmt_time_str(date, sizeof(date), &now);
	ASSERT_UEQ((uintmax_t)parse_date_str(date), (uintmax_t)now);
	sprintf(date,
		"%02u %s %04u %02u:%02u:%02u",
		tm->tm_mday,
		mon_short_names[tm->tm_mon],
		tm->tm_year + 1900,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec);
	ASSERT_UEQ((uintmax_t)parse_date_str(date), (uintmax_t)now);

	http_gmt_time_str(date, 1, NULL);
	ASSERT_STR(date, "");
	http_gmt_time_str(date, 6, NULL);
	ASSERT_STR(date,
		"Thu, "); /* part of "Thu, 01 Jan 1970 00:00:00 GMT" */
	http_gmt_time_str(date, sizeof(date), NULL);
	ASSERT_STR(date, "Thu, 01 Jan 1970 00:00:00 GMT");

	for (i = 2ul; i < 0x8000000ul; i += i / 2) {
		now = (time_t)i;

		http_gmt_time_str(date, sizeof(date), &now);
		ASSERT((uintmax_t)parse_date_str(date) == (uintmax_t)now);

		tm = gmtime(&now);
		sprintf(date,
			"%02u-%s-%04u %02u:%02u:%02u",
			tm->tm_mday,
			mon_short_names[tm->tm_mon],
			tm->tm_year + 1900,
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec);
		ASSERT((uintmax_t)parse_date_str(date) == (uintmax_t)now);
	}

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
		string_t request, reply_regex;
	} tests[] = {
	    {"GET hello.txt HTTP/1.0\r\nRange: bytes=3-5\r\n\r\n",
	     "^HTTP/1.1 206 Partial Content"},
	    {NULL, NULL},
	};

	ASSERT((ctx = http_setup(1024, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);
	for (i = 0; tests[i].request != NULL; i++) {
		ASSERT((conn = http_download("localhost", atoi(HTTP_PORT), 0, ebuf, sizeof(ebuf), "%s", tests[i].request)) != NULL);
		http_close_connection(conn);
	}
	http_stop(ctx);

	ASSERT((ctx = http_setup(1024, &CALLBACKS, NULL, (const options_ini_t **)OPTIONS)) != NULL);
	for (i = 0; tests[i].request != NULL; i++) {
		ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1, ebuf, sizeof(ebuf), "%s", tests[i].request)) != NULL);
		http_close_connection(conn);
	}
	http_stop(ctx);
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
	string_t request = "GET /U7 HTTP/1.0\r\n\r\n";

	ctx = http_setup(0, NULL, NULL, (const options_ini_t **)OPTIONS);
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

	http_stop(ctx);
	return 0;
}

static int api_callback(http_t *conn) {
	char post_data[100] = "";

	ASSERT(conn->client->protocol == 123);
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
	static string_t request =
	    "POST /?a=%20&b=&c=xx HTTP/1.0\r\n"
	    "Host:  blah.com\n"     /* More spaces before */
	    "content-length: 3\r\n" /* Lower case header name */
	    "\r\nb=123456"; /* Content size > content-length, test for http_read() */

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.start = api_callback;
	ASSERT((ctx = http_setup(0, &callbacks, (void *)123, (const options_ini_t **)OPTIONS)) != NULL);
	ASSERT((conn = http_download("localhost", atoi(HTTP_PORT), 0, ebuf, sizeof(ebuf), "%s", request)) != NULL);
	http_close_connection(conn);
	http_stop(ctx);
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

TEST(http_md5) {
	MD5_CTX md5_state;
	unsigned char md5_val[16 + 1];
	char md5_str[32 + 1];
	string_t test_str = "The quick brown fox jumps over the lazy dog";

	md5_val[16] = 0;
	MD5_Init(&md5_state);
	MD5_Final(md5_val, &md5_state);
	ASSERT(strcmp((string_t)md5_val,
		"\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9"
		"\x80\x09\x98\xec\xf8\x42\x7e") == 0);
	sprintf(md5_str,
		"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		md5_val[0],
		md5_val[1],
		md5_val[2],
		md5_val[3],
		md5_val[4],
		md5_val[5],
		md5_val[6],
		md5_val[7],
		md5_val[8],
		md5_val[9],
		md5_val[10],
		md5_val[11],
		md5_val[12],
		md5_val[13],
		md5_val[14],
		md5_val[15]);
	ASSERT(strcmp(md5_str, "d41d8cd98f00b204e9800998ecf8427e") == 0);

	http_md5(md5_str, "", NULL);
	ASSERT(strcmp(md5_str, "d41d8cd98f00b204e9800998ecf8427e") == 0);

	MD5_Init(&md5_state);
	MD5_Update(&md5_state, (const unsigned char *)test_str, strlen(test_str));
	MD5_Final(md5_val, &md5_state);
	sprintf(md5_str,
		"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		md5_val[0],
		md5_val[1],
		md5_val[2],
		md5_val[3],
		md5_val[4],
		md5_val[5],
		md5_val[6],
		md5_val[7],
		md5_val[8],
		md5_val[9],
		md5_val[10],
		md5_val[11],
		md5_val[12],
		md5_val[13],
		md5_val[14],
		md5_val[15]);
	ASSERT(strcmp(md5_str, "9e107d9d372bb6826bd81d3542a419d6") == 0);

	http_md5(md5_str, test_str, NULL);
	ASSERT(strcmp(md5_str, "9e107d9d372bb6826bd81d3542a419d6") == 0);

	http_md5(md5_str,
		"The",
		" ",
		"quick brown fox",
		"",
		" jumps ",
		"over the lazy dog",
		"",
		"",
		NULL);
	ASSERT(strcmp(md5_str, "9e107d9d372bb6826bd81d3542a419d6") == 0);

	http_md5(md5_str, "HttPie", NULL);
	ASSERT(strcmp(md5_str, "1a3e4874dfb17d96f8f8379adf7bd574") == 0);

	return 0;
}

TEST(str_encode64) {
	const char *_in[] = {"a", "ab", "abc", "abcd", NULL};
	const char *out[] = {"YQ==", "YWI=", "YWJj", "YWJjZA=="};
	char buf[100];
	int i;

	for (i = 0; _in[i] != NULL; i++) {
		str_encode64((unsigned char *)_in[i], buf, sizeof(buf));
		ASSERT(!strcmp(buf, out[i]));
	}

	return 0;
}

TEST(http_get_valid_options) {
	const options_ini_t *config_options = http_get_valid_options();
	/* Check size of config_options vs. number of options in enum. */
	ASSERT_NULL(config_options[NUM_OPTIONS].name);
	ASSERT_EQ((int)INI_TYPE_UNKNOWN,
		config_options[NUM_OPTIONS].type);

	/* Check option enums vs. option names. */
	/* Check if the order in
	* static `options_ini_t` config_options[]
	* is the same as in the option enum
	* This test allows to reorder config_options and the enum,
	* and check if the order is still consistent. */
	ASSERT_STR("max_fd", config_options[MAX_FD].name);
	ASSERT_STR("cgi_pattern", config_options[CGI_EXTENSIONS].name);
	ASSERT_STR("cgi_environment", config_options[CGI_ENVIRONMENT].name);
	ASSERT_STR("put_delete_auth_file",
		config_options[PUT_DELETE_PASSWORDS_FILE].name);
	ASSERT_STR("cgi_interpreter", config_options[CGI_INTERPRETER].name);
	ASSERT_STR("protect_uri", config_options[PROTECT_URI].name);
	ASSERT_STR("authentication_domain",
		config_options[AUTHENTICATION_DOMAIN].name);
	ASSERT_STR("enable_auth_domain_check",
		config_options[ENABLE_AUTH_DOMAIN_CHECK].name);
	ASSERT_STR("ssi_pattern", config_options[SSI_EXTENSIONS].name);
	ASSERT_STR("throttle", config_options[THROTTLE].name);
	ASSERT_STR("access_log_file", config_options[ACCESS_LOG_FILE].name);
	ASSERT_STR("enable_directory_listing",
		config_options[ENABLE_DIRECTORY_LISTING].name);
	ASSERT_STR("error_log_file", config_options[ERROR_LOG_FILE].name);
	ASSERT_STR("global_auth_file",
		config_options[GLOBAL_PASSWORDS_FILE].name);
	ASSERT_STR("index_files", config_options[INDEX_FILES].name);
	ASSERT_STR("enable_keep_alive",
		config_options[ENABLE_KEEP_ALIVE].name);
	ASSERT_STR("access_control_list",
		config_options[ACCESS_CONTROL_LIST].name);
	ASSERT_STR("extra_mime_types", config_options[EXTRA_MIME_TYPES].name);
	ASSERT_STR("listening_ports", config_options[LISTENING_PORTS].name);
	ASSERT_STR("document_root", config_options[DOCUMENT_ROOT].name);
	ASSERT_STR("fallback_document_root",
		config_options[FALLBACK_DOCUMENT_ROOT].name);
	ASSERT_STR("ssl_certificate", config_options[SSL_CERTIFICATE].name);
	ASSERT_STR("ssl_certificate_chain",
		config_options[SSL_CERTIFICATE_CHAIN].name);
	ASSERT_STR("num_threads", config_options[NUM_THREADS].name);
	ASSERT_STR("prespawn_threads", config_options[PRESPAWN_THREADS].name);
	ASSERT_STR("run_as_user", config_options[RUN_AS_USER].name);
	ASSERT_STR("url_rewrite_patterns",
		config_options[URL_REWRITE_PATTERN].name);
	ASSERT_STR("hide_files_patterns", config_options[HIDE_FILES].name);
	ASSERT_STR("request_timeout_ms",
		config_options[REQUEST_TIMEOUT].name);
	ASSERT_STR("keep_alive_timeout_ms",
		config_options[KEEP_ALIVE_TIMEOUT].name);
	ASSERT_STR("linger_timeout_ms", config_options[LINGER_TIMEOUT].name);
	ASSERT_STR("listen_backlog",
		config_options[LISTEN_BACKLOG_SIZE].name);
	ASSERT_STR("ssl_verify_peer",
		config_options[SSL_DO_VERIFY_PEER].name);
	ASSERT_STR("ssl_ca_path", config_options[SSL_CA_PATH].name);
	ASSERT_STR("ssl_ca_file", config_options[SSL_CA_FILE].name);
	ASSERT_STR("ssl_verify_depth", config_options[SSL_VERIFY_DEPTH].name);
	ASSERT_STR("ssl_default_verify_paths",
		config_options[SSL_DEFAULT_VERIFY_PATHS].name);
	ASSERT_STR("ssl_cipher_list", config_options[SSL_CIPHER_LIST].name);
	ASSERT_STR("ssl_protocol_version",
		config_options[SSL_PROTOCOL_VERSION].name);
	ASSERT_STR("ssl_short_trust", config_options[SSL_SHORT_TRUST].name);

	ASSERT_STR("websocket_timeout_ms",
		config_options[WEBSOCKET_TIMEOUT].name);
	ASSERT_STR("enable_websocket_ping_pong",
		config_options[ENABLE_WEBSOCKET_PING_PONG].name);

	ASSERT_STR("decode_url", config_options[DECODE_URL].name);
	ASSERT_STR("decode_query_string",
		config_options[DECODE_QUERY_STRING].name);

	ASSERT_STR("quickjs_script_pattern",
		config_options[QUICKJS_SCRIPT_EXTENSIONS].name);
	ASSERT_STR("websocket_root", config_options[WEBSOCKET_ROOT].name);
	ASSERT_STR("fallback_websocket_root",
		config_options[FALLBACK_WEBSOCKET_ROOT].name);

	ASSERT_STR("access_control_allow_origin",
		config_options[ACCESS_CONTROL_ALLOW_ORIGIN].name);
	ASSERT_STR("access_control_allow_methods",
		config_options[ACCESS_CONTROL_ALLOW_METHODS].name);
	ASSERT_STR("access_control_allow_headers",
		config_options[ACCESS_CONTROL_ALLOW_HEADERS].name);
	ASSERT_STR("error_pages", config_options[ERROR_PAGES].name);
	ASSERT_STR("tcp_nodelay", config_options[CONFIG_TCP_NODELAY].name);

	ASSERT_STR("static_file_max_age",
		config_options[STATIC_FILE_MAX_AGE].name);
	ASSERT_STR("strict_transport_security_max_age",
		config_options[STRICT_HTTPS_MAX_AGE].name);
	ASSERT_STR("allow_sendfile_call",
		config_options[ALLOW_SENDFILE_CALL].name);

	ASSERT_STR("additional_header",
		config_options[ADDITIONAL_HEADER].name);
	ASSERT_STR("max_request_size", config_options[MAX_REQUEST_SIZE].name);
	ASSERT_STR("allow_index_script_resource",
		config_options[ALLOW_INDEX_SCRIPT_SUB_RES].name);

	return 0;
}

TEST(http_get_uri_type) {
	/* is_valid_uri is superseded by http_get_uri_type */
	ASSERT_EQ(2, http_get_uri_type("/api"));
	ASSERT_EQ(2, http_get_uri_type("/api/"));
	ASSERT_EQ(2,
		http_get_uri_type("/some/long/path%20with%20space/file.xyz"));
	ASSERT_EQ(0, http_get_uri_type("api"));
	ASSERT_EQ(1, http_get_uri_type("*"));
	ASSERT_EQ(0, http_get_uri_type("*xy"));
	ASSERT_EQ(3, http_get_uri_type("http://somewhere/"));
	ASSERT_EQ(3, http_get_uri_type("https://somewhere/some/file.html"));
	ASSERT_EQ(4, http_get_uri_type("http://somewhere:8080/"));
	ASSERT_EQ(4, http_get_uri_type("https://somewhere:8080/some/file.html"));

	return 0;
}

TEST(http_builtin_mime_type) {
	ASSERT_STR(http_builtin_mime_type("x.txt"), "text/plain");
	ASSERT_STR(http_builtin_mime_type("x.html"), "text/html");
	ASSERT_STR(http_builtin_mime_type("x.HTML"), "text/html");
	ASSERT_STR(http_builtin_mime_type("x.hTmL"), "text/html");
	ASSERT_STR(http_builtin_mime_type("/abc/def/ghi.htm"), "text/html");
	ASSERT_STR(http_builtin_mime_type("x.unknown_extention_xyz"),
		"text/plain");

	return 0;
}


TEST(parse_port_string) {
	/* Adapted from unit_test.c */
	/* Copyright (c) 2013-2020 the Civetweb developers */
	/* Copyright (c) 2004-2013 Sergey Lyubka */
	struct t_test_parse_port_string {
		const char *port_string;
		int valid;
		int ip_family;
		uint16_t port_num;
	};

	static struct t_test_parse_port_string testdata[] =
	{{"0", 1, 4, 0},
	  {"1", 1, 4, 1},
	  {"65535", 1, 4, 65535},
	  {"65536", 0, 0, 0},

	  {"1s", 1, 4, 1},
	  {"1r", 1, 4, 1},
	  {"1k", 0, 0, 0},

	  {"1.2.3", 0, 0, 0},
	  {"1.2.3.", 0, 0, 0},
	  {"1.2.3.4", 0, 0, 0},
	  {"1.2.3.4:", 0, 0, 0},

	  {"1.2.3.4:0", 1, 4, 0},
	  {"1.2.3.4:1", 1, 4, 1},
	  {"1.2.3.4:65535", 1, 4, 65535},
	  {"1.2.3.4:65536", 0, 0, 0},

	  {"1.2.3.4:1s", 1, 4, 1},
	  {"1.2.3.4:1r", 1, 4, 1},
	  {"1.2.3.4:1k", 0, 0, 0},

	  /* IPv6 config */
	  {"[::1]:123", 1, 6, 123},
	  {"[::]:80", 1, 6, 80},
	  {"[3ffe:2a00:100:7031::1]:900", 1, 6, 900},

	  /* IPv4 + IPv6 config */
	  {"+80", 1, 4 + 6, 80},

	  {NULL, 0, 0, 0}};

	http_socket *so = calloc(1, sizeof(http_socket));
	struct vec vec;
	int ip_family;
	int i, ret;

	for (i = 0; testdata[i].port_string != NULL; i++) {
		vec.ptr = testdata[i].port_string;
		vec.len = strlen(vec.ptr);

		ip_family = 123;
		ret = parse_port_string(&vec, so, &ip_family);

		if ((ret != testdata[i].valid)
			|| (ip_family != testdata[i].ip_family)) {
			cerr("Port string [%s]: "
				"expected valid=%i, family=%i; \n"
				"got valid=%i, family=%i\n",
				testdata[i].port_string,
				testdata[i].valid,
				testdata[i].ip_family,
				ret,
				ip_family);
		}

		if (ip_family == 4)
			ASSERT((int)so->lsa.sin.sin_family == (int)AF_INET);

		if (ip_family == 6)
			ASSERT((int)so->lsa.sin.sin_family == (int)AF_INET6);

		/* Test valid strings only */
		if (ret)
			ASSERT(htons(so->lsa.sin.sin_port) == testdata[i].port_num);
	}

	/* special case: localhost can be ipv4 or ipv6 */
	vec.ptr = "localhost:123";
	vec.len = strlen(vec.ptr);
	ret = parse_port_string(&vec, so, &ip_family);
	if (ret != 1)
		cerr("IP of localhost seems to be unknown on this system (%i)\n",
			(int)ret);

	if ((ip_family != 4) && (ip_family != 6))
		cerr("IP family for localhost must be 4 or 6 but is %i\n",
			(int)ip_family);

	ASSERT_EQ((int)htons(so->lsa.sin.sin_port), (int)123);
	free(so);
	return 0;
}

static void minimal_http_https_client_impl(const char *server,
	uint16_t port,
	int use_ssl,
	const char *uri,
	const char *expected) {
	/* Client var */
	http_t *client;
	char client_err_buf[256];
	char client_data_buf[4096];
	int64_t data_read;
	int r;

	client = http_connect_client(
		server, port, use_ssl, client_err_buf, sizeof(client_err_buf));

	if ((client == NULL) || (0 != strcmp(client_err_buf, ""))) {
		cerr("%s connection to server [%s] port [%u] failed: [%s]",
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			client_err_buf);
		abort();
	}

	defer(http_close_connection, client);
	http_printf(client, "GET %s HTTP/1.0\r\n\r\n", uri);
	r = http_get_response(client, client_err_buf, sizeof(client_err_buf), 1000);
	if ((r < 0) || (0 != strcmp(client_err_buf, ""))) {
		cerr(
			"%s connection to server [%s] port [%u] did not respond: [%s]"CLR_LN,
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			client_err_buf);
		abort();
	}

	ASSERT(client != NULL);

	/* Check for status code 200 OK or 30? moved */
	if ((client->code != 200)
		&& (client->code / 10 != 30)) {
		cerr("Request to %s://%s:%u/%s: Status %u"CLR_LN,
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			uri,
			client->code);
		abort();
	}

	data_read = 0;
	while (data_read < client->content_length) {
		r = http_read(client,
			client_data_buf + data_read,
			sizeof(client_data_buf) - (size_t)data_read);
		if (r > 0) {
			data_read += r;
			ASSERT((data_read < sizeof(client_data_buf)));
		}
	}

	/* Nothing left to read */
	r = http_read(client, client_data_buf, sizeof(client_data_buf));
	ASSERT_EQ_ABORT(r, 0);

	if (expected) {
		ASSERT_STR_ABORT(client_data_buf, expected);
	}

	//http_close_connection(client);
}

static void minimal_http_client_check(const char *server,
	uint16_t port,
	const char *uri,
	const char *expected) {
	minimal_http_https_client_impl(server, port, 0, uri, expected);
}

static void minimal_https_client_check(const char *server,
	uint16_t port,
	const char *uri,
	const char *expected) {
	minimal_http_https_client_impl(server, port, 1, uri, expected);
}

static int minimal_test_request_handler(http_t *conn, void *cbdata) {
	const char *msg = (const char *)cbdata;
	unsigned long len = (unsigned long)strlen(msg) + 1;

	ASSERT(conn != NULL);
	ASSERT(len > 0);

	ASSERT_STR(conn->method, "GET");
	ASSERT_EQ(conn->req.local_uri[0], '/');
	ASSERT_EQ(conn->path[0], '/');
	ASSERT_EQ(conn->req.http_version[0], '1');
	ASSERT_EQ(conn->req.http_version[1], '.');
	ASSERT_EQ(conn->req.http_version[3], 0);
	ASSERT_TRUE(conn->num_headers >= 0);

	if (conn->req.query_string != NULL) {
		msg = conn->req.query_string;
		len = (unsigned long)strlen(msg) + 1;
	}

	http_printf(conn,
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: %lu\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n",
		len);

	http_write(conn, msg, len);
	return 200;
}

const char *lastMessage;
static int test_log_message(const http_t *conn, const char *message) {
	(void)conn;
	trace;
	printf("LOG_MESSAGE: %s\n", message);
	lastMessage = message;

	return 0; /* Return 0 means "not yet handled" */
}

static http_ini_t *test_http_setup(const http_clb_t *callbacks,
	void *user_data,
	const char **configuration_options,
	unsigned line) {
	http_ini_t *ctx;
	http_clb_t cb;

	if (callbacks) {
		memcpy(&cb, callbacks, sizeof(cb));
	} else {
		memset(&cb, 0, sizeof(cb));
	}

	if (cb.log_message == NULL) {
		cb.log_message = test_log_message;
	}

	ctx = http_setup(1024, &cb, user_data, (const options_ini_t **)configuration_options);
	if (!ctx) {
		/* http_setup is not supposed to fail anywhere, except for
		 * special tests (for them, line is 0). */
		cerr(
			"http_setup failed in line %u\n: \nlast message %s"CLR_LN,
			line,
			(lastMessage ? lastMessage : "<NULL>"));
	}

	return ctx;
}

void main_main(http_ini_t *ctx) {
	/* Add some handler */
	http_route(ctx,
		"/hello",
		minimal_test_request_handler,
		(void *)"Hello world");
	http_route(ctx,
		"/8",
		minimal_test_request_handler,
		(void *)"Number eight");

	/* Run the server for 5 seconds */
	delay(seconds(5));

	/* Call a test client */
	minimal_http_client_check("127.0.0.1", 8080, "/hello", "Hello world");

	/* Run the server for 1 second */
	delay(seconds(1));

	/* Call a test client */
	minimal_http_client_check("127.0.0.1", 8080, "/8?Alternative=Response", "Alternative=Response");

	/* Run the server for 1 second */
	delay(seconds(1));

	trace;
	/* Call a test client */
	minimal_http_client_check("localhost", 8080, "/8", "Number eight");

	http_stop(ctx);
}

TEST(httpi_start) {
	/* This test should ensure the minimum server example in
	 * docs/Embedding.md is still running. */

	/* Server context handle */
	http_ini_t *ctx;

	/* Initialize the library */
	/* Start the server */
	ASSERT_NOTNULL((ctx = test_http_setup(NULL, 0, NULL, __LINE__)));
	ASSERT_EQ(test_parse_port_string(), 0);
	httpi_start(ctx, main_main);
	/* Stop the server */
	return 0;
}

TEST(main_main) {
	int i, unused, result = 0;

	/* create test data */
	fetch_data = (char *)malloc(fetch_data_size);
	for (i = 0; i < fetch_data_size; i++) {
		fetch_data[i] = 'a' + i % 10;
	}

	/* tests with network access */
	init_CALLBACKS();
	EXEC_TEST_WITH(http_download, 0);
	EXEC_TEST_WITH(http_download, 1);

	EXEC_TEST_WITH(http_connect_websocket_client, 0);
	EXEC_TEST_WITH(http_connect_websocket_client, 1);

	EXEC_TEST(http_upload);
	EXEC_TEST(request_replies);
	EXEC_TEST(api_calls);
	EXEC_TEST(http_route);

	/* test completed */
	free(fetch_data);

	return result;
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
	cout("HttPi %s unit test\n\n", httpi_version());
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
	//EXEC_TEST(http_url_encode);
	EXEC_TEST(http_url_decode);
	EXEC_TEST(http_md5);
	EXEC_TEST(alloc_vprintf);
	//EXEC_TEST(str_decode64);
	EXEC_TEST(str_encode64);
	EXEC_TEST(mask_data);
	EXEC_TEST(parse_date_str);
	EXEC_TEST(http_get_valid_options);
	EXEC_TEST(http_builtin_mime_type);
	EXEC_TEST(http_get_uri_type);
	EXEC_TEST(http_stat);

	/* start stop server */
	EXEC_TEST(httpi_start);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;

	EXEC_TEST(main_main);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
