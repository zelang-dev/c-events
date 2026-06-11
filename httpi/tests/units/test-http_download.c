#include "../test_assert.h"
#include <openssl/md5.h>

#if defined(_WIN32)
#   define TESTDIR "../../httpi/tests/units"
#else
#   define TESTDIR "../httpi/tests/units"
#endif

void check_func(int condition, string_t cond_txt, unsigned line);

static int s_total_tests = 0;
static int s_failed_tests = 0;

void check_func(int condition, string_t cond_txt, unsigned line)
{
	++s_total_tests;
	if (!condition) {
		printf("Fail on line %d: [%s]"CLR_LN, line, cond_txt);
		++s_failed_tests;
	}
}

#define ASSERT(expr)                                                           \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
	} while (0)

#define HTTP_PORT "8080"
#define HTTP_REDIRECT_PORT "8088"
#define HTTPS_PORT "8443"
#define LISTENING_ADDR                                                         \
	"127.0.0.1:" HTTP_PORT ",127.0.0.1:" HTTP_REDIRECT_PORT "r"                \
	",127.0.0.1:" HTTPS_PORT "s"

static char *read_conn(http_t *conn, int *size) {
	string data = NULL;
	defer_free(data = http_read_until(conn, size));
	return data;
}

static char *read_file(string_t path, int *size) {
	FILE *fp;
	struct stat st;
	char filedir[PATH_MAX] = {0};
	snprintf(filedir, sizeof(filedir), ".%s%s", SYS_DIRSEP, path);
	char *data = fs_readfile(filedir);
	ASSERT(data != NULL);
	*size = (int)fs_filesize(path);
	ASSERT(strlen(data) == (size_t)*size);
	return data;
}

static long fetch_data_size = 1024 * 1024;
static char *fetch_data;
static string_t inmemory_file_data = "hi there";
static string_t upload_filename = "upload_test.txt";
static string_t upload_filename2 = "upload_test2.txt";
static string_t upload_ok_message = "upload successful";
static string_t OPTIONS[] = {
	"document_root",
	".",
	"listening_ports",
	LISTENING_ADDR,
	"enable_keep_alive",
	"yes",
	/*"ssl_certificate",
	"../resources/ssl_cert.pem",*/
	NULL,
};

static string_t open_file_cb(http_t *conn, string_t path, size_t *size) {
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

	if (atoi(http_get_query(conn)) == 1) {
		ASSERT(!strcmp(path, "./upload_test.txt"));
		ASSERT((p1 = read_file("test-httpi_units.c", &len1)) != NULL);
		ASSERT((p2 = read_file(path, &len2)) != NULL);
		ASSERT(len1 == len2);
		ASSERT(memcmp(p1, p2, len1) == 0);
		fs_unlink(upload_filename);
	} else if (atoi(http_get_query(conn)) == 2) {
		if (!strcmp(path, "./upload_test.txt")) {
			ASSERT((p1 = read_file("test-httpi_setup.c", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			fs_unlink(upload_filename);
		} else if (!strcmp(path, "./upload_test2.txt")) {
			ASSERT((p1 = read_file("ssi_test.shtml", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			fs_unlink(upload_filename);
		} else {
			ASSERT(0);
		}
	} else {
		ASSERT(0);
	}

	http_printf(conn, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", (int)strlen(upload_ok_message), upload_ok_message);
}

static int begin_request_handler_cb(http_t *conn) {
	int req_len = (int)(http_get_length(conn));
	string_t s_req_len = http_get_header(conn, "Content-Length");
	char *data;
	long to_write, write_now;
	int bytes_read, bytes_written;

	ASSERT(((req_len == 0 || req_len == -1) && (s_req_len == NULL)) ||
	       ((s_req_len != NULL) && (req_len = atol(s_req_len))));

	string val = http_get_path(conn);
	if (!strncmp(val, "/data/", 6)) {
		if (!strcmp(trim_at(val, 6), "all")) {
			to_write = fetch_data_size;
		} else {
			to_write = atol(trim_at(val, 6));
		}
		http_printf(conn,
		          "HTTP/1.1 200 OK\r\n"
		          "Connection: close\r\n"
		          "Content-Length: %li\r\n"
		          "Content-Type: text/plain\r\n\r\n", to_write);
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
		return 1;
	}

	if (str_is(val, "/content_length")) {
		if (req_len > 0) {
			data = malloc(req_len);
			defer_free(data);
			ASSERT(data != NULL);
			bytes_read = http_read(conn, data, req_len);
			ASSERT(bytes_read == req_len);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
			          "Content-Length: %d\r\n" /* The official definition */
			          "Content-Type: text/plain\r\n\r\n",
			          bytes_read);
			http_write(conn, data, bytes_read);
		} else {
			data = malloc(1024);
			defer_free(data);
			ASSERT(data != NULL);
			bytes_read = http_read(conn, data, 1024);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
				"Content-Type: text/plain\r\n\r\n");
			if (bytes_read > 0)
				http_write(conn, data, bytes_read);
		}

		return 1;
	}

	if (str_is(val, "/upload")) {
		ASSERT(http_get_query(conn) != NULL);
		ASSERT(http_upload(conn, ".") == atoi(http_get_query(conn)));
	}

	return 0;
}

static int log_message_cb(const http_t *conn, string_t msg)
{
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

void main_main(http_ini_t *ctx) {
	bool use_ssl = false;
	string_t test_data = "123456789A123456789B";

	char *p1, *p2, ebuf[100];
	string_t h;
	int i, len1, len2, port;
	http_t *conn;

	/* create test data */
	defer_free(fetch_data = malloc(fetch_data_size));
	for (i = 0; i < fetch_data_size; i++) {
		fetch_data[i] = 'a' + i % 10;
	}

	if (use_ssl) {
		port = atoi(HTTPS_PORT);
	} else {
		port = atoi(HTTP_PORT);
	}

	ASSERT(http_download(NULL, port, use_ssl, "%s", "") == NULL);
	ASSERT(http_download("localhost", 0, use_ssl, "%s", "") == NULL);
	ASSERT(http_download("localhost", port, use_ssl, "%s", "") == NULL);

	/* Fetch nonexistent file, should see 404 */
	ASSERT((conn = http_download("localhost", port, use_ssl, "%s", "GET /gimbec HTTP/1.0\r\n\r\n")) != NULL);
	ASSERT(http_get_code(conn) == (http_status)404);
	http_close_connection(conn);

	if (use_ssl) {
		ASSERT((conn = http_download("google.com", 443, 1, "%s", "GET / HTTP/1.0\r\n\r\n")) != NULL);
		http_close_connection(conn);
	} else {
		ASSERT((conn = http_download("google.com", 80, 0, "%s", "GET / HTTP/1.0\r\n\r\n")) != NULL);
		http_close_connection(conn);
	}

	/* Fetch test-httpi_units.c, should succeed */
	ASSERT((conn = http_download("localhost", port, use_ssl, "%s", "GET /test-httpi_units.c HTTP/1.0\r\n\r\n")) != NULL);
	ASSERT(http_get_code(conn) == (http_status)200);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT((p2 = read_file("test-httpi_units.c", &len2)) != NULL);
	ASSERT(len1 == len2);
	ASSERT(memcmp(p1, p2, len1) == 0);
	http_close_connection(conn);

	/* Fetch _in-memory file, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, "%s", "GET /blah HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(inmemory_file_data));
	ASSERT(memcmp(p1, inmemory_file_data, len1) == 0);
	http_close_connection(conn);

	/* Fetch _in-memory data with no Content-Length, should succeed. */
	ASSERT((conn = http_download("localhost", port, use_ssl, "%s", "GET /data/all HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT(http_get_length(conn) == fetch_data_size);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)fetch_data_size);
	ASSERT(memcmp(p1, fetch_data, len1) == 0);
	http_close_connection(conn);

	/* Fetch _in-memory data with no Content-Length, should succeed. */
	for (i = 0; i <= 1024 * /* 1024 * */ 8; i += (i < 2 ? 1 : i)) {
		ASSERT((conn = http_download("localhost", port, use_ssl, "GET /data/%i HTTP/1.1\r\n\r\n", i)) != NULL);
		ASSERT(http_get_length(conn) == i);
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
		http_close_connection(conn);
	}

	/* Fetch data with Content-Length, should succeed and return the defined
	 * length. */
	ASSERT((conn = http_download(
		"localhost",
		port,
		use_ssl,
		"POST /content_length HTTP/1.1\r\nContent-Length: %u\r\n\r\n%s",
		(unsigned)strlen(test_data),
		test_data)) != NULL);
	h = http_get_header(conn, "Content-Length");
	ASSERT((h != NULL) && (atoi(h) == (int)strlen(test_data)));
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(http_get_length(conn) == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	ASSERT(strcmp(http_get_protocol(conn), "HTTP/1.1") == 0);
	ASSERT(http_get_code(conn) == 200);
	ASSERT(strcmp(http_version(conn), "1.1") == 0);
	http_close_connection(conn);

	/* A POST request without Content-Length set is only valid, if the request
	 * used Transfer-Encoding: chunked. Otherwise, it is an HTTP protocol
	 * violation. Here we send a chunked request, the reply is not chunked. */
	ASSERT((conn = http_download("localhost",
		port,
		use_ssl,
		"POST /content_length "
		"HTTP/1.1\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n%x\r\n%s\r\n0\r\n\r\n",
		(uint32_t)strlen(test_data),
		test_data)) != NULL);
	h = http_get_header(conn, "Content-Length");
	ASSERT(h == NULL);
	ASSERT(http_get_length(conn) == -1);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	http_close_connection(conn);

	/* Another chunked POST request with different chunk sizes. */
	ASSERT((conn = http_download("localhost",
		port,
		use_ssl,
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
	ASSERT(http_get_length(conn) == -1);
	ASSERT((p1 = read_conn(conn, &len1)) != NULL);
	ASSERT(len1 == (int)strlen(test_data));
	ASSERT(memcmp(p1, test_data, len1) == 0);
	http_close_connection(conn);

	/* Test non existent */
	ASSERT((conn = http_download("localhost", port, use_ssl, "%s", "GET /non_exist HTTP/1.1\r\n\r\n")) != NULL);
	ASSERT_STR_ABORT(http_get_protocol(conn), "HTTP/1.1");
	ASSERT_EQ_ABORT(http_get_code(conn), 404);
	ASSERT_STR_ABORT(http_get_message(conn), "Not Found");
	http_close_connection(conn);

	if (use_ssl) {
		/* Test SSL redirect */
		ASSERT((conn = http_download("localhost", atoi(HTTP_REDIRECT_PORT), 0, "%s", "GET /data/4711 HTTP/1.1\r\n\r\n")) != NULL);
		ASSERT((http_get_code(conn) == 302));
		h = http_get_header(conn, "Location");
		ASSERT(h != NULL);
		ASSERT(strcmp(h, "https://127.0.0.1:" HTTPS_PORT "/data/4711") == 0);
		http_close_connection(conn);
	}

	/* Test new API */
	ebuf[0] = 1;
	conn = http_connect("localhost", port, use_ssl, ebuf, sizeof(ebuf));
	ASSERT(conn != NULL);
	ASSERT(ebuf[0] == 0);
	ASSERT(http_get_length(conn) == 0);
	http_printf(conn, "GET /index.html HTTP/1.1\r\n");
	http_printf(conn, "Host: www.example.com\r\n");
	http_printf(conn, "\r\n");
	i = http_get_response(conn, ebuf, sizeof(ebuf), 1000);
	ASSERT(ebuf[0] == 0);
	ASSERT(http_get_length(conn) == -1);
	http_read(conn, ebuf, sizeof(ebuf));
	ASSERT(!strncmp(ebuf, "Error 404", 9));

	http_close_connection(conn);

	/* Stop the test server */
	http_stop(ctx);
}

TEST(http_download) {
	int result = 0;

	http_ini_t *ctx;
	http_clb_t cb = http_callbacks(begin_request_handler_cb, log_message_cb, NULL, open_file_cb, NULL, upload_cb);
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, &cb, NULL, server_opts(OPTIONS)), (data_types)DATA_HTTP_SERVER));
	httpi_start(ctx, main_main);

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
	cout("HttPi %s download test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */
	f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("./test-http_download.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain test-http_download.c\n");
	}

	/* start stop server */
	EXEC_TEST(http_download);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
