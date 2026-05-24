#include "../test_assert.h"
#include <openssl/md5.h>

#if defined(_WIN32)
#   define TESTDIR "../../httpi/tests/httpi"
#else
#   define TESTDIR "../httpi/tests/httpi"
#endif

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

	if (atoi(http_get_query(conn)) == 1) {
		ASSERT(!strcmp(path, "./upload_test.txt"));
		ASSERT((p1 = read_file("../src/app/url.c", &len1)) != NULL);
		ASSERT((p2 = read_file(path, &len2)) != NULL);
		ASSERT(len1 == len2);
		ASSERT(memcmp(p1, p2, len1) == 0);
		free_ex(p1);
		free_ex(p2);
		remove(upload_filename);
	} else if (atoi(http_get_query(conn)) == 2) {
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
	int req_len = (int)(http_get_length(conn));
	string_t s_req_len = http_get_header(conn, "Content-Length");
	char *data;
	long to_write, write_now;
	int bytes_read, bytes_written;

	ASSERT(((req_len == -1) && (s_req_len == NULL)) ||
	       ((s_req_len != NULL) && (req_len = atol(s_req_len))));

	if (!strncmp(http_get_uri(conn), "/data/", 6)) {
		if (!strcmp(http_get_uri(conn) + 6, "all")) {
			to_write = fetch_data_size;
		} else {
			to_write = atol(http_get_url(conn) + 6);
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

	if (!strcmp(http_get_url(conn), "/content_length")) {
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

	if (!strcmp(http_get_url(conn), "/upload")) {
		ASSERT(http_get_query(conn) != NULL);
		ASSERT(http_upload(conn, ".") == atoi(http_get_query(conn)));
		return 1;
	}

	return 0;
}

static int log_message_cb(const http_t *conn, string_t msg)
{
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

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

static int websocket_data_handler(const http_t *conn, int flags, char *data, size_t data_len, void *cbdata)
{
	(void)conn;
	(void)flags;
	(void)data;
	(void)data_len;
	(void)cbdata;
	return 1;
}

void main_main(http_ini_t *ctx) {
	bool use_ssl = false;
	http_t *conn;
	int port;
	http_ini_t *ctx;

	use_ca_certificate("cert.pem");
	tls_selfserver_set();

	if (use_ssl)
		port = atoi(HTTPS_PORT);
	else
		port = atoi(HTTP_PORT);

	/* Try to connect to our own server */
	/* Invalid port test */
	conn = http_connect_websocket_client("localhost",
	                                   0,
	                                   use_ssl,
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
	                                   "/",
	                                   "http://websocket.org",
	                                   (ws_data_cb)websocket_data_handler,
	                                   NULL,
	                                   NULL);
	ASSERT(conn != NULL);

	delay(2000);

	http_stop(ctx);
	return 0;
}

TEST(http_connect_websocket_client) {
	int result = 0;

	http_ini_t *ctx;
	http_clb_t cb = http_callbacks(begin_request_handler_cb, log_message_cb, NULL, open_file_cb, NULL, upload_cb);
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, &cb, NULL, server_opts(OPTIONS)), DATA_HTTP_SERVER));
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
	cout("HttPi %s websocket test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */
	f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("./test-http_connect_ws.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain test-http_connect_ws.c\n");
	}

	/* start stop server */
	EXEC_TEST(http_connect_websocket_client);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
