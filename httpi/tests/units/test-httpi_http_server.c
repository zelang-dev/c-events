#include "../test_assert.h"
#include <openssl/md5.h>

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

	client = http_connect(
		server, port, use_ssl, client_err_buf, sizeof(client_err_buf));

	if ((client == NULL) || (0 != strcmp(client_err_buf, ""))) {
		cerr("%s connection to server [%s] port [%u] failed: [%s]",
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			client_err_buf);
		abort();
	}

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
	int code = http_get_code(client);
	if ((code != 200)
		&& (code / 10 != 30)) {
		cerr("Request to %s://%s:%u/%s: Status %u"CLR_LN,
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			uri,
			code);
		abort();
	}

	data_read = 0;
	while (data_read < http_get_length(client)) {
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

	http_close_connection(client);
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

	ASSERT_STR(http_get_method(conn), "GET");
	ASSERT_EQ(http_get_path(conn)[0], '/');
	ASSERT_EQ(http_version(conn)[0], '1');
	ASSERT_EQ(http_version(conn)[1], '.');
	ASSERT_EQ(http_version(conn)[3], 0);
	ASSERT_TRUE(http_header_count(conn) >= 0);

	if (http_get_query(conn) != NULL) {
		msg = http_get_query(conn);
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
	printf("LOG_MESSAGE: %s\n", message);
	lastMessage = message;

	return 0; /* Return 0 means "not yet handled" */
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

	/* Call a test client */
	minimal_http_client_check("localhost", 8080, "/8", "Number eight");

	/* Stop the server */
	http_stop(ctx);
}

TEST(httpi_start) {
	/* This test should ensure the minimum server example in
	 * docs/Embedding.md is still running. */

	/* Server context handle */
	http_ini_t *ctx;
	http_clb_t cb = http_callbacks(null, test_log_message, null, null, null, null);

	/* Initialize the library */
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, &cb, null, null), (data_types)DATA_HTTP_SERVER));

	/* Start the server */
	httpi_start(ctx, main_main);
	return 0;
}

TEST(list) {
	int result = 0;

	/* print headline */
	cout("HttPi %s minimal `http` request/response server test\n\n", httpi_version());

	/* start stop server */
	EXEC_TEST(httpi_start);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
