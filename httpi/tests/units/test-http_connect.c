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

#define no_of_testhosts (6)
/* Try to communicate with an external http server. */
static const char *external_ip[no_of_testhosts] = {
	"github.com", "google.com", "sourceforge.net",
	"microsoft.com", "echo.websocket.org", "httpbin.org"
};

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

	client = http_connect(server, port, use_ssl, client_err_buf, sizeof(client_err_buf));
	ASSERT_EQ_ABORT(is_type(client, (data_types)DATA_HTTPINFO), true);
	if (0 != strcmp(client_err_buf, "")) {
		cerr("%s connection to server [%s] port [%u] failed: [%s]",
			use_ssl ? "HTTPS" : "HTTP",
			server,
			port,
			client_err_buf);
	}

	if (use_ssl)
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

	/* Check for status code 200 OK or 30? moved */
	int code = http_get_code(client);
	if ((code != 200)
		&& (code / 10 != 30)) {
		cerr("Request to %s://%s:%u%s: Status %u"CLR_LN,
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
	ASSERT_EQ_ABORT((r = http_read(client, client_data_buf, sizeof(client_data_buf))), 0);

	if (expected) {
		ASSERT_STR_ABORT(client_data_buf, expected);
	}

	if (!use_ssl)
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

void main_main(param_t args) {
	/* Call as a http client */
	minimal_http_client_check(external_ip[0],
		80,
		"/zelang-dev/c-events/",
		NULL /* no check */);

	use_ca_certificate("cert.pem");

	/* Call as a https client */
	minimal_https_client_check(external_ip[0],
		443,
		"/",
		NULL /* no check */);
}

TEST(http_connect) {
	return events_start(1024, main_main, null);
}

TEST(list) {
	int result = 0;

	/* print headline */
	cout("HttPi %s minimal client test\n\n", httpi_version());

	/* start stop server */
	EXEC_TEST(http_connect);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
