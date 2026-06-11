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

static const char *locate_path(const char *a_path) {
	static char r_path[256];
#ifdef _WIN32
	sprintf(r_path, "..\\..\\..\\..\\%s\\", a_path);
#else
	sprintf(r_path,	"../../../%s/",	a_path);
#endif
	return r_path;
}

#define locate_test_exes() locate_path("build")

/****************************************************************************/
/* WEBSOCKET SERVER                                                         */
/****************************************************************************/
static const char *websocket_welcome_msg = "websocket welcome\n";
static const size_t websocket_welcome_msg_len = 18 /* strlen(websocket_welcome_msg) */;
static const char *websocket_goodbye_msg = "websocket bye\n";
static const size_t websocket_goodbye_msg_len = 14 /* strlen(websocket_goodbye_msg) */;

static int websock_server_connect(http_t *conn, void *udata) {
	(void)conn;

	ASSERT((void *)udata == (void *)(ptrdiff_t)7531);
	cout("Server: Websocket connected"CLR_LN);

	return 0; /* return 0 to accept every connection */
}

static void websock_server_ready(http_t *conn, void *udata) {
	ASSERT((void *)udata == (void *)(ptrdiff_t)7531);
	ASSERT((void *)conn != (void *)NULL);
	cout("Server: Websocket ready"CLR_LN);
	/* Send websocket welcome message */
	http_websocket_write(conn, WS_OPS_TEXT, websocket_welcome_msg, websocket_welcome_msg_len);
	cout("Server: Websocket ready X"CLR_LN);
}

#define long_ws_buf_len_16 (500)
#define long_ws_buf_len_64 (70000)
static char long_ws_buf[long_ws_buf_len_64];

static int websock_server_data(http_t *conn,
	int bits,
	char *data,
	size_t data_len,
	void *udata) {
	(void)bits;

	ASSERT((void *)udata == (void *)(ptrdiff_t)7531);
	cout("Server: Got %u bytes from the client"CLR_LN, (unsigned)data_len);

	if (data_len == 3 && !memcmp(data, "bye", 3)) {
		/* Send websocket goodbye message */
		http_websocket_write(conn, WS_OPS_TEXT,
			websocket_goodbye_msg,
			websocket_goodbye_msg_len);
	} else if (data_len == 5 && !memcmp(data, "data1", 5)) {
		http_websocket_write(conn, WS_OPS_TEXT, "ok1", 3);
	} else if (data_len == 5 && !memcmp(data, "data2", 5)) {
		http_websocket_write(conn, WS_OPS_TEXT, "ok 2", 4);
	} else if (data_len == 5 && !memcmp(data, "data3", 5)) {
		http_websocket_write(conn, WS_OPS_TEXT, "ok - 3", 6);
	} else if (data_len == long_ws_buf_len_16) {
		ASSERT(memcmp(data, long_ws_buf, long_ws_buf_len_16) == 0);
		http_websocket_write(conn, WS_OPS_BINARY,
			long_ws_buf,
			long_ws_buf_len_16);
	} else if (data_len == long_ws_buf_len_64) {
		ASSERT(memcmp(data, long_ws_buf, long_ws_buf_len_64) == 0);
		http_websocket_write(conn, WS_OPS_BINARY,
			long_ws_buf,
			long_ws_buf_len_64);
	} else {

#if defined(__MINGW32__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunreachable-code"
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
#endif
		panicking("Got unexpected message from websocket client");
		return 0;

#ifdef __clang__
#pragma clang diagnostic pop
#endif
#if defined(__MINGW32__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
	}
	return 1; /* return 1 to keep the connection open */
}

static void websock_server_close(http_t *conn, void *udata) {
#if !defined(__MACH__) && !defined(__APPLE__)
	ASSERT((void *)udata == (void *)(ptrdiff_t)7531);
	cout("Server: Close connection"CLR_LN);

	/* Can not send a websocket goodbye message here -
	 * the connection is already closed */
#endif

	(void)conn;
	(void)udata;
}

/****************************************************************************/
/* WEBSOCKET CLIENT                                                         */
/****************************************************************************/
struct tclient_data {
	void *data;
	size_t len;
	int closed;
	int clientId;
};

static int websocket_client_data_handler(http_t *conn,
	int flags,
	char *data,
	size_t data_len,
	void *user_data) {
	http_ini_t *ctx = httpi_context(conn);
	struct tclient_data *pclient_data =
		(struct tclient_data *)httpi_user_data(ctx);

	ASSERT(user_data == (void *)pclient_data);

	ASSERT(pclient_data != NULL);
	ASSERT(flags > 128);
	ASSERT(flags < 128 + 16);
	ASSERT((flags == (int)(128 | WS_OPS_BINARY))
		|| (flags == (int)(128 | WS_OPS_TEXT)));

	if (flags == (int)(128 | WS_OPS_TEXT)) {
		cout(
			"Client %i received %lu bytes text data from server: %.*s"CLR_LN,
			pclient_data->clientId,
			(unsigned long)data_len,
			(int)data_len,
			data);
	} else {
		cout("Client %i received %lu bytes binary data from"CLR_LN,
			pclient_data->clientId,
			(unsigned long)data_len);
	}

	pclient_data->data = malloc(data_len);
	ASSERT(pclient_data->data != NULL);
	memcpy(pclient_data->data, data, data_len);
	pclient_data->len = data_len;

	return 1;
}

static void websocket_client_close_handler(http_t *conn, void *user_data) {
	http_ini_t *ctx = httpi_context(conn);
	struct tclient_data *pclient_data = (struct tclient_data *)httpi_user_data(ctx);

#if !defined(__MACH__) && !defined(__APPLE__)
	ASSERT(user_data == (void *)pclient_data);
	ASSERT(pclient_data != NULL);

	cout("Client %i: Close handler"CLR_LN, pclient_data->clientId);
	pclient_data->closed++;
#else

	(void)user_data;
	pclient_data->closed++;

#endif /* __MACH__ && __APPLE__ */
}

static http_ini_t *g_ctx;

static int request_test_handler(http_t *conn, void_t cbdata) {
	int i;
	const char *chunk_data = "123456789A123456789B123456789C";
	const httpi_t *ri;
	http_ini_t *ctx;
	void_t ud;

	ctx = httpi_context(conn);
	ud = httpi_user_data(ctx);
	ri = http_request_info(conn);

	ASSERT(ri != NULL);
	ASSERT(ctx == g_ctx);
	ASSERT(ud == &g_ctx);
	ASSERT((void *)cbdata == (void *)7);

	http_ok(conn, "text/plain", -1);
	for (i = 1; i <= 10; i++) {
		http_chunk(conn, chunk_data, (unsigned)i);
	}
	http_chunk(conn, 0, 0);

	return 200;
}

void main_main(http_ini_t *ctx) {
	http_t *client_conn;
	const httpi_t *ri;
	char uri[64], ebuf[100];
	char buf[1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 8];
	const char *expected =
		"112123123412345123456123456712345678123456789123456789A";
	int i;
	short ipv4_port = 8084;
	short ipv4s_port = 8094;
	short ipv4r_port = 8194;
	short ipv6_port = 8086;
	short ipv6s_port = 8096;
	short ipv6r_port = 8196;

	const char *request = "GET /U7 HTTP/1.0\r\n\r\n";

	const char *opt;
	FILE *f;
	const char *plain_file_content;
	const char *encoded_file_content;
	const char *cgi_script_content;
	const char *expected_cgi_result;
	int opt_idx = 0;

	use_ca_certificate("../../cert.pem");
	tls_selfserver_set();

	struct tclient_data ws_client1_data = {NULL, 0, 0, 1};
	struct tclient_data ws_client2_data = {NULL, 0, 0, 2};
	struct tclient_data ws_client3_data = {NULL, 0, 0, 3};
	struct tclient_data ws_client4_data = {NULL, 0, 0, 4};
	http_t *ws_client1_conn = NULL;
	http_t *ws_client2_conn = NULL;
	http_t *ws_client3_conn = NULL;
	http_t *ws_client4_conn = NULL;

	char cmd_buf[256];

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
		http_route(ctx, uri, request_test_handler, (void *)(ptrdiff_t)i);
	}

	http_websocket_route(ctx,
		"/websocket",
		websock_server_connect,
		websock_server_ready,
		websock_server_data,
		websock_server_close,
		(void *)7531);

	/* Try to load non existing file */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET /file/not/found HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 404);
	http_close_connection(client_conn);

	/* Get data from callback */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get data from callback using http://127.0.0.1 */
	client_conn = http_download("127.0.0.1", ipv4_port, 0, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	if ((i >= 0) && ((size_t)i < sizeof(buf))) {
		buf[i] = 0;
	} else {
		cerr("ERROR: test_request_handlers: read returned %i (>=0, <%i)",
			(int)i,
			(int)sizeof(buf));
		abort();
	}
	ASSERT((int)i < (int)sizeof(buf));
	ASSERT(i > 0);
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get data from callback using http://[::1] */
	client_conn = http_download("[::1]", ipv6_port, 0, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get data from callback using https://127.0.0.1 */
	client_conn = http_download("127.0.0.1", ipv4s_port, 1, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get redirect from callback using http://127.0.0.1 */
	client_conn = http_download("127.0.0.1", ipv4r_port, 0, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	http_status code = http_get_code(client_conn);
	ASSERT((code == 301) || (code == 302)
		|| (code == 303) || (code == 307)
		|| (code == 308));
	i = http_read(client_conn, buf, sizeof(buf));
	http_close_connection(client_conn);

	/* Get data from callback using https://[::1] */
	client_conn = http_download("[::1]", ipv6s_port, 1, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT(str_is(buf, expected));
	http_close_connection(client_conn);

	/* Get redirect from callback using http://127.0.0.1 */
	client_conn = http_download("[::1]", ipv6r_port, 0, "%s", request);
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT((code == 301) || (code == 302)
		|| (code == 303) || (code == 307)
		|| (code == 308));
	http_close_connection(client_conn);

/* It seems to be impossible to find out what the actual working
 * directory of the CI test environment is. Before breaking another
 * dozen of builds by trying blindly with different paths, just
 * create the file here */
#ifdef _WIN32
	f = fs_fopen("test.txt", "wb");
#else
	f = fs_fopen("test.txt", "w");
#endif
	plain_file_content = "simple text file\n";
	fs_fwrite((void_t)plain_file_content, 17, 1, f);
	fs_fclose(f);

#ifdef _WIN32
	f = fs_fopen("test_gz.txt.gz", "wb");
#else
	f = fs_fopen("test_gz.txt.gz", "w");
#endif
	encoded_file_content = "\x1f\x8b\x08\x08\xf8\x9d\xcb\x55\x00\x00"
		"test_gz.txt"
		"\x00\x01\x11\x00\xee\xff"
		"zipped text file"
		"\x0a\x34\x5f\xcc\x49\x11\x00\x00\x00";
	fs_fwrite((void_t)encoded_file_content, 1, 52, f);
	fs_fclose(f);

#ifdef _WIN32
	f = fs_fopen("test.cgi", "wb");
	cgi_script_content = "#!test.cgi.cmd\r\n";
	fs_fwrite((void_t)cgi_script_content, strlen(cgi_script_content), 1, f);
	fs_fclose(f);
	f = fs_fopen("test.cgi.cmd", "w");
	cgi_script_content = "@echo off\r\n"
		"echo Connection: close\r\n"
		"echo Content-Type: text/plain\r\n"
		"echo.\r\n"
		"echo CGI test\r\n"
		"\r\n";
	fs_fwrite((void_t)cgi_script_content, strlen(cgi_script_content), 1, f);
	fs_fclose(f);
#else
	f = fs_fopen("test.cgi", "w");
	cgi_script_content = "#!/bin/sh\n\n"
		"printf \"Connection: close\\r\\n\"\n"
		"printf \"Content-Type: text/plain\\r\\n\"\n"
		"printf \"\\r\\n\"\n"
		"printf \"CGI test\\r\\n\"\n"
		"\n";
	fs_fwrite((void_t)cgi_script_content, strlen(cgi_script_content), 1, f);
	fs_fclose(f);
	fs_chmod("test.cgi", S_IRWXU);
#endif
	expected_cgi_result = "CGI test";

	/* Get static data */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET /test.txt HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == 17);
	if ((i >= 0) && (i < (int)sizeof(buf))) {
		buf[i] = 0;
	}
	ASSERT_STR_ABORT(buf, plain_file_content);

	http_close_connection(client_conn);


/* Test with CGI test executable */
#if defined(_WIN32)
	sprintf(cmd_buf, "%s\\cgi_test.exe", locate_test_exes());
	fs_copyfile(cmd_buf, "cgi_test.cgi");
#else
	sprintf(cmd_buf, "%s/cgi_test", locate_test_exes());
	fs_copyfile(cmd_buf, "cgi_test.cgi");
#endif

	/* TODO: add test for windows, check with POST */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "POST /cgi_test.cgi HTTP/1.0\r\nContent-Length: 3\r\n\r\nABC");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	http_close_connection(client_conn);

	/* Get zipped static data - will not work if Accept-Encoding is not set */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET /test_gz.txt HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);

	ASSERT(http_get_code(client_conn) == 404);
	http_close_connection(client_conn);

	/* Get zipped static data - with Accept-Encoding */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET /test_gz.txt HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == 52);
	if ((i >= 0) && (i < (int)sizeof(buf))) {
		buf[i] = 0;
	}
	ASSERT(http_get_length(client_conn) == 52);
	ASSERT_STR_ABORT(buf, encoded_file_content);

	delay(100);
	http_close_connection(client_conn);

	/* Get CGI generated data */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET /test.cgi HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);

	i = http_read(client_conn, buf, sizeof(buf));
	if ((i >= 0) && (i < (int)sizeof(buf))) {
		while ((i > 0) && ((buf[i - 1] == '\r') || (buf[i - 1] == '\n'))) {
			i--;
		}
		buf[i] = 0;
	}
	ASSERT(i == (int)strlen(expected_cgi_result));
	ASSERT(str_is(buf, expected_cgi_result));
	ASSERT(http_get_code(client_conn) == 200);
	http_close_connection(client_conn);

	/* Get directory listing */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "GET / HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i > 21);
	buf[21] = 0;
	ASSERT_STR_ABORT(buf, "<!DOCTYPE html><html>");
	delay(100);
	http_close_connection(client_conn);

	/* POST to static file (will not work) */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "POST /test.txt HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 405);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i >= 29);
	buf[29] = 0;
	ASSERT_STR_ABORT(buf, "Error 405: Method Not Allowed");
	http_close_connection(client_conn);

	/* PUT to static file (will not work) */
	client_conn = http_download("localhost", ipv4_port, 0, "%s", "PUT /test.txt HTTP/1.0\r\n\r\n");
	ASSERT(client_conn != NULL);
	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	/* Result must be an error code*/
	ASSERT((http_get_code(client_conn) > 400
		&& http_get_code(client_conn) < 500));
	http_close_connection(client_conn);

	/* Get data from callback using http_connect instead of http_download */
	memset(ebuf, 0, sizeof(ebuf));
	client_conn = http_connect("127.0.0.1", ipv4_port, 0, ebuf, sizeof(ebuf));
	ASSERT(client_conn != NULL);
	ASSERT_STR_ABORT(ebuf, "");

	http_printf(client_conn, "%s", request);

	i = http_get_response(client_conn, ebuf, sizeof(ebuf), 10000);
	ASSERT(i >= 0);
	ASSERT_STR_ABORT(ebuf, "");

	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get data from callback using http_connect and absolute URI */
	memset(ebuf, 0, sizeof(ebuf));
	client_conn = http_connect("localhost", ipv4_port, 0, ebuf, sizeof(ebuf));
	ASSERT(client_conn != NULL);
	ASSERT_STR_ABORT(ebuf, "");

	http_printf(client_conn, "GET http://test.domain:%d/U7 HTTP/1.0\r\n\r\n", ipv4_port);

	i = http_get_response(client_conn, ebuf, sizeof(ebuf), 10000);
	ASSERT(i >= 0);
	ASSERT_STR_ABORT(ebuf, "");

	ri = http_request_info(client_conn);

	ASSERT(ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	i = http_read(client_conn, buf, sizeof(buf));
	ASSERT(i == (int)strlen(expected));
	buf[i] = 0;
	ASSERT_STR_ABORT(buf, expected);
	http_close_connection(client_conn);

	/* Get data non existing handler (will return 404) */
	client_conn = http_connect("localhost", ipv4_port, 0, ebuf, sizeof(ebuf));

	ASSERT(str_is(ebuf, ""));
	ASSERT(client_conn != NULL);

	http_printf(client_conn,
		"GET /unknown_url HTTP/1.1\r\n"
		"Host: localhost:%u\r\n"
		"\r\n",
		ipv4_port);

	i = http_get_response(client_conn, ebuf, sizeof(ebuf), 10000);
	ASSERT(i == -1);
	ASSERT(str_is(ebuf, ""));
	ASSERT_EQ_ABORT(http_get_code(client_conn), 404);
	http_close_connection(client_conn);

	/* Websocket test */
	/* Then connect a first client */
	ws_client1_conn =
		http_websocket_connect("localhost",
			ipv4_port,
			0,
			"/websocket",
			NULL,
			websocket_client_data_handler,
			websocket_client_close_handler,
			&ws_client1_data);

	ASSERT(ws_client1_conn != NULL);

	http_websocket_wait(ws_client1_conn); /* Wait for the websocket welcome message */
	ASSERT(ws_client1_data.closed == 0);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client3_data.closed == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);
	ASSERT(ws_client1_data.data != NULL);
	ASSERT(ws_client1_data.len == websocket_welcome_msg_len);
	ASSERT(!memcmp(ws_client1_data.data,
		websocket_welcome_msg,
		websocket_welcome_msg_len));
	free(ws_client1_data.data);
	ws_client1_data.data = NULL;
	ws_client1_data.len = 0;

	http_websocket_text(ws_client1_conn, "data1", 5);

	http_websocket_wait(ws_client1_conn); /* Wait for the websocket acknowledge message */
	ASSERT(ws_client1_data.closed == 0);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);
	ASSERT(ws_client1_data.data != NULL);
	ASSERT(ws_client1_data.len == 3);
	ASSERT(!memcmp(ws_client1_data.data, "ok1", 3));
	free(ws_client1_data.data);
	ws_client1_data.data = NULL;
	ws_client1_data.len = 0;

/* Now connect a second client */
	ws_client2_conn =
		http_websocket_connect("[::1]",
			ipv6_port,
			0,
			"/websocket",
			NULL,
			websocket_client_data_handler,
			websocket_client_close_handler,
			&ws_client2_data);
	ASSERT(ws_client2_conn != NULL);

	http_websocket_wait(ws_client2_conn); /* Wait for the websocket welcome message */
	ASSERT(ws_client1_data.closed == 0);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client1_data.data == NULL);
	ASSERT(ws_client1_data.len == 0);
	ASSERT(ws_client2_data.data != NULL);
	ASSERT(ws_client2_data.len == websocket_welcome_msg_len);
	ASSERT(!memcmp(ws_client2_data.data,
		websocket_welcome_msg,
		websocket_welcome_msg_len));
	free(ws_client2_data.data);
	ws_client2_data.data = NULL;
	ws_client2_data.len = 0;

	http_websocket_text(ws_client1_conn, "data2", 5);

	http_websocket_wait(ws_client1_conn); /* Wait for the websocket acknowledge message */

	ASSERT(ws_client1_data.closed == 0);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);
	ASSERT(ws_client1_data.data != NULL);
	ASSERT(ws_client1_data.len == 4);
	ASSERT(!memcmp(ws_client1_data.data, "ok 2", 4));
	free(ws_client1_data.data);
	ws_client1_data.data = NULL;
	ws_client1_data.len = 0;

	http_websocket_text(ws_client1_conn, "bye", 3);

	http_websocket_wait(ws_client1_conn); /* Wait for the websocket goodbye message */

	ASSERT(ws_client1_data.closed == 0);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);
	ASSERT(ws_client1_data.data != NULL);
	ASSERT(ws_client1_data.len == websocket_goodbye_msg_len);
	ASSERT(!memcmp(ws_client1_data.data,
		websocket_goodbye_msg,
		websocket_goodbye_msg_len));
	free(ws_client1_data.data);
	ws_client1_data.data = NULL;
	ws_client1_data.len = 0;

	ASSERT(ws_client1_data.closed == 0); /* Not closed */

	http_close_connection(ws_client1_conn);

	delay(500); /* Won't get any message */

	ASSERT(ws_client1_data.closed == 1); /* Closed */

	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client1_data.data == NULL);
	ASSERT(ws_client1_data.len == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);

	http_websocket_text(ws_client2_conn, "bye", 3);

	http_websocket_wait(ws_client2_conn); /* Wait for the websocket goodbye message */

	ASSERT(ws_client1_data.closed == 1);
	ASSERT(ws_client2_data.closed == 0);
	ASSERT(ws_client1_data.data == NULL);
	ASSERT(ws_client1_data.len == 0);
	ASSERT(ws_client2_data.data != NULL);
	ASSERT(ws_client2_data.len == websocket_goodbye_msg_len);
	ASSERT(!memcmp(ws_client2_data.data,
		websocket_goodbye_msg,
		websocket_goodbye_msg_len));
	free(ws_client2_data.data);
	ws_client2_data.data = NULL;
	ws_client2_data.len = 0;

	http_close_connection(ws_client2_conn);

	/* Won't get any message */

	ASSERT(ws_client1_data.closed == 1);
	ASSERT(ws_client2_data.closed == 1);
	ASSERT(ws_client1_data.data == NULL);
	ASSERT(ws_client1_data.len == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);

	/* Connect client 3 */
	ws_client3_conn =
		http_websocket_connect("localhost",
			ipv4s_port,
			1,
			"/websocket",
			NULL,
			websocket_client_data_handler,
			websocket_client_close_handler,
			&ws_client3_data);

	ASSERT(ws_client3_conn != NULL);

	http_websocket_wait(ws_client3_conn); /* Wait for the websocket welcome message */
	ASSERT(ws_client1_data.closed == 1);
	ASSERT(ws_client2_data.closed == 1);
	ASSERT(ws_client3_data.closed == 0);
	ASSERT(ws_client1_data.data == NULL);
	ASSERT(ws_client1_data.len == 0);
	ASSERT(ws_client2_data.data == NULL);
	ASSERT(ws_client2_data.len == 0);
	ASSERT(ws_client3_data.data != NULL);
	ASSERT(ws_client3_data.len == websocket_welcome_msg_len);
	ASSERT(!memcmp(ws_client3_data.data,
		websocket_welcome_msg,
		websocket_welcome_msg_len));
	free(ws_client3_data.data);
	ws_client3_data.data = NULL;
	ws_client3_data.len = 0;

	/* Write long data (16 bit size header) */
	http_websocket_binary(ws_client3_conn,
		long_ws_buf,
		long_ws_buf_len_16);

	/* Wait for the response */
	http_websocket_wait(ws_client3_conn);

	ASSERT((int)ws_client3_data.len == (int)long_ws_buf_len_16);
	ASSERT(!memcmp(ws_client3_data.data, long_ws_buf, long_ws_buf_len_16));
	free(ws_client3_data.data);
	ws_client3_data.data = NULL;
	ws_client3_data.len = 0;

	/* Write long data (64 bit size header) */
	http_websocket_binary(ws_client3_conn,
		long_ws_buf,
		long_ws_buf_len_64);

	/* Wait for the response */
	http_websocket_wait(ws_client3_conn);

	ASSERT((int)ws_client3_data.len == (int)long_ws_buf_len_64);
	ASSERT(!memcmp(ws_client3_data.data, long_ws_buf, long_ws_buf_len_64));
	free(ws_client3_data.data);
	ws_client3_data.data = NULL;
	ws_client3_data.len = 0;

	/* Disconnect client 3 */
	ASSERT(ws_client3_data.closed == 0);
	http_close_connection(ws_client3_conn);
	ASSERT(ws_client3_data.closed == 1);

	/* Connect client 4 */
	ws_client4_conn = http_websocket_connect("localhost",
			ipv4s_port,
			1,
			"/websocket",
			NULL,
			websocket_client_data_handler,
			websocket_client_close_handler,
			&ws_client4_data);

	ASSERT(ws_client4_conn != NULL);

	http_websocket_wait(ws_client4_conn); /* Wait for the websocket welcome message */
	ASSERT(ws_client1_data.closed == 1);
	ASSERT(ws_client2_data.closed == 1);
	ASSERT(ws_client3_data.closed == 1);
	ASSERT(ws_client4_data.closed == 0);
	ASSERT(ws_client4_data.data != NULL);
	ASSERT(ws_client4_data.len == websocket_welcome_msg_len);
	ASSERT(!memcmp(ws_client4_data.data,
		websocket_welcome_msg,
		websocket_welcome_msg_len));
	free(ws_client4_data.data);
	ws_client4_data.data = NULL;
	ws_client4_data.len = 0;
	/* stop the server without closing this connection */

	/* Close the server */
	g_ctx = NULL;
	http_stop(ctx);
}

TEST(http_route) {
	int opt_idx = 0, result = 0;
	string_t OPTIONS[16];
	http_ini_t *ctx;
	const char *HTTP_PORT = "8084,[::]:8086,8194r,[::]:8196r,8094s,[::]:8096s";

	memset((void *)OPTIONS, 0, sizeof(OPTIONS));
	OPTIONS[opt_idx++] = "listening_ports";
	OPTIONS[opt_idx++] = HTTP_PORT;
	OPTIONS[opt_idx++] = "authentication_domain";
	OPTIONS[opt_idx++] = "test.domain";
	OPTIONS[opt_idx++] = "document_root";
	OPTIONS[opt_idx++] = ".";
	//OPTIONS[opt_idx++] = "ssl_certificate";
	//OPTIONS[opt_idx++] = ".";

	ASSERT_TRUE(is_type(ctx = httpi_setup(2048, null, &g_ctx, server_opts(OPTIONS)), (data_types)DATA_HTTP_SERVER));
	g_ctx = ctx;
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
	cout("HttPi %s full api/request/route test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */
	if ((f = fopen("hello.txt", "r")))
		fclose(f);
	else
		cout("Error: Test directory does not contain hello.txt\n");

	if ((f = fopen("test-http_route.c", "r")))
		fclose(f);
	else
		cout("Error: Test directory does not contain test-http_route.c\n");

	/* start stop server */
	EXEC_TEST(http_route);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
