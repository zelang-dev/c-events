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
	char *data = fs_readfile(path);
	ASSERT(data != NULL);
	*size = (int)fs_filesize(path);
	return data;
}

static long fetch_data_size = 1024 * 1024;
static char *fetch_data;
static string_t inmemory_file_data = "hi there";
static string_t upload_filename = "upload_test.txt";
static string_t upload_filename2 = "upload_test2.txt";
static string_t upload_ok_message = "upload successful";

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
	int len1 = 0, len2 = 0;

	if (atoi(http_get_query(conn)) == 1) {
		ASSERT(!strcmp(path, "./upload_test.txt"));
		ASSERT((p1 = read_file("./passfile", &len1)) != NULL);
		ASSERT((p2 = read_file(path, &len2)) != NULL);
		ASSERT(len1 == len2);
		ASSERT(memcmp(p1, p2, 112) == 0);
		fs_unlink(path);
	} else if (atoi(http_get_query(conn)) == 2) {
		if (!strcmp(path, "./upload_test.txt")) {
			ASSERT((p1 = read_file("./CMakeLists.txt", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, 168) == 0);
			fs_unlink(path);
		} else if (!strcmp(path, "./upload_test2.txt")) {
			ASSERT((p1 = read_file("./hello_gz_unzipped.txt", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			fs_unlink(path);
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
		return 1;
	}

	return 0;
}

static int log_message_cb(const http_t *conn, string_t msg) {
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

void main_main(http_ini_t *ctx) {
	http_t *client_conn;
	char client_err[256], nonce[256];
	const httpi_t *client_ri;
	int client_res;
	FILE *f;
	const char *passwd_file = ".htpasswd";
	const char *test_file = "test_http_auth.test_file.txt";
	const char *test_content = "test_http_auth test_file content";
	const char *domain;
	const char *doc_root;
	const char *auth_request;
	const char *str;
	size_t len;
	int i;
	char HA1[256], HA2[256], HA[256];
	char HA1_md5_buf[33], HA2_md5_buf[33], HA_md5_buf[33];
	char *HA1_md5_ret, *HA2_md5_ret, *HA_md5_ret;
	const char *nc = "00000001";
	const char *cnonce = "6789ABCD";

	domain = http_get_option(ctx, "authentication_domain");
	ck_assert(domain != NULL);
	len = strlen(domain);
	ck_assert_uint_gt(len, 0);
	ck_assert_uint_lt(len, 64);
	doc_root = http_get_option(ctx, "document_root");
	ck_assert_str_eq(doc_root, ".");

	/* Create a default file in the document root */
	if (async_fprintf(test_file, "wb", test_content) <= 0)
		cerr("Cannot create file %s", test_file);

	fs_unlink(passwd_file);

	/* Read file before a .htpasswd file has been created */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ck_assert(client_conn != NULL);
	ck_assert_str_eq(client_err, "");
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ck_assert_int_ge(client_res, 0);
	ck_assert_str_eq(client_err, "");
	client_ri = http_request_info(client_conn);
	ck_assert(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ck_assert_int_gt(client_res, 0);
	ck_assert_int_le(client_res, sizeof(client_err));
	ck_assert_str_eq(client_err, test_content);
	http_close_connection(client_conn);

	delay(500);

	/* Create a .htpasswd file */
	client_res = http_modify_passwords_file(passwd_file, domain, "user", "pass");
	ck_assert_int_eq(client_res, 1);

	client_res = http_modify_passwords_file(NULL, domain, "user", "pass");
	ck_assert_int_eq(client_res, 0); /* Filename is required */

	delay(500);

	/* Repeat test after .htpasswd is created */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ck_assert(client_conn != NULL);
	ck_assert_str_eq(client_err, "");
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ck_assert_int_ge(client_res, 0);
	ck_assert_str_eq(client_err, "");
	client_ri = http_request_info(client_conn);
	ck_assert(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 401);

	auth_request = http_get_header(client_conn, "WWW-Authenticate");
	ASSERT(auth_request != NULL);

	str = "Digest qop=\"auth\", realm=\"";
	len = strlen(str);
	ASSERT(str_case_equal(auth_request, str, len));
	ASSERT(!strncmp(auth_request + len, domain, strlen(domain)));
	len += strlen(domain);
	str = "\", nonce=\"";
	ASSERT(!strncmp(auth_request + len, str, strlen(str)));
	len += strlen(str);
	str = strchr(auth_request + len, '\"');
	ck_assert_ptr_ne(str, NULL);
	ck_assert_ptr_ne(str, auth_request + len);
	/* nonce is from including (auth_request + len) to excluding (str) */
	ck_assert_int_gt((ptrdiff_t)(str)-(ptrdiff_t)(auth_request + len), 0);
	ck_assert_int_lt((ptrdiff_t)(str)-(ptrdiff_t)(auth_request + len),
		(ptrdiff_t)sizeof(nonce));
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce,
		auth_request + len,
		(size_t)((ptrdiff_t)(str)-(ptrdiff_t)(auth_request + len)));
	memset(HA1, 0, sizeof(HA1));
	memset(HA2, 0, sizeof(HA2));
	memset(HA, 0, sizeof(HA));
	memset(HA1_md5_buf, 0, sizeof(HA1_md5_buf));
	memset(HA2_md5_buf, 0, sizeof(HA2_md5_buf));
	memset(HA_md5_buf, 0, sizeof(HA_md5_buf));

	sprintf(HA1, "%s:%s:%s", "user", domain, "pass");
	sprintf(HA2, "%s:/%s", "GET", test_file);
	HA1_md5_ret = http_md5(HA1_md5_buf, HA1, NULL);
	HA2_md5_ret = http_md5(HA2_md5_buf, HA2, NULL);

	ck_assert_ptr_eq(HA1_md5_ret, HA1_md5_buf);
	ck_assert_ptr_eq(HA2_md5_ret, HA2_md5_buf);

	HA_md5_ret = http_md5(HA_md5_buf, "user", ":", domain, ":", "pass", NULL);
	ck_assert_ptr_eq(HA_md5_ret, HA_md5_buf);
	ck_assert_str_eq(HA1_md5_ret, HA_md5_buf);

	HA_md5_ret = http_md5(HA_md5_buf, "GET", ":", "/", test_file, NULL);
	ck_assert_ptr_eq(HA_md5_ret, HA_md5_buf);
	ck_assert_str_eq(HA2_md5_ret, HA_md5_buf);

	HA_md5_ret = http_md5(HA_md5_buf, HA1_md5_buf, ":", nonce, ":", nc, ":", cnonce, ":", "auth", ":", HA2_md5_buf, NULL);
	ck_assert_ptr_eq(HA_md5_ret, HA_md5_buf);

	/* Retry with Authorization */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ck_assert(client_conn != NULL);
	ck_assert_str_eq(client_err, "");
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n", test_file);
	http_printf(client_conn,
		"Authorization: Digest "
		"username=\"%s\", "
		"realm=\"%s\", "
		"nonce=\"%s\", "
		"uri=\"/%s\", "
		"qop=auth, "
		"nc=%s, "
		"cnonce=\"%s\", "
		"response=\"%s\"\r\n\r\n",
		"user",
		domain,
		nonce,
		test_file,
		nc,
		cnonce,
		HA_md5_buf);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ck_assert_int_ge(client_res, 0);
	ck_assert_str_eq(client_err, "");
	client_ri = http_request_info(client_conn);
	ck_assert(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ck_assert_int_gt(client_res, 0);
	ck_assert_int_le(client_res, sizeof(client_err));
	ck_assert_str_eq(client_err, test_content);
	http_close_connection(client_conn);

	delay(500);


	/* Remove the user from the .htpasswd file again */
	client_res = http_modify_passwords_file(passwd_file, domain, "user", NULL);
	ck_assert_int_eq(client_res, 1);

	delay(500);


	/* Try to access the file again. Expected: 401 error */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ck_assert(client_conn != NULL);
	ck_assert_str_eq(client_err, "");
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ck_assert_int_ge(client_res, 0);
	ck_assert_str_eq(client_err, "");
	client_ri = http_request_info(client_conn);
	ck_assert(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 401);
	http_close_connection(client_conn);

	delay(500);

	/* Now remove the password file */
	fs_unlink(passwd_file);
	delay(500);

	/* Access to the file must work like before */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ck_assert(client_conn != NULL);
	ck_assert_str_eq(client_err, "");
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ck_assert_int_ge(client_res, 0);
	ck_assert_str_eq(client_err, "");
	client_ri = http_request_info(client_conn);
	ck_assert(client_ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ck_assert_int_gt(client_res, 0);
	ck_assert_int_le(client_res, sizeof(client_err));
	ck_assert_str_eq(client_err, test_content);
	http_close_connection(client_conn);

	delay(500);


	/* Stop the server and clean up */
	http_stop(ctx);
	fs_unlink(test_file);
}

TEST(http_authentication) {
	http_ini_t *ctx;
	string_t OPTIONS[] = {
		"document_root",
		".",
		"listening_ports",
		"8080",
		"static_file_max_age",
		"0",
		NULL,
	};

	/* Initialize the library */
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, null, null, server_opts(OPTIONS)), DATA_HTTP_SERVER));

	/* Start the server */
	httpi_start(ctx, main_main);
	return 0;
}

TEST(list) {
	char buffer[512];
	int unused, result = 0;

#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
	unused = chdir(TESTDIR);

	/* print headline */
	cout("HttPi %s authentication test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */

	FILE *f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("test-http_auth.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain test-http_auth.c\n");
	}

	EXEC_TEST(http_authentication);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
