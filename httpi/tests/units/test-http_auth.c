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
	ASSERT(domain != NULL);
	len = strlen(domain);
	ASSERT((len > 0 && len < 64));
	doc_root = http_get_option(ctx, "document_root");
	ASSERT(str_is(doc_root, "."));

	/* Create a default file in the document root */
	if (async_fprintf(test_file, "wb", test_content) <= 0)
		cerr("Cannot create file %s", test_file);

	fs_unlink(passwd_file);

	/* Read file before a .htpasswd file has been created */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ASSERT(client_conn != NULL);
	ASSERT(str_is(client_err, ""));
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ASSERT(client_res >= 0);
	ASSERT(str_is(client_err, ""));
	client_ri = http_request_info(client_conn);
	ASSERT(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ASSERT((client_res > 0 && client_res <= sizeof(client_err)));
	ASSERT(str_is(client_err, test_content));
	http_close_connection(client_conn);

	delay(500);

	/* Create a .htpasswd file */
	client_res = http_modify_passwords_file(passwd_file, domain, "user", "pass");
	ASSERT(client_res == 1);

	client_res = http_modify_passwords_file(NULL, domain, "user", "pass");
	ASSERT(client_res == 0); /* Filename is required */

	delay(500);

	/* Repeat test after .htpasswd is created */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ASSERT(client_conn != NULL);
	ASSERT(str_is(client_err, ""));
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ASSERT(client_res >= 0);
	ASSERT(str_is(client_err, ""));
	client_ri = http_request_info(client_conn);
	ASSERT(client_ri != NULL);

	ASSERT_EQ_ABORT(http_get_code(client_conn), 401);

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
	ASSERT(str != NULL);
	ASSERT(str != (auth_request + len));
	/* nonce is from including (auth_request + len) to excluding (str) */
	ASSERT(((ptrdiff_t)(str)-(ptrdiff_t)(auth_request + len) > 0
		&& (ptrdiff_t)(str)-(ptrdiff_t)(auth_request + len) < (ptrdiff_t)sizeof(nonce)));
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

	ASSERT(HA1_md5_ret == HA1_md5_buf);
	ASSERT(HA2_md5_ret == HA2_md5_buf);

	HA_md5_ret = http_md5(HA_md5_buf, "user", ":", domain, ":", "pass", NULL);
	ASSERT(HA_md5_ret == HA_md5_buf);
	ASSERT(str_is(HA1_md5_ret, HA_md5_buf));

	HA_md5_ret = http_md5(HA_md5_buf, "GET", ":", "/", test_file, NULL);
	ASSERT(HA_md5_ret == HA_md5_buf);
	ASSERT(str_is(HA2_md5_ret, HA_md5_buf));

	HA_md5_ret = http_md5(HA_md5_buf, HA1_md5_buf, ":", nonce, ":", nc, ":", cnonce, ":", "auth", ":", HA2_md5_buf, NULL);
	ASSERT(HA_md5_ret == HA_md5_buf);
	http_close_connection(client_conn);

	/* Retry with Authorization */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ASSERT(client_conn != NULL);
	ASSERT(str_is(client_err, ""));
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
	ASSERT(client_res >= 0);
	ASSERT(str_is(client_err, ""));
	client_ri = http_request_info(client_conn);
	ASSERT(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ASSERT((client_res > 0 && client_res <= sizeof(client_err)));
	ASSERT(str_is(client_err, test_content));
	http_close_connection(client_conn);

	delay(500);

	/* Remove the user from the .htpasswd file again */
	client_res = http_modify_passwords_file(passwd_file, domain, "user", NULL);
	ASSERT(client_res == 1);

	delay(500);

	/* Try to access the file again. Expected: 401 error */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ASSERT(client_conn != NULL);
	ASSERT(str_is(client_err, ""));
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ASSERT(client_res >= 0);
	ASSERT(str_is(client_err, ""));
	client_ri = http_request_info(client_conn);
	ASSERT(client_ri != NULL);

	ASSERT(http_get_code(client_conn) == 401);
	http_close_connection(client_conn);

	delay(500);

	/* Now remove the password file */
	fs_unlink(passwd_file);
	delay(500);

	/* Access to the file must work like before */
	memset(client_err, 0, sizeof(client_err));
	client_conn = http_connect("127.0.0.1", 8080, 0, client_err, sizeof(client_err));
	ASSERT(client_conn != NULL);
	ASSERT(str_is(client_err, ""));
	http_printf(client_conn, "GET /%s HTTP/1.0\r\n\r\n", test_file);
	client_res = http_get_response(client_conn, client_err, sizeof(client_err), 10000);
	ASSERT(client_res >= 0);
	ASSERT(str_is(client_err, ""));
	client_ri = http_request_info(client_conn);
	ASSERT(client_ri != NULL);
	ASSERT(http_get_code(client_conn) == 200);
	client_res = (int)http_read(client_conn, client_err, sizeof(client_err));
	ASSERT((client_res > 0 && client_res <= sizeof(client_err)));
	ASSERT(str_is(client_err, test_content));
	http_close_connection(client_conn);

	delay(500);
	fs_unlink(test_file);

	/* Stop the server and clean up */
	http_stop(ctx);
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
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, null, null, server_opts(OPTIONS)), (data_types)DATA_HTTP_SERVER));

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
