#include "../../src/lib/httpi_internal.h"
#include "../test_assert.h"
#include <openssl/md5.h>

#if defined(_WIN32)
#   define TESTDIR "../../httpi/tests/units"
#else
#   define TESTDIR "../httpi/tests/units"
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
		printf("Fail on line %d: [%s]"CLR_LN, line, cond_txt);
		++s_failed_tests;
	}
}

#define ASSERT(expr)                                                           \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
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
	int i;

	struct {
		char before[256];
		const char after[256];
	} data[] = {
		{"/path/to/file.ext", "/path/to/file.ext"},
		{"/file.ext", "/file.ext"},
		{"/path/../file.ext", "/file.ext"},
		{"/../to/file.ext", "/to/file.ext"},
		{"/../../file.ext", "/file.ext"},
		{"/./../file.ext", "/file.ext"},
		{"/.././file.ext", "/file.ext"},
		{"/././file.ext", "/file.ext"},
		{"/././file.ext", "/file.ext"},
		{"/path/.to/..file.ext", "/path/.to/..file.ext"},
		{"/file", "/file"},
		{"/path/", "/path/"},

		{"file.ext", "file.ext"},
		{"./file.ext", "file.ext"},
		{"../file.ext", "file.ext"},
		{".file.ext", ".file.ext"},
		{"..file.ext", "..file.ext"},
		{"file", "file"},
		{"/x/../", "/"},
		{"/x/../../", "/"},
		{"/x/.././", "/"},
		{"/./x/.././", "/"},

		/* Windows specific */
		{"\\file.ext", "/file.ext"},
		{"\\..\\file.ext", "/file.ext"},
		{"/file.", "/file"},
		{"/path\\to.\\.\\file.", "/path/to/file"},

		/* Multiple dots and slashes */
		{"\\//\\\\x", "/x"},
		{"//", "/"},
		{"/./", "/"},
		{"/../", "/"},
		{"/.../", "/"},
		{"/..../", "/"},
		{"/...../", "/"},
		{"/...../", "/"},
		{"/...//", "/"},
		{"/..././", "/"},
		{"/.../../", "/"},
		{"/.../.../", "/"},

		/* Test cases from issues */
		{"/foo/bar/baz/../qux.txt", "/foo/bar/qux.txt"},
		{"/../alice/bob/../carol/david/frank/../../grace.ext/hugo/../irene.jpg",
		 "/alice/carol/grace.ext/irene.jpg"},
		{"/a/b/..", "/a/"},
		{"/a/b/c/../d/../..", "/a/"}};

	for (i = 0; i < get_array_size(data); i++) {
		remove_double_dots_slashes(data[i].before);
		ASSERT(str_is(data[i].before, data[i].after));
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
	ASSERT_UEQ((unsigned char)out[0], (0u ^ 4u));
	ASSERT_UEQ((unsigned char)out[1], (1u ^ 3u));
	ASSERT_UEQ((unsigned char)out[2], (2u ^ 2u));
	ASSERT_UEQ((unsigned char)out[3], (3u ^ 1u));
	ASSERT_UEQ((unsigned char)out[4], (4u ^ 4u));

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

TEST(alloc_printf) {
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
		str_encode64(_in[i], buf, sizeof(buf));
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
	cout("HttPi %s core units test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */
	f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("test-httpi_units.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain test-httpi_units.c\n");
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
	EXEC_TEST(alloc_printf);
	//EXEC_TEST(str_decode64);
	EXEC_TEST(str_encode64);
	EXEC_TEST(mask_data);
	EXEC_TEST(parse_date_str);
	EXEC_TEST(http_get_valid_options);
	EXEC_TEST(http_builtin_mime_type);
	EXEC_TEST(http_get_uri_type);
	EXEC_TEST(http_stat);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
