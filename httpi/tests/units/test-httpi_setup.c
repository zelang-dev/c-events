#include "../../src/lib/httpi_internal.h"
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

const char *lastMessage;
static int test_log_message(const http_t *conn, const char *message) {
	(void)conn;
	printf("LOG_MESSAGE: %s\n", message);
	lastMessage = message;

	return 0; /* Return 0 means "not yet handled" */
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

TEST(httpi_setup) {
	/* Server context handle */
	http_ini_t *ctx;
	http_clb_t cb;

	memset(&cb, 0, sizeof(cb));
	if (cb.log_message == NULL) {
		cb.log_message = test_log_message;
	}

	/* Initialize the library */
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, &cb, null, null), (data_types)DATA_HTTP_SERVER));
	ASSERT_EQ(test_parse_port_string(), 0);
	http_stop(ctx);
	return 0;
}

TEST(list) {
	int result = 0;

	cout("HttPi %s setup/config and stop test\n\n", httpi_version());
	EXEC_TEST(httpi_setup);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
