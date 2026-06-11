#include <httpi.h>
#include "test_assert.h"

#if defined(_WIN32) || defined(_WIN64)
#   define TESTDIR "../../httpi/tests"
#else
#   define TESTDIR "../httpi/tests"
#endif

TEST(parse_multibad) {
	int unused;
    http_t *parser = http_for(nullptr, 1.1);

#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	unused = chdir(TESTDIR);
	string raw = json_read_file("multibody/bad_multipart.txt");

	parse_http(HTTP_RESPONSE, parser, raw);
	ASSERT_TRUE(is_type(parser, (data_types)DATA_HTTPINFO));

	ASSERT_NULL(http_get_header(parser, "User-Agent"));
	ASSERT_STR("localhost:8080", http_get_header(parser, "Host"));
	ASSERT_STR("*/*", http_get_header(parser, "Accept"));
	ASSERT_STR("1143", http_get_header(parser, "Content-Length"));
	ASSERT_STR("100-continue", http_get_header(parser, "Expect"));
	ASSERT_STR("line one",
		http_get_header(parser, "X-Multi-Line"));
	ASSERT_TRUE(http_is_multipart(parser));

	parse_multipart(parser);
	ASSERT_STR("multipart/form-data; boundary=----------------------------83ff53821b7c",
		http_get_header(parser, "Content-Type"));
	ASSERT_STR("----------------------------83ff53821b7c",
		http_get_boundary(parser));
	ASSERT_XEQ(3, http_multi_count(parser));
	ASSERT_XEQ(51, http_multi_length(parser, "img"));
	ASSERT_TRUE(http_multi_is_file(parser, "img"));
	ASSERT_STR("a.png", http_multi_filename(parser, "img"));
	ASSERT_STR("image/png", http_multi_type(parser, "img"));
	ASSERT_STR("form-data", http_multi_disposition(parser, "img"));

	unused = chdir("../build");

#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	return exit_scope();
}

TEST(list) {
    int result = 0;

	EXEC_TEST(parse_multibad);

    return result;
}

int main(int argc, char **argv) {
    TEST_FUNC(list());
}
