#include <httpi.h>
#include "test_assert.h"

TEST(parse_http) {
    http_t *parser = http_for(nullptr, 1.1);

    char raw[] = "HTTP/1.1 200 OK\n\
Date: Tue, 12 Apr 2016 13:58:01 GMT\n\
Server: Apache/2.2.14 (Ubuntu)\n\
X-Powered-By: PHP/5.3.14 ZendServer/5.0\n\
Set-Cookie: ZDEDebuggerPresent=php,phtml,php3; Path=/\n\
Set-Cookie: PHPSESSID=6sf8fa8rlm8c44avk33hhcegt0; Path=/; HttpOnly\n\
Expires: Thu, 19 Nov 1981 08:52:00 GMT\n\
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\n\
Pragma: no-cache\n\
Vary: Accept-Encoding\n\
Content-Encoding: gzip\n\
Content-Length: 192\n\
Content-Type: text/xml\n\n";

    parse_http(HTTP_RESPONSE, parser, raw);
    ASSERT_TRUE(is_type(parser, (data_types)DATA_HTTPINFO));

    ASSERT_STR("Tue, 12 Apr 2016 13:58:01 GMT", http_get_header(parser, "Date"));
    ASSERT_STR("Apache/2.2.14 (Ubuntu)", http_get_header(parser, "Server"));
    ASSERT_STR("PHP/5.3.14 ZendServer/5.0", http_get_header(parser, "X-Powered-By"));
    ASSERT_STR("PHPSESSID=6sf8fa8rlm8c44avk33hhcegt0; Path=/; HttpOnly", http_get_header(parser, "Set-Cookie"));
    ASSERT_STR("Thu, 19 Nov 1981 08:52:00 GMT", http_get_header(parser, "Expires"));
    ASSERT_STR("no-store, no-cache, must-revalidate, post-check=0, pre-check=0", http_get_header(parser, "Cache-Control"));
    ASSERT_STR("no-cache", http_get_header(parser, "Pragma"));
    ASSERT_STR("Accept-Encoding", http_get_header(parser, "Vary"));
    ASSERT_STR("gzip", http_get_header(parser, "Content-Encoding"));
    ASSERT_STR("192", http_get_header(parser, "Content-Length"));
    ASSERT_STR("text/xml", http_get_header(parser, "Content-Type"));
    ASSERT_STR("HTTP/1.1", http_get_protocol(parser));
    ASSERT_STR("OK", http_get_message(parser));
    ASSERT_STR("/", http_get_var(parser, "Set-Cookie", "Path"));

    ASSERT_EQ(200, http_get_code(parser));

    ASSERT_TRUE(http_has_header(parser, "Pragma"));
    ASSERT_TRUE(http_has_flag(parser, "Cache-Control", "no-store"));
	ASSERT_TRUE(http_has_var(parser, "Set-Cookie", "PHPSESSID"));

	ASSERT_EQ(2, (int)http_cookie_count(parser));
	ASSERT_TRUE(http_cookie_is_multi(parser));
	ASSERT_TRUE(http_cookie_is_httpOnly(parser, "PHPSESSID"));
	ASSERT_FALSE(http_cookie_is_httpOnly(parser, "ZDEDebuggerPresent"));
	ASSERT_FALSE(http_cookie_is_secure(parser, "PHPSESSID"));

	ASSERT_STR("php,phtml,php3", http_get_cookie(parser, "ZDEDebuggerPresent"));
	ASSERT_STR("6sf8fa8rlm8c44avk33hhcegt0", http_get_cookie(parser, "PHPSESSID"));
	ASSERT_STR("/", http_cookie_path(parser, "ZDEDebuggerPresent"));
	ASSERT_STR("/", http_cookie_path(parser, "PHPSESSID"));
	ASSERT_STR("ZDEDebuggerPresent", http_cookie_names(parser)[0].char_ptr);
	ASSERT_STR("PHPSESSID", http_cookie_names(parser)[1].char_ptr);

	return 0;
}

TEST(http_get_decoded) {
	hash_http_t *buf = http_extract_var(null, "&", "=");
	ASSERT_NULL(buf);

	ASSERT_TRUE(is_type(buf = http_extract_var("key1=value1&key2=value2&key3=value%203&key4=value+4", "&", "="),
		DATA_HASHTABLE));
	ASSERT_STR(http_get_decoded(buf, "key1"), "value1");
	ASSERT_STR(http_get_decoded(buf, "key2"), "value2");
	ASSERT_STR(http_get_decoded(buf, "key3"), "value 3");
	ASSERT_STR(http_get_decoded(buf, "key4"), "value 4");
	ASSERT_NULL(http_get_decoded(buf, "f"));

	ASSERT_NOTNULL((buf = http_extract_var("a=1&&b=2&d&=&c=3%20&e=", "&", "=")));
	ASSERT_STR(http_get_decoded(buf, "a"), "1");
	ASSERT_STR(http_get_decoded(buf, "b"), "2");
	ASSERT_STR(http_get_decoded(buf, "c"), "3 ");
	ASSERT_STR(http_get_decoded(buf, "d"), "");
	ASSERT_STR(http_get_decoded(buf, "e"), "");
	return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(parse_http);
	EXEC_TEST(http_get_decoded);

    return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
