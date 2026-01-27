#include <events.h>
#include "assertions.h"

TEST(parse_uri) {
    uri_t *url = parse_uri("http://secret:hideout@zelang.dev:80/this/is/a/very/deep/directory/structure/and/file.html?lots=1&of=2&parameters=3&too=4&here=5#some_page_ref123");
    ASSERT_TRUE((data_type(url) == DATA_TCP));
    ASSERT_STR("http", url->scheme);
    ASSERT_STR("zelang.dev", url->host);
    ASSERT_STR("secret", url->user);
    ASSERT_STR("hideout", url->pass);
    ASSERT_EQ(80, url->port);
    ASSERT_STR("/this/is/a/very/deep/directory/structure/and/file.html", url->path);
    ASSERT_STR("lots=1&of=2&parameters=3&too=4&here=5", url->query);
    ASSERT_STR("some_page_ref123", url->fragment);

	char **token, **token_part;
	int x, i = 0;
	ASSERT_NOTNULL((token = str_slice(url->query, "&", &i)));
	for (x = 0; x < i; x++) {
		token_part = str_slice(token[x], "=", NULL);
		switch (x) {
			case 0:
				ASSERT_STR(token_part[0], "lots");
				ASSERT_STR(token_part[1], "1");
				break;
			case 1:
				ASSERT_STR(token_part[0], "of");
				ASSERT_STR(token_part[1], "2");
				break;
			case 2:
				ASSERT_STR(token_part[0], "parameters");
				ASSERT_STR(token_part[1], "3");
				break;
			case 3:
				ASSERT_STR(token_part[0], "too");
				ASSERT_STR(token_part[1], "4");
				break;
			case 4:
				ASSERT_STR(token_part[0], "here");
				ASSERT_STR(token_part[1], "5");
				break;
		}
	}

    fileinfo_t *fileinfo = pathinfo(url->path);
	ASSERT_TRUE((data_type(fileinfo) == DATA_FILEINFO));
    ASSERT_STR("/this/is/a/very/deep/directory/structure/and", fileinfo->dirname);
    ASSERT_STR("and", fileinfo->base);
    ASSERT_STR("file.html", fileinfo->filename);
    ASSERT_STR("html", fileinfo->extension);
    return 0;
}

TEST(str_explode) {
	const char *pizza = "piece1 piece2 piece3 piece4 piece5 piece6";
	array_t pieces = null;
	ASSERT_TRUE(is_data(pieces = str_explode(pizza, " ")));
	ASSERT_TRUE(($size(pieces) == 6));
	ASSERT_STR("piece1", pieces[0].char_ptr);
	ASSERT_STR("piece3", pieces[2].char_ptr);
	ASSERT_STR("piece6", pieces[5].char_ptr);

	$delete(pieces);
	ASSERT_FALSE(is_data(pieces));

	return 0;
}

TEST(str_repeat) {
	ASSERT_STR(str_repeat("-=", 10), "-=-=-=-=-=-=-=-=-=-=");
	return 0;
}

TEST(str_pad) {
	char *input = "Alien";
	ASSERT_STR(str_pad(input, 10, null, 0), "Alien     ");
	ASSERT_STR(str_pad(input, 10, "-=", STR_PAD_LEFT), "-=-=-Alien");
	ASSERT_STR(str_pad(input, 10, "_", STR_PAD_BOTH), "__Alien___");
	ASSERT_STR(str_pad(input, 6, "___", 0), "Alien_");
	ASSERT_STR(str_pad(input, 3, "*", 0), "Alien");
	return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(parse_uri);
	EXEC_TEST(str_explode);
	EXEC_TEST(str_repeat);
	EXEC_TEST(str_pad);

    return result;
}

void *main_main(param_t args) {
	TEST_TASK(list());
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(6);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
