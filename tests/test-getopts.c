#include <events.h>
#include "assertions.h"

TEST(getopts) {
	ASSERT_TRUE(getopt_has(NULL, true));
	ASSERT_STR("garbage", getopts());
	ASSERT_TRUE(getopt_has("-n", false));
	ASSERT_STR("nothing", getopts());
	ASSERT_TRUE(getopt_has("-bool", true));
	ASSERT_STR("-bool", getopts());

	return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(getopts);

    return result;
}

int main(int argc, char **argv) {
	getopt_arguments_set(argc, argv);
	getopt_message_set("\tgarbage -n nothing -bool\n", 3, false);
	TEST_FUNC(list());
}
