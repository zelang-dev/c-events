#undef NO_RPMALLOC
#include "assertions.h"

int some_func(int args) {
	return args * 2;
}

TEST(arrays) {
	array_t d = arrays(8, "hello", "world", 32,
		"hello world", 123, some_func,
		"four", 600);
	ASSERT_TRUE(is_data(d));
	ASSERT_TRUE(($size(d) == 8));

	char *ar1 = d[0].char_ptr;
	char *ar2 = d[1].char_ptr;
	size_t num = d[2].max_size;

	ASSERT_EQ(str_is(ar1, "hello"), true);
	ASSERT_EQ(str_is(ar2, "world"), true);
	ASSERT_UEQ(num, 32);


	char *data = "hello again!";
	ASSERT_STR("hello world", d[3].char_ptr);
	ASSERT_UEQ(246, ((intptr_func_t)d[5].func)(d[4].max_size));
	ASSERT_STR("four", d[6].char_ptr);
	ASSERT_UEQ(600, d[7].max_size);

	d[4].char_ptr = data;
	ASSERT_STR("hello again!", d[4].char_ptr);

	d[7].char_ptr = "string 600";
	ASSERT_STR("string 600", d[7].char_ptr);

	$append(d, 256);
	ASSERT_UEQ(256, d[8].max_size);
	ASSERT_TRUE(($size(d) == 9));
	$remove(d, 7);
	ASSERT_TRUE(($size(d) == 8));
	ASSERT_UEQ(256, d[7].max_size);

	$delete(d);
	ASSERT_FALSE(is_data(d));

	return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(arrays);

	return result;
}

int main(int argc, char **argv) {
	events_set_allocator(rp_malloc, rp_realloc, rp_calloc, rpfree);
	TEST_FUNC(list());
}
