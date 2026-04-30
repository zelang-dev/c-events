#include <map.h>
#include "test_assert.h"

TEST(slice) {
	map_array_t primes = map_array(ar_integer, 6, 2, 3, 5, 7, 11, 13);
	ASSERT_TRUE(is_type(primes, DATA_MAP));
    ASSERT_UEQ(6, map_count(primes));
    println(1, primes);

    slice_t part = slice(primes, 2, 5);
	ASSERT_TRUE(is_type(part, DATA_MAP));
    ASSERT_UEQ(3, map_count(part));
    println(1, part);

    ASSERT_UEQ(5, slice_get(part, 0).max_size);
    ASSERT_UEQ(7, slice_get(part, 1).max_size);
    ASSERT_UEQ(11, slice_get(part, 2).max_size);

    return exit_scope();
}

TEST(list) {
    int result = 0;

    EXEC_TEST(slice);

    return result;
}

int main(int argc, char **argv) {
    TEST_FUNC(list());
}
