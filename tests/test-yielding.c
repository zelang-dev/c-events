#include <events.h>
#include "assertions.h"

void *hello_world(param_t args) {
    yielding("Hello");
    return "world";
}

TEST(yielded) {
    generator_t gen = generator(hello_world, 0);
    ASSERT_TRUE((data_type(gen) == DATA_GENERATOR));
    ASSERT_STR("Hello", yielded(gen).char_ptr);
    ASSERT_NULL(yielded(gen).object);
    ASSERT_STR("world", results_for(gen_id()).char_ptr);

    return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(yielded);

    return result;
}

void *main_main(param_t args) {
	TEST_TASK(list());
}

int main(int argc, char **argv) {
	events_init(1024);
	async_task(main_main, 0);
	events_t *loop = events_create(6);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
