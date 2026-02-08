#include "assertions.h"

void *worker(param_t args) {
	int id = args[0].integer + 1;

	sleep_task(1000);
    if (id == 4)
        return casting(32);
    else if (id == 3)
        return "hello world";

    return 0;
}

TEST(waitfor) {
    int cid[30], i;

    waitgroup_t wg = waitgroup(10);
	ASSERT_TRUE(is_waitgroup(wg));

	for (i = 0; i < 30; i++) {
		cid[i] = go(worker, 1, i);
    }
	ASSERT_TRUE((tasks_count(wg) == 30));

	array_t wgr = waitfor(wg);
    ASSERT_TRUE(is_data(wgr));
	ASSERT_FALSE(is_waitgroup(wg));
    ASSERT_EQ($size(wgr), 2);

	ASSERT_EQ(32, results_for(cid[3]).integer);
    ASSERT_STR("hello world", results_for(cid[2]).char_ptr);

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(waitfor);

    return result;
}

void *main_main(param_t args) {
	TEST_TASK(list());
}

int main(int argc, char **argv) {
	events_init(1024);
	async_task(main_main, 0);
	waitgroup_t wg = waitgroup(10);
	ASSERT_FALSE(is_waitgroup(wg));

	events_t *loop = events_thread_init();
	async_run(loop);
	events_destroy(loop);

	return 0;
}