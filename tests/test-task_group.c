#include <events.h>
#include "assertions.h"

void *worker(param_t args) {
	int id = task_id();
	ASSERT_EQU(id, args[0].integer + 2);

	sleep_task(1000);
    if (id == 4)
        return casting(32);
    else if (id == 3)
        return "hello world";

    return 0;
}

TEST(task_group) {
	int cid[10], i;

	task_group_t *wg = task_group();
	ASSERT_TASK((is_group(wg) == true));
	for (i = 0; i < 10; i++) {
		cid[i] = async_task(worker, 1, i);
		ASSERT_EQ(cid[i], i + 2);
	}
	ASSERT_EQ(tasks_count(wg), 10);
	array_t wgr = tasks_wait(wg);
	ASSERT_TASK(is_data(wgr));
	ASSERT_TASK((is_group(wg) == false));
	ASSERT_EQ($size(wgr), 2);
	ASSERT_EQ(32, results_for(cid[2]).integer);
	ASSERT_TASK(str_is("hello world", results_for(cid[1]).char_ptr));

	return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(task_group);

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
