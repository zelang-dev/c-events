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

void *main_main(param_t args) {
    int cid[10], i;

	task_group_t *wg = task_group();
	ASSERT_TASK(is_data(wg->group));
    for (i = 0; i < 10; i++) {
		cid[i] = async_task(worker, 1, i);
		ASSERT_EQU(cid[i], i + 2);
    }
	ASSERT_EQU($size(wg->group), 10);
    array_t wgr = tasks_wait(wg);
	ASSERT_TASK(is_data(wgr));
	ASSERT_TASK((is_data(wg->group) == false));
	ASSERT_EQU($size(wgr), 2);
	ASSERT_EQU(32, results_for(cid[2]).integer);
	ASSERT_TASK(str_is("hello world", results_for(cid[1]).char_ptr));

	return 0;
}

TEST(task_group) {
	events_init(1024);
	async_task(main_main, 0);
	events_t *loop = events_create(6);
	async_run(loop);
	events_destroy(loop);

    return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(task_group);

    return result;
}

int main(int argc, char **argv) {
    TEST_FUNC(list());
}
