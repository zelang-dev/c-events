#include <events.h>
#include "assertions.h"

static int output_count = 0;

void *worker_misc(param_t args) {
	ASSERT_TASK(($size(args) == 3));
	sleep_task(args[0].u_int);
	ASSERT_TASK((str_is("spawn", args[1].char_ptr)));
    return args[2].char_ptr;
}

int _on_exit(int64_t exit_status, int term_signal) {
    ASSERT_EQ(0, exit_status);
    ASSERT_EQ(0, term_signal);
}

int _on_output(fds_t writeto, size_t count, char *outputfrom) {
    output_count++;
	ASSERT_TRUE(str_has(outputfrom, "This is stdout")
		|| str_has(outputfrom, "Sleeping...")
		|| str_has(outputfrom, "`test-dir` argument received"));
	ASSERT_FALSE(str_has(outputfrom, "Exiting"));
}

TEST(spawn) {
	uint32_t res = async_task(worker_misc, 3, 700, "spawn", "finish");
	execinfo_t *child = spawn("child", "test-dir", (spawn_cb)_on_output, (exit_cb)_on_exit);

	ASSERT_TASK((task_is_ready(res) == false));
	ASSERT_TASK((spawn_pid(child) > 0));
	ASSERT_TASK((spawn_is_finish(child) == false));
	while (!spawn_is_finish(child))
        yield_task();

	ASSERT_TASK((spawn_is_finish(child) == true));
	while (!task_is_ready(res))
		yield_task();

	ASSERT_TASK((task_is_ready(res) == true));
	ASSERT_TASK(str_is(results_for(res).char_ptr, "finish"));
	ASSERT_TASK((3 == output_count));

    return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(spawn);

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
