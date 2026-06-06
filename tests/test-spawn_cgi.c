#include <events.h>
#include "assertions.h"

static int output_count = 0;

void *worker_misc(param_t args) {
	ASSERT_TASK(($size(args) == 3));
	delay(args[0].u_int);
	ASSERT_TASK((str_is("spawn", args[1].char_ptr)));
    return args[2].char_ptr;
}

int _on_exit(int64_t exit_status, int term_signal) {
    ASSERT_EQ(0, exit_status);
	ASSERT_EQ(0, term_signal);

	return 0;
}

int _on_output(fds_t writeto, size_t count, char *outputfrom) {
    output_count++;
	ASSERT_TRUE(str_has(outputfrom, "The REQUEST_METHOD GET")
		|| str_has(outputfrom, "Sleeping... ZeLang!")
		|| str_has(outputfrom, "CONTENT_LENGTH `14`")
		|| str_has(outputfrom, "`php.js` argument received"));
	ASSERT_FALSE(str_has(outputfrom, "environment"));

	return 0;
}

TEST(spawn) {
	size_t len = 0;
	uint32_t res = async_task(worker_misc, 3, 700, "spawn", "finish");
	execinfo_t *child = spawn_cgi("child_cgi", "php.js",
		exec_addenv(null, &len, 3, kv("REQUEST_METHOD", "GET"), kv("HTTP_X_POWER_BY", "ZeLang"), kv("CONTENT_LENGTH", "14")),
		(spawn_cb)_on_output, (exit_cb)_on_exit);

	ASSERT_TASK((task_is_ready(res) == false));
	ASSERT_TASK((spawn_pid(child) > 0));
	ASSERT_TASK((spawn_is_finish(child) == false));
	while (!spawn_is_finish(child))
        yield();

	ASSERT_TASK((spawn_is_finish(child) == true));
	while (!task_is_ready(res))
		yield();

	ASSERT_TASK((task_is_ready(res) == true));
	ASSERT_TASK(str_is(results_for(res).char_ptr, "finish"));
	ASSERT_TASK((4 == output_count));

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
	return events_start(1024, (main_cb)main_main, 0);
}