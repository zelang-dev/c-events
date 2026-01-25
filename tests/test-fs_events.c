#include <events.h>
#include "assertions.h"

const char *watch_path = "watchdir";
static int watch_count = 0;

void *worker_misc(param_t args) {
    ASSERT_TASK(($size(args) > 1));
    sleep_task(args[0].u_int);
	ASSERT_TASK(str_is("event", args[1].char_ptr));
    yield_task();
    return "fs_events";
}

int watch_handler(int wd, int events, const char *filename, void *filter) {
    ASSERT_STR("watchdir", fs_events_path(wd));
	watch_count++;

	if (events & WATCH_ADDED) {
		ASSERT_TASK((str_has(filename, "file1.txt")));
	}

	if (events & WATCH_REMOVED)
		ASSERT_TASK((str_has(filename, "file1.txt") || str_has(filename, "watchdir")));

	if (events & WATCH_MODIFIED)
		ASSERT_TASK((str_has(filename, "file1.txt")));

	return 0;
}

TEST(fs_events) {
    char filepath[ARRAY_SIZE] = {0};
    int i = 0;
	uint32_t res = async_task(worker_misc, 2, 1000, "event");
	ASSERT_EQ(0, fs_mkdir(watch_path, 0700));
	ASSERT_FALSE(task_is_ready(res));

	int rid = fs_events(watch_path, (watch_cb)watch_handler, null);
	ASSERT_FALSE(task_is_ready(res));

	sleep_task(1);
	snprintf(filepath, ARRAY_SIZE, "%s/file%d.txt", watch_path, 1);
	ASSERT_EQ(5, fs_writefile(filepath, "hello"));

	sleep_task(200);
	ASSERT_EQ(0, fs_unlink(filepath));

	sleep_task(500);
	ASSERT_EQ(0, fs_rmdir(watch_path));

	while (!task_is_ready(res))
        yield_task();

	ASSERT_EQ(0, fs_events_cancel(rid));
    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "fs_events");
    ASSERT_EQ(3, watch_count);

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(fs_events);

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
