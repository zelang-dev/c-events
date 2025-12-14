#include <events.h>
#include "assertions.h"

/******hello  world******/

char *buf = "blablabla";
char *path = "write.temp";

void *worker3(param_t args) {
	ASSERT_TASK(($size(args) == 2));
	sleep_task(args[0].u_int);
	ASSERT_TASK((args[0].u_int == 500));
	ASSERT_TASK(str_is("worker", args[1].char_ptr));
	return "finish";
}

TEST(fs_open) {
	char text[2048];
	uint32_t res = async_task(worker3, 2, 500, "worker");
	ASSERT_EQ(fs_open("does_not_exist", O_RDONLY, 0), TASK_ERRED);
	int fd = fs_open(__FILE__, O_RDONLY, 0);
	ASSERT_TRUE((fd > 0));
	fs_read(fd, text, sizeof(text));
	ASSERT_STR("/******hello  world******/", str_trim_at(text, str_pos(text, "/*"), 26));
	while (!task_is_ready(res)) {
		yield_task();
	}

	ASSERT_TRUE(task_is_ready(res));
	ASSERT_STR(results_for(res).char_ptr, "finish");

	return 0;
}

void *worker(param_t args) {
    ASSERT_TASK(str_is("hello world", args->char_ptr));
    return "done";
}

TEST(fs_close) {
    uint32_t res = async_task(worker, 1, "hello world");
    ASSERT_TRUE((res > task_id()));
    ASSERT_FALSE(task_is_ready(res));
    int fd = fs_open(__FILE__, O_RDONLY, 0);
    ASSERT_TRUE((fd > 0));
    ASSERT_EQ(0, fs_close(fd));

    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "done");
    ASSERT_EQ(TASK_ERRED, fs_close(fd));

    return 0;
}

void *worker2(param_t args) {
    ASSERT_TASK(($size(args) == 0));
    sleep_task(600);
    return "hello world";
}

TEST(fs_write_read) {
	char text[22] = {0};
	uint32_t res = async_task(worker2, 0);
    int fd = fs_open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_FALSE(task_is_ready(res));
    ASSERT_TRUE((fd > 0));
	ASSERT_EQ(9, fs_write(fd, buf, strlen(buf)));
    ASSERT_EQ(0, fs_close(fd));
	fd = fs_open(path, O_RDONLY, 0);
	ASSERT_TRUE((fd > 0));
	ASSERT_EQ(9, fs_read(fd, text, sizeof(text)));
	ASSERT_STR("blablabla", text);
    ASSERT_EQ(0, fs_close(fd));
	ASSERT_EQ(0, fs_unlink(path));
	while (!task_is_ready(res)) {
		yield_task();
    }

    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "hello world");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(fs_open);
    EXEC_TEST(fs_close);
    EXEC_TEST(fs_write_read);

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
