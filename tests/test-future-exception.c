#include "assertions.h"

int some_worker(int args) {
    throw(division_by_zero);
    return args / 0;
}

void *future_check(param_t args) {
    char *arg1 = args[0].char_ptr;
    int num = args[1].integer;
	intptr_func_t worker = (intptr_func_t)args[2].func;

    ASSERT_THREAD(str_is(arg1, "hello world"));
    ASSERT_THREAD((num == 128));
	os_sleep(500);

	ASSERT_THREAD((worker(num) == 256));

    return $(true);
}

TEST(thrd_async) {
	future_t fut = thrd_async(future_check, 3, "hello world", 128, some_worker);

    ASSERT_TRUE(is_future(fut));
    ASSERT_FALSE(thrd_is_done(fut));

    try {
        ASSERT_TRUE(thrd_get(fut).boolean);
    } catch (division_by_zero) {
        ASSERT_STR(err.name, "division_by_zero");
    }

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(thrd_async);

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