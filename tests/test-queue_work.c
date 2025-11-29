#include <events.h>
#include "assertions.h"

void *main_main(param_t args) {
	ASSERT_TASK(is_data(args));
	ASSERT_EQU($size(args), 1);
	os_worker_t *thrd = events_addthreads_loop(args->object);
	ASSERT_TASK((data_type(thrd) == DATA_PTR));
	ASSERT_TASK((async_gethostbyname(thrd, "www.google.com") != NULL));
	return 0;
}

TEST(queue_work) {
	events_init(1024);
	events_t *loop = events_create(6);
	async_task(main_main, 1, loop);
	async_run(loop);
	events_destroy(loop);

	return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(queue_work);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
