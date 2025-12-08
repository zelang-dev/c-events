#include <events.h>
#include "assertions.h"

void *main_main(param_t args) {
	ASSERT_TASK(is_data(args));
	ASSERT_EQU($size(args), 1);
	struct hostent *host = NULL;
	os_worker_t *thrd = events_add_pool(args->object);
	ASSERT_TASK((data_type(thrd) == DATA_PTR));
	ASSERT_TASK((data_type(events_pool()) == DATA_PTR));
	ASSERT_TASK((events_pool() != thrd));
	ASSERT_TASK(((host = async_get_hostbyname(thrd, "dns.google")) != NULL));
	ASSERT_TASK(str_is(gethostbyname_ip(host), "8.8.8.8") || str_is(gethostbyname_ip(host), "8.8.4.4"));
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
