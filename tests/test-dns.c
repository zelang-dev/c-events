#include <events.h>
#include "assertions.h"

void *main_main(param_t args) {
	struct hostent *host = NULL;
	future *thrd = events_create_future(event_loop());
	ASSERT_TASK((data_type(thrd) == DATA_THREAD));
	ASSERT_TASK((data_type(futures_pool()) == DATA_THREAD));
	ASSERT_TASK((futures_pool() == thrd));
	ASSERT_TASK(((host = async_gethostbyname("dns.google")) != NULL));
	ASSERT_TASK(str_is(gethostbyname_ip(host), "8.8.8.8") || str_is(gethostbyname_ip(host), "8.8.4.4"));
	return 0;
}

TEST(queue_work) {
	return events_start(1024, (main_cb)main_main, 0);
}

TEST(list) {
	int result = 0;

	EXEC_TEST(queue_work);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
