#include "assertions.h"

void *worker_client(param_t args) {
	int server = 0;
	char buf[10] = {0};
	ASSERT_TASK(($size(args) == 3));

    sleep_task(args[0].u_int);
	ASSERT_TASK(str_is("worker_client", args[1].char_ptr));

	ASSERT_TASK(socket_is_uds(server = uds_connect("unix://test.sock")));
	ASSERT_TASK((async_read(server, buf, sizeof(buf)) == 5));
	ASSERT_TASK(str_is("world", buf));
	ASSERT_TASK((async_write(server, "hello", 5) == 5));
	sleep_task(100);

    return args[2].char_ptr;
}

int worker_connected(int socket) {
	char buf[10] = {0};
	ASSERT_TRUE((async_write(socket, "world", 5) == 5));
	ASSERT_TRUE((async_read(socket, buf, sizeof(buf)) == 5));
	ASSERT_TRUE(str_is("hello", buf));

    return 0;
}

TEST(uds_accept) {
    int client = 0, socket;
	uint32_t res = async_task(worker_client, 3, 200, "worker_client", "finish");

	ASSERT_TRUE(socket_is_uds(socket = uds_bind("test.sock", 0)));
	ASSERT_FALSE(socket_is_uds(client));
	ASSERT_TRUE(socket_is_uds(client = uds_accept(socket, null)));

	ASSERT_FALSE(task_is_ready(res));
	uds_handler((uds_unix_cb)worker_connected, client);
	ASSERT_FALSE(task_is_ready(res));

	while (!task_is_ready(res))
        yield_task();

    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(uds_accept);

    return result;
}

void *main_main(param_t args) {
	TEST_TASK(list());
}

int main(int argc, char **argv) {
	if (events_init(1024) == 0) {
		async_task(main_main, 0);
		events_t *loop = events_create(6);
		if (!is_empty(loop)) {
			async_run(loop);
			events_destroy(loop);
		}
	} else {
#if __APPLE__ || __MACH__
		perror("todo: Apple M1"CLR_LN);
#else
		perror("main!"CLR_LN);
		return -1;
#endif
	}
	return 0;
}