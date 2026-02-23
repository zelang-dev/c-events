#include "assertions.h"

void *worker_client(param_t args) {
	int server = 0;
	char buf[10] = {0};
    ASSERT_WORKER(($size(args) == 3));

    sleep_task(args[0].u_int);
	ASSERT_WORKER(str_is("worker_client", args[1].char_ptr));

	ASSERT_WORKER(is_pipe(server = uds_connect("unix://test.sock")));
	ASSERT_WORKER((async_read(server, buf, sizeof(buf)) == 5));
	ASSERT_WORKER(str_is("world", buf));
	ASSERT_WORKER((async_write(server, "hello", 5) == 5));
	sleep_task(100);

    return args[2].char_ptr;
}

void worker_connected(int socket) {
	char buf[10] = {0};
	ASSERT_WORKER((async_write(socket, "world", 5) == 5));
	ASSERT_WORKER((async_read(socket, buf, sizeof(buf)) == 5));
    ASSERT_WORKER(str_is("hello", buf));

    return 0;
}

TEST(pipe_listen) {
    int client, socket;
	uint32_t res = async_task(worker_client, 3, 200, "worker_client", "finish");

    ASSERT_TRUE(socket_is_uds(socket = uds_bind("test.sock", 0)));
    ASSERT_TRUE(is_pipe(client = uds_accept(socket, 128)));
    ASSERT_FALSE(socket_is_udp(client));

	ASSERT_FALSE(task_is_ready(res));
	uds_handler(worker_connected, casting(client));
	ASSERT_FALSE(task_is_ready(res));

	while (!task_is_ready(res))
        yield_task();

    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(pipe_listen);

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