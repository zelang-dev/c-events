#include "assertions.h"

void *worker_client(param_t args) {
    int server = 0;
    ASSERT_WORKER(($size(args) == 3));

    sleep_task(args[0].u_int);
	ASSERT_WORKER(str_is("worker_client", args[1].char_ptr));

    ASSERT_WORKER(is_pipe(server = stream_connect("unix://test.sock")));
	ASSERT_WORKER(str_is("world", stream_read_wait(server)));
    ASSERT_WORKER((stream_write(server, "hello") == 0));

    return args[2].char_ptr;
}

void *worker_connected(param_t socket) {
    ASSERT_WORKER((stream_write(socket->integer, "world") == 0));
    ASSERT_WORKER(str_is("hello", stream_read_wait(socket->integer)));

    return 0;
}

TEST(pipe_listen) {
    int client, socket;
	uint32_t res = async_task(worker_client, 3, 1000, "worker_client", "finish");

    ASSERT_TRUE(is_pipe(socket = stream_bind("unix://test.sock", 0)));
    ASSERT_TRUE(is_pipe(client = stream_listen(socket, 128)));
    ASSERT_FALSE(is_tls(client));

	ASSERT_FALSE(task_is_ready(res));
	async_task(worker_connected, casting(client));
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