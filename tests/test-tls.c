#include "assertions.h"

void *worker_client(param_t args) {
	int server;
	process_t child;
	ASSERT_TASK(($size(args) == 4));
	sleep_task(args[0].u_int);

	ASSERT_TASK(str_is("tls_client", args[1].char_ptr));
	ASSERT_TASK(((child = exec("./client", null, exec_info(null, true, inherit, inherit, inherit))) > 0));
	sleep_task(1000);

	return args[2].char_ptr;
}

int worker_connected(int socket) {
	ASSERT_TRUE((tls_writer(socket, "world", 0) == 5));
	char data[10] = {0};
	tls_reader(socket, data, sizeof(data));
	ASSERT_TRUE(str_is("hello", data));

    return 0;
}

TEST(tls_accept) {
    int client, socket;
	ASSERT_TRUE(socket_is_secure(socket = tls_bind("tls://127.0.0.1:7000", 128)));
	uint32_t res = async_task(worker_client, 4, 500, "tls_client", "finish", socket);
	ASSERT_TRUE(socket_is_secure(client = tls_accept(socket, null, null)));

	if (socket_is_secure(client)) {
		tls_handler((tls_client_cb)worker_connected, client);
	}

	ASSERT_FALSE(task_is_ready(res));
	while (!task_is_ready(res))
		yield_task();

    ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(tls_accept);

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
