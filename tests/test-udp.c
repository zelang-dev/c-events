#include "assertions.h"

/* modified test version of https://github.com/zelang-dev/c-asio/tree/main/tests/test-udp.c */

void *worker_client(param_t args) {
    int nread, client = 0;
	udp_t packets = null;
	char buf[Kb(8)] = {0};
	ASSERT_TASK(($size(args) == 3));
	sleep_task(args[0].u_int);

	ASSERT_TASK(str_is("worker_client", args[1].char_ptr));
	ASSERT_TASK(socket_is_udp(client = udp_bind("127.0.0.1:7777", 0)));
	sleep_task(200);

	udp_with(client, "127.0.0.2:9999", 0);
	ASSERT_TASK((async_sendto(client, "hello", 5) == 5));
	ASSERT_TASK(((nread = async_recvfrom(client, buf, sizeof(buf), &packets)) == 5));
	ASSERT_TASK((data_type(packets) == DATA_UDP));
	ASSERT_TASK(str_is("world", udp_message(packets)));

    return args[2].char_ptr;
}

void *worker_connected(udp_t client) {
	ASSERT_TASK(str_is("hello", udp_message(client)));
	ASSERT_TASK((udp_send(client, "world", 5) == 5));
	sleep_task(500);

	return 0;
}

TEST(udp_recv) {
	int server = 0;
	udp_t client = null;
	uint32_t res = async_task(worker_client, 3, 1000, "worker_client", "finish");
	ASSERT_FALSE(socket_is_udp(server));
	ASSERT_TRUE(socket_is_udp(server = udp_bind("127.0.0.2:9999", 0)));

	ASSERT_FALSE(task_is_ready(res));
	ASSERT_TRUE((data_type(client = udp_recv(server)) == DATA_UDP));

    ASSERT_FALSE(task_is_ready(res));
	udp_handler((udp_packet_cb)worker_connected, client);

	while (!task_is_ready(res))
        yield_task();

	ASSERT_TRUE(task_is_ready(res));
    ASSERT_STR(results_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

	EXEC_TEST(udp_recv);

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
