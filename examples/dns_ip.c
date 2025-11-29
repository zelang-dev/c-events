
#include <events.h>

void *main_main(param_t args) {
	os_worker_t *thrd = events_addthreads_loop(args[0].object);
	char *ip = async_gethostbyname(thrd, args[1].char_ptr);
	printf("\n> %s <\n", ip);
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: dns_ip hostname\n");
		exit(1);
	}

	events_init(1024);
	events_t *loop = events_create(6);
	async_task(main_main, 2, loop, argv[1]);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
