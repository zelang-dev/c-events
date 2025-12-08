
#include "events.h"

void *main_main(param_t args) {
	printf("%s", args[0].char_ptr);
	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 1, "Now quitting.\n");
	async_run(loop);
	events_destroy(loop);

	return 0;
}
