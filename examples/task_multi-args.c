#include <events.h>

void *worker(param_t args) {
    int i, count = args[0].integer;
    char *text = args[1].char_ptr;

    for (i = 0; i < count; i++) {
        printf("%s\n", text);
		sleep_task(10);
    }
    return 0;
}

int main(int argc, char **argv) {
	events_init(1024);

	async_task(worker, 2, 4, "a");
	async_task(worker, 2, 2, "b");
	async_task(worker, 2, 3, "c");

	events_t *base = events_create(6);
	while (events_is_running(base)) {
		events_once(base, 1);
	}
	events_destroy(base);

	return 0;
}
