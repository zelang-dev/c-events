#include "events.h"

void _on_exit(int exit_status, int term_signal) {
	fprintf(stderr, "\nProcess exited with status %d, signal %d\n",
		exit_status, term_signal);
}

void *main_main(param_t args) {
	execinfo_t *child = spawn("child_command", "test-dir", NULL, _on_exit);
	if (child != NULL) {
		fprintf(stderr, "\nLaunched process with ID %zu\n", spawn_pid(child));
		while (!spawn_is_finish(child))
			yield_task();
	}

	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
