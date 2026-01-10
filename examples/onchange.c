#include <events.h>

const char *command;

void run_command(filefd_t fd, events_monitors events, const char *filename) {
	fprintf(stderr, "Change detected in %s: ", fs_watch_path());

	if (events & WATCH_ADDED || events & WATCH_REMOVED)
        fprintf(stderr, "renamed");
	if (events & WATCH_MODIFIED)
        fprintf(stderr, "changed");

	fprintf(stderr, " %s\n", filename ? filename : "");
    system(command);
}

void *main_main(param_t args) {
	int argc = args[0].integer;
	char **argv = args[1].array_char;

	command = argv[1];
	while (argc-- > 2) {
        fprintf(stderr, "Adding watch on %s\n", argv[argc]);
        fs_events(argv[argc], run_command);
    }

    return ((int)sleep_task(100000) < 0 ? task_err_code(): 0);
}

int main(int argc, char **argv) {
    if (argc <= 2) {
        fprintf(stderr, "Usage: %s <command> <file1> [file2 ...]\n", argv[0]);
        return 1;
	}

	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 2, casting(argc), argv);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
