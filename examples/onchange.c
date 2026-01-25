/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/onchange.c, but actually working correctly,
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/onchange/main.c */

#include <events.h>

const char *command;

void run_command(int wd, events_monitors events, const char *filename, void *filter) {
	fprintf(stderr, "Change detected in: %s ", fs_events_path(wd));

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
        fs_events(argv[argc], run_command, null);
    }

    return 0;
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
