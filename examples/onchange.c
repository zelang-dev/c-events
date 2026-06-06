/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/onchange.c, but actually working correctly,
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/onchange/main.c */

#include <events.h>

const char *command;

void run_command(int wd, events_monitors events, const char *filename, void *filter) {
	cerr(CLR"Change detected in: %s ", fs_events_path(wd));

	if (events & WATCH_ADDED || events & WATCH_REMOVED)
		cerr("renamed");
	if (events & WATCH_MODIFIED)
		cerr("changed");

	cerr(" %s"CLR_LN, filename ? filename : "");
    system(command);
}

void main_main(param_t params) {
	array_t args = (array_t)params->object;
	int argc = args[0].integer;
	char **argv = args[1].array_char;
	$delete(args);

	command = argv[1];
	while (argc-- > 2) {
        cerr("Adding watch on %s\n", argv[argc]);
        fs_events(argv[argc], run_command, null);
    }
}

int main(int argc, char **argv) {
    if (argc <= 2) {
        return cerr("Usage: %s <command> <file1> [file2 ...]\n", argv[0]);
	}

	return events_start(1024, main_main, arrays(2, casting(argc), argv));
}
