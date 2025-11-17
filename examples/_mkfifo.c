
#include "events.h"
/*
Mainly for Windows modified from https://github.com/chocolateboy/mcfifo
*/

#define _USAGE 1
#define _BAD_PROCESS 5

int usage(char *prgname) {
	fprintf(stderr, "usage: %s name cmd [ arg1, ... ]\r\n", prgname);
	return _USAGE;
}

int main(int argc, char **argv) {
	if (argc < 3)
		return usage(argv[0]);

	char *str = str_cat_argv(argc, argv, 3, ","), *piped = argv[1];
	if (mkfifo(piped, 0666) == -1) {
		perror("mkfifo");
		exit(1);
	}

	fprintf(stderr, "Connect to: %s\n", mkfifo_name());
	int other = open(piped, O_RDONLY, 0);
	process_t ps = exec(argv[2], str, exec_info(NULL, false, mkfifo_handle(), mkfifo_handle(), inherit));
	if (ps > 0) {
		exec_wait(ps, INFINITE, NULL);
	} else {
		perror("Error! create process");
		close(other);
		return _BAD_PROCESS;
	}

	close(other);
	unlink(mkfifo_name());
	return 0;
}
