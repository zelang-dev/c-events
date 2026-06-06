
/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/uvcat.c
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/uvcat/main.c */

#include <events.h>

void main_main(param_t args) {
	char text[1024];
	int len, fd = fs_open(args->const_char_ptr, O_RDONLY, 0);
	if (fd > 0) {
		if ((len = fs_read(fd, text, sizeof(text))) > 0)
			fs_write(STDOUT_FILENO, text, len);

		(void)fs_close(fd);
		return;
	}
	abort();
}

int main(int argc, char **argv) {
	if (argc < 2) {
		cerr("usage: _cat filepath\n");
		exit(1);
	}

	events_start(1024, main_main, argv[1]);
	printf(LN_CLR CLR_LN);
	return 0;
}
