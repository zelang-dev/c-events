
/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/uvcat.c
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/uvcat/main.c */

#include <events.h>

void *main_main(param_t args) {
	char text[1024];
	int len, fd = fs_open(args[0].const_char_ptr, O_RDONLY, 0);
	if (fd > 0) {
		if ((len = fs_read(fd, text, sizeof(text))) > 0)
			fs_write(STDOUT_FILENO, text, len);

		return casting(fs_close(fd));
	}

	return casting(fd);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: _cat filepath\n");
		exit(1);
	}

	events_init(1024);
	events_t *loop = events_create(6);
	async_task(main_main, 1, argv[1]);
	async_run(loop);
	events_destroy(loop);

	printf(LN_CLR CLR_LN);
	return 0;
}
