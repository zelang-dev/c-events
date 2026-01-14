
#include <events.h>

void showfile(int fd, events_monitors events, const char *filename) {
	if (events & WATCH_ADDED)
		printf("The file %s was created."CLR_LN, filename);
	else if (events & WATCH_REMOVED)
		printf("The file %s was deleted."CLR_LN, filename);
	else if (events & WATCH_MODIFIED)
		printf("The file %s was modified."CLR_LN, filename);

	if (events & WATCH_REMOVED)
		events_del(fd);
}

void *main_main(param_t args) {
	/* create loop */
	events_t *loop = args[0].object;

	/* add watch folder and action */
	int fd = events_watch(loop, args[1].const_char_ptr, showfile);
	if (fd < 0) {
		perror("events_watch failed");
		return 0;
	}

	/* loop */
	while (events_is_registered(loop, fd)) {
		tasks_info(active_task(), 1);
		yield_task();
	}

	(void)events_del_watch(loop);

	return (0);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s directory\n", argv[0]);
		return 0;
	}

	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 2, loop, argv[1]);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
