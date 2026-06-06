
#include <events.h>

void showfile(int fd, events_monitors events, const char *filename, void *filter) {
	(void)filter;

	if (events & WATCH_ADDED)
		printf("The file %s was created."CLR_LN, filename);
	else if (events & WATCH_REMOVED)
		printf("The file %s was deleted."CLR_LN, filename);
	else if (events & WATCH_MODIFIED)
		printf("The file %s was modified."CLR_LN, filename);
	else if (events & WATCH_MOVED)
		printf("The file %s was moved."CLR_LN, filename);

	if (events & WATCH_REMOVED)
		events_remove(fd);
}

void main_main(param_t args) {
	/* create loop */
	events_t *loop = event_loop();

	/* add watch folder and action */
	int fd = events_watch(loop, args->const_char_ptr, showfile, null);
	if (fd < 0) {
		perror("events_watch failed");
		return;
	}

	printf("\nNumber of directories beening watched recursively: %d\n", events_watch_count(fd));

	/* loop */
	while (events_is_watching(fd)) {
		yield_active_info();
	}

	(void)events_del_watch(loop);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		return cout("Usage: %s directory\n", argv[0]);
	}

	return events_start(1024, main_main, argv[1]);
}
