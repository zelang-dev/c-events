
#include <events.h>

void showfile(int fd, events_monitors events, const char *filename) {
	if (events & WATCH_ADDED)
		printf("The file %s was created.\n", filename);
	else if (events & WATCH_REMOVED)
		printf("The file %s was deleted.\n", filename);
	else if (events & WATCH_MODIFIED)
		printf("The file %s was modified.\n", filename);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s directory\n", argv[0]);
		return 0;
	}

	/* init events */
	events_init(1024);

	/* create loop */
	events_t *loop = events_create(1);

	/* add watch folder and action */
	int fd, wd = events_watch(loop, argv[1], showfile);
	if (wd < 0) {
		perror("events_watch failed");
		return 1;
	}

	/* loop */
	while (events_is_running(loop))
		events_once(loop, 0);

	/* cleanup */
	events_destroy(loop);

	(void)inotify_rm_watch(fd, wd);
	(void)close(fd);

	exit(0);
}