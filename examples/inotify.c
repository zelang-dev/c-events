/*
* Modified from https://developer.ibm.com/tutorials/l-ubuntu-inotify/
*/

#include <events.h>

#define EVENT_SIZE  ( sizeof (inotify_t) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s directory\n", argv[0]);
		return 0;
	}

	int length, fd, wd;
	char buffer[BUF_LEN];

	fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init failed");
		return 1;
	}

	wd = inotify_add_watch(fd, argv[1], IN_MODIFY | IN_CREATE | IN_DELETE);
	if (wd < 0) {
		perror("inotify_add_watch failed");
		return 1;
	}

	length = read(fd, buffer, BUF_LEN);
	if (length < 0) {
		perror("read failed");
		return 1;
	}

	inotify_t *event = (inotify_t *)buffer;
	do {
		if (!inotify_length(event))
			break;

		uint32_t mask = inotify_mask(event);
		char *path = inotify_name(event);
		if (inotify_added(event)) {
			if (mask & IN_ISDIR) {
				printf("The directory %s was created.\n", path);
			} else {
				printf("The file %s was created.\n", path);
			}
		} else if (inotify_removed(event)) {
			if (mask & IN_ISDIR) {
				printf("The directory %s was deleted.\n", path);
			} else {
				printf("The file %s was deleted.\n", path);
			}
		} else if (inotify_modified(event)) {
			if (mask & IN_ISDIR) {
				printf("The directory %s was modified.\n", path);
			} else {
				printf("The file %s was modified.\n", path);
			}
		}
	} while ((event = inotify_next(event)) != NULL);

	(void)inotify_rm_watch(fd, wd);
	(void)close(fd);

	exit(0);
}