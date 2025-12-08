/*
 * This sample code shows how to use Libevent to read from a named pipe.
 * XXX This code could make better use of the Libevent interfaces.
 *
 * XXX This does not work on Windows; ignore everything inside the _WIN32 block.
 *
 * On UNIX, compile with:
 * cc -I/usr/local/include -o event-read-fifo event-read-fifo.c \
 *     -L/usr/local/lib -levent
 */

#include <events.h>

static void fifo_read(fds_t fd, int event, void *arg) {
	char buf[255];
	int len;

	fprintf(stderr, "fifo_read called with fd: %d, event: %d, arg: %p\n", socket2fd(fd), event, arg);
	len = read(fd, buf, sizeof(buf) - 1);
	if (len <= 0) {
		if (len == -1)
			perror("read");
		else if (len == 0)
			fprintf(stderr, "Connection closed\n");
		events_del(fd);
		return;
	}

	buf[len] = '\0';
	fprintf(stdout, "Read: %s\n", buf);
}

static void signal_cb(fds_t sig, int event, void *arg) {
	events_t *loop = events_loop(sig);
	unlink(mkfifo_name());
	events_destroy(loop);
}

int main(int argc, char **argv) {
	events_t *base;
	struct stat st;
	const char *fifo = "event.fifo";
	int socket;

	if (lstat(fifo, &st) == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			errno = EEXIST;
			perror("lstat");
			exit(1);
		}
	}

	unlink(fifo);
	if (mkfifo(fifo, 0600) == -1) {
		perror("mkfifo");
		exit(1);
	}

	/* Initialize the event library */
	base = events_create(6);

	socket = open(fifo, O_RDWR | O_NONBLOCK, 0);
	if (socket == -1) {
		perror("open");
		unlink(mkfifo_name());
		events_destroy(base);
		exit(1);
	}

	fprintf(stderr, "Write data to %s\n", mkfifo_name());

	/* catch SIGINT so that event.fifo can be cleaned up*/
	events_add(base, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL);

	/* Initialize one event */
	events_add(base, socket, EVENTS_READ, 0, fifo_read, NULL);

	while (events_is_running(base)) {
		events_once(base, 1);
	}

	close(socket);
	unlink(fifo);
	events_destroy(base);

	return (0);
}
