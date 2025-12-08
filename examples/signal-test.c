/*
 * Compile with:
 * cc -I/usr/local/include -o signal-test \
 *   signal-test.c -L/usr/local/lib -levent
 */

#include <events.h>

int called = 0;

static void signal_cb(fds_t sig, int event, void *arg) {
	events_t *loop = events_loop(sig);

	printf("signal_cb: got signal %d\n", socket2fd(sig));

	if (called >= 2) {
		events_del(sig);
	}

	called++;
}

int main(int argc, char **argv) {
	int signal_int = 0;
	events_t *base;
	int ret = 0;

	events_init(1024);

	/* Initialize the event library */
	base = events_create(6);
	if (!base) {
		ret = 1;
		goto out;
	}

	/* Initialize one event */
	signal_int = events_add(base, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL);
	if (signal_int == -1) {
		ret = 2;
		goto out;
	}

	while (events_is_running(base)) {
		events_once(base, 1);
	}

out:
	events_destroy(base);
	return ret;
}
