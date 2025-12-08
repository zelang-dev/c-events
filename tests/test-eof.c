#include <events.h>
#include "assertions.h"

int test_okay = 1;
int called = 0;
struct timeval timeout = {60, 0};

static void read_cb(fds_t fd, int event, void *ar) {
	char buf[256];
	int len;

	if (EVENTS_TIMEOUT & event) {
		printf("%s: Timeout!\n", __func__);
		events_del(fd);
		return;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	printf("%s: read %d%s\n", __func__,
		len, len ? "" : " - means EOF");

	if (EVENTS_CLOSED & event && !len) {
		printf("%s: Closed!\n", __func__);
		events_set_event(fd, EVENTS_TIMEOUT);
		test_okay = 0;
	}

	called++;
}

int main(int argc, char **argv) {
	events_t *base;
	const char *test = "test string";
	fds_t pair[2];

	/* Initialize the event library */
	if (events_init(1024) || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	if (!(base = events_create(60)))
		return (1);

	if (send(pair[0], test, (int)strlen(test) + 1, 0) < 0)
		return (1);
	shutdown(pair[0], SHUT_WR);

	/* Initialize one event */
	events_add(base, pair[1], EVENTS_READ | EVENTS_TIMEOUT, 1, read_cb, NULL);
	while (events_is_running(base))
		events_once(base, 60);

	/* Finalize library */
	events_destroy(base);
	events_deinit();

	if (test_okay == 0 && called > 1)
		printf("\npass\n");

	return (test_okay);
}
