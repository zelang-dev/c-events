#include <events.h>
#include "assertions.h"

struct timeval timeout = {3, 0};

static void closed_cb(sockfd_t fd, int event, void *arg)
{
	if (EVENTS_TIMEOUT & event) {
		printf("%s: Timeout!\n", __func__);
		exit(1);
	}

	if (EVENTS_CLOSED & event) {
		printf("%s: detected socket close with success\n", __func__);
		return;
	}

	printf("%s: unable to detect socket close\n", __func__);
	exit(1);
}

int main(int argc, char **argv) {
	events_t *base;
	const char *test = "test string";
	sockfd_t pair[2];
	intptr_t ev;

	events_init(1024);
	if (!(base = events_create(60)))
		return (1);

	/* Create a pair of sockets */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	/* Send some data on socket 0 and immediately close it */
	if (send(pair[0], test, (int)strlen(test)+1, 0) < 0)
		return (1);
	shutdown(pair[0], SHUT_WR);

	/* Dispatch */
	ev = events_add(base, pair[1], EVENTS_CLOSED | EVENTS_TIMEOUT, 5, closed_cb, NULL);
	events_once(base, 60);

	/* Finalize library */
	events_destroy(base);
	events_deinit();

	return 0;
}
