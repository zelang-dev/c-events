/*
 * XXX This sample code was once meant to show how to use the basic Libevent
 * interfaces, but it never worked on non-Unix platforms, and some of the
 * interfaces have changed since it was first written.  It should probably
 * be removed or replaced with something better.
 *
 * Compile with:
 * cc -I/usr/local/include -o time-test time-test.c -L/usr/local/lib -levent
 */

#include <events.h>

struct timeval lasttime;
int event_is_persistent = 1;

#define	get_timersub(tvp, uvp, vvp)		\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {		\
			(vvp)->tv_sec--;			\
			(vvp)->tv_usec += 1000000;	\
		}								\
	} while (0)

static void timeout_cb(actor_t *actor, void *args) {
	struct timeval newtime, difference;
	double elapsed;

	events_timeofday(&newtime, NULL);
	get_timersub(&newtime, &lasttime, &difference);
	elapsed = difference.tv_sec +
		(difference.tv_usec / 1.0e6);

	printf("timeout_cb called at %d: %.3f seconds elapsed.\n",
		(int)newtime.tv_sec, elapsed);
	lasttime = newtime;

	if (event_is_persistent)
		events_repeat_actor(actor, seconds(2));
	else
		events_clear_actor(actor);

	event_is_persistent = 0;
}

int main(int argc, char **argv) {
	events_t *base;

	/* Initialize the event library */
	events_init(1024);

	base = events_create(2);

	/* Initialize one event */
	events_actor(base, 500, timeout_cb, NULL);

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	events_timeofday(&lasttime, NULL);
	while (events_is_running(base))
		events_once(base, 0);

	/* Finalize library */
	events_destroy(base);
	events_deinit();

	return (0);
}
