
#include <events.h>

/*
 * This benchmark tests how quickly we can propagate a write down a chain
 * of socket pairs.  We start by writing to the first socket pair and all
 * events will fire subsequently until the last socket pair has been reached
 * and the benchmark terminates.
 */

static int fired;
events_t *base;
static fds_t *pipes;

#define	get_timersub(tvp, uvp, vvp)		\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {		\
			(vvp)->tv_sec--;			\
			(vvp)->tv_usec += 1000000;	\
		}								\
	} while (0)

static void read_cb(fds_t fd, int events, void *arg) {
	char ch;
	fds_t sock = (fds_t)(intptr_t)arg;
	(void)recv(fd, &ch, sizeof(ch), 0);
	if (sock >= 0) {
		if (send(sock, "e", 1, 0) < 0)
			perror("read_cb send");
	}
	fired++;
	events_del(fd);
}

static struct timeval *run_once(int num_pipes) {
	int i;
	fds_t *cp;
	static struct timeval ts, te, tv_timeout;

	fds_t *pipes = (fds_t *)calloc(num_pipes * 2, sizeof(fds_t));
	if (pipes == NULL) {
		perror("calloc");
		exit(1);
	}

	for (cp = pipes, i = 0; i < num_pipes; i++, cp += 2) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, cp) == -1) {
			perror("socketpair");
			exit(1);
		}
	}

	/* measurements includes event setup */
	events_timeofday(&ts, NULL);

	/* provide a default timeout for events */
	timerclear(&tv_timeout);

	for (cp = pipes, i = 0; i < num_pipes; i++, cp += 2) {
		fds_t fd = i < num_pipes - 1 ? cp[3] : -1;
		events_add(base, cp[0], EVENTS_READ, 0, read_cb, casting(fd));
	}

	fired = 0;

	/* kick everything off with a single write */
	if (send(pipes[1], "e", 1, 0) < 0)
		perror("send");

	events_once(base, 1);

	events_timeofday(&te, NULL);
	get_timersub(&te, &ts, &te);

	for (cp = pipes, i = 0; i < num_pipes; i++, cp += 2) {
		close(cp[0]);
		close(cp[1]);
	}

	free(pipes);
	return (&te);
}

int main(int argc, char **argv) {
	int i, c;
	struct timeval *tv;
	int num_pipes = 100;

	/* init events */
	events_init(1024);
	base = events_create(60);
	for (i = 0; i < 25; i++) {
		tv = run_once(num_pipes);
		if (tv == NULL)
			exit(1);
		fprintf(stdout, "%ld\n",
			tv->tv_sec * 1000000L + tv->tv_usec);
	}
	events_destroy(base);
	events_deinit();

	exit(0);
}
