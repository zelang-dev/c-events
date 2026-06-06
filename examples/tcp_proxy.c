#include <events.h>

char *server;
int local, port;

void *rwtask(param_t v) {
	int *a, rfd, wfd, n;
	char buf[2048];

	a = v->int_ptr;
	rfd = a[0];
	wfd = a[1];
	free(a);

	while ((n = async_read(rfd, buf, sizeof buf)) > 0)
		async_write(wfd, buf, n);

	shutdown(wfd, SHUT_WR);
	close(rfd);

	return 0;
}

int *mkfd2(int fd1, int fd2) {
	int *a;

	a = malloc(2 * sizeof a[0]);
	if (a == 0) {
		cerr("out of memory\n");
		abort();
	}
	a[0] = fd1;
	a[1] = fd2;

	return a;
}

void *proxytask(param_t v) {
	int fd, remotefd;

	fd = v->integer;
	if ((remotefd = async_connect(server, port, true)) < 0) {
		perror("async_connect");
		close(fd);
		return 0;
	}

	cerr("\nconnected to %s:%d"CLR_LN, server, port);

	async_task(rwtask, 1, mkfd2(fd, remotefd));
	async_task(rwtask, 1, mkfd2(remotefd, fd));

	return 0;
}

void main_main(param_t param) {
	array_t args = (array_t)param->object;
	fds_t cfd, fd;
	int rport;
	char remote[16];

	local = atoi(args[0].char_ptr);
	server = args[1].char_ptr;
	port = atoi(args[2].char_ptr);
	$delete(args);

	if ((fd = async_bind(OS_NULL, local, 128, true)) < 0) {
		cerr("cannot listen on tcp port %d: %s\n", local, strerror(errno));
		exit(1);
	}

	while ((cfd = async_accept(fd, remote, &rport)) >= 0) {
		cerr("connection from %s:%d"CLR_LN, remote, rport);
		async_task(proxytask, 1, casting(cfd));
	}
}

int main(int argc, char **argv) {
	if (argc != 4) {
		cerr("usage: tcpproxy localport server remoteport\n");
		exit(1);
	}

	return events_start(1024, main_main, arrays(3, argv[1], argv[2], argv[3]));
}
