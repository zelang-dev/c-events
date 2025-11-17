#include "events.h"
#include <assert.h>

#define HOST 0 /* 0x7f000001 for localhost */
#define PORT 23456
#define MAX_FDS 1024
#define TIMEOUT_SECS 10

static void setup_sock(sockfd_t fd) {
	char on = 1, r;
	r = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	assert(r == 0);
	r = events_set_nonblocking(fd);
	assert(r == 0);
}

static void close_conn(events_t *loop, int fd) {
	sockfd_t sfd = fd2socket(fd);
	events_del(sfd);
	close(sfd);
	printf("closed: %d\n", fd);
}

static void rw_callback(sockfd_t sfd, int events, void *cb_arg) {
	int fd = socket2fd(sfd);
	events_t *loop = events_loop(sfd);
	if ((events & EVENTS_TIMEOUT) != 0) {
	  /* timeout */
		close_conn(loop, fd);
	} else if ((events & EVENTS_READ) != 0) {
	  /* update timeout, and read */
		char buf[1024];
		ssize_t r;
		events_set_timeout(sfd, TIMEOUT_SECS);
		r = read(fd, buf, sizeof(buf));
		switch (r) {
			case 0: /* connection closed by peer */
				close_conn(loop, fd);
				break;
			case -1: /* error */
				if (errno == EAGAIN || errno == EWOULDBLOCK) { /* try again later */
					break;
				} else { /* fatal error */
					close_conn(loop, fd);
				}
				break;
			default: /* got some data, send back */
				if (write(fd, buf, r) != r) {
					close_conn(loop, fd); /* failed to send all data at once, close */
				}
				break;
		}
	}
}

static void accept_callback(sockfd_t fd, int events, void *cb_arg) {
	sockfd_t newfd = accept(fd, NULL, NULL);
	events_t *loop = events_loop(fd);
	int sfd = socket2fd(newfd);
	if (sfd != -1) {
		printf("connected: %d\n", sfd);
		setup_sock(newfd);
		events_add(loop, newfd, EVENTS_READ, TIMEOUT_SECS, rw_callback, NULL);
	} else if (events & EVENTS_TIMEOUT) {
		events_destroy(loop);
		events_deinit();
	}
}

int main(void) {
	events_t *loop;
	sockfd_t listen_sock;
	char flag = 1;

	/* init events */
	events_init(MAX_FDS);

	/* listen to port */
	assert((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	assert(setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == 0);

	struct sockaddr_in listen_addr;
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_port = htons(PORT);
	listen_addr.sin_addr.s_addr = htonl(HOST);

	assert(bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) == 0);
	assert(listen(listen_sock, 5) == 0);
	setup_sock(listen_sock);

	/* create loop */
	loop = events_create(1);

	/* add listen socket */
	events_add(loop, listen_sock, EVENTS_READ, 0, accept_callback, NULL);

	/* loop */
	while (events_is_running(loop)) {
		fputc('.', stdout); fflush(stdout);
		if (events_once(loop, 10) == -1)
			break;
	}

	/* cleanup */
	events_destroy(loop);
	events_deinit();

	return 0;
}
