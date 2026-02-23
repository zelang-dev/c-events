#define NO_REDEF_POSIX_FUNCTIONS
#include "events_internal.h"

int uds_connect(char *addr) {
	uint32_t ip = 0, port = 0;
	char *host = str_parseip(addr, &ip, &port, true);
	int fd = socket2fd(async_connect(host, port, -1));
	if (fd > 0)
		defer_free(events_target(fd)->uds);

	return fd;
}

int uds_bind(char *addr, int backlog) {
	uint32_t ip = 0, port = 0;
	char *host = str_parseip(addr, &ip, &port, true);
	int fd = socket2fd(async_bind(host, port, backlog, -1));
	if (fd > 0) {
		defer(unlink, host);
		defer_free(events_target(fd)->uds);
	}
	return fd;
}

EVENTS_INLINE int uds_accept(int fd, char *server) {
	int cfd = socket2fd(async_accept(fd2socket(fd), server, null));
	if (cfd > 0)
		events_target(cfd)->uds = events_target(fd)->uds;
	return cfd;
}

/*
int async_sendto(int fd, void *buf, int n) {
	int m;
	udp_t packet = events_target(fd)->udp;
	socklen_t client_len = sizeof(packet->addr);

	while ((m = sendto(socket2fd(fd), (const char *)buf, n, packet->flags, (sockaddr_t *)packet->addr, client_len)) < 0
		&& os_geterror() == EAGAIN) {
		async_wait(fd, 'w');
	}
	return m;
}

int async_recvfrom(int fd, void *buf, int n, unsigned int flags) {
	int m;

	while ((m = recvfrom(socket2fd(fd), buf, n, flags, null, null)) < 0
		&& os_geterror() == EAGAIN) {
		async_wait(fd, 'r');
	}

	return m;
}
*/
EVENTS_INLINE bool socket_is_uds(int socket) {
	if (socket <= 0) return false;
	uds_t uds = events_target(socket)->uds;
	return !is_empty(uds) && is_ptr_usable(uds) && data_type(uds) == DATA_UNIX;
}

static void *uds_client(param_t args) {
	int client = args[0].integer;
	uds_unix_cb handlerFunc = (uds_unix_cb)args[1].func;

	deferring(close, client);
	handlerFunc(client);

	return 0;
}

EVENTS_INLINE void uds_handler(uds_unix_cb connected, int client) {
	if (!is_data(sys_event.cpu_index)
		&& events_tasks_pool(events_create(sys_event.cpu_count)) < 0) {
		launch((launch_func_t)uds_client, 2, client, connected);
	} else {
		int rid = go(uds_client, 2, casting(client), connected);
		if (rid > 0) {
			events_deque_t *q = sys_event.local[results_tid(rid)];
			atomic_flag_test_and_set(&q->started);
			yield_task();
		}
	}
}
