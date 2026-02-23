#define NO_REDEF_POSIX_FUNCTIONS
#include "events_internal.h"

int udp_connect(char *addr) {
	udp_t packet = null;
	uint32_t ip = 0, port = 0;
	char *host = str_parseip(addr, &ip, &port, true);
	int fd = socket2fd(async_connect(host, port, false));
	if (fd > 0
		&& defer_free(packet = events_calloc(1, sizeof(struct udp_packet_s)))) {
		packet->socket = fd;
		packet->type = DATA_UDP;
		events_target(fd)->udp = packet;
	}

	return fd;
}

int udp_bind(char *addr, unsigned int flags) {
	udp_t packet = null;
	uint32_t ip = 0, port = 0;
	char *host = str_parseip(addr, &ip, &port, true);
	int fd = socket2fd(async_bind(host, port, ip, false));
	if (fd > 0
		&& defer_free(packet = events_calloc(1, sizeof(struct udp_packet_s)))) {
		packet->socket = fd;
		packet->flags = flags;
		packet->type = DATA_UDP;
		events_target(fd)->udp = packet;
	}

	return fd;
}

void udp_with(int fd, char *addr, unsigned int flags) {
	uint32_t ip = 0, port = 0;
	char *host = str_parseip(addr, &ip, &port, false);
	udp_t packet = events_target(fd)->udp;

	packet->flags = flags;
	struct sockaddr_in *sa = (struct sockaddr_in *)packet->addr;

	memset(sa, 0, sizeof sa);
	memmove(&sa->sin_addr, &ip, 4);
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	if (!is_empty(host))
		events_free(host);
}

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

int udp_send(udp_t packet, void *buf, int n) {
	int m;
	socklen_t client_len = sizeof(packet->addr);

	while ((m = sendto(fd2socket(packet->socket), (const char *)buf, n, packet->flags, (sockaddr_t *)packet->addr, client_len)) < 0
		&& os_geterror() == EAGAIN) {
		async_wait(packet->socket, 'w');
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

udp_t udp_recv(int fd) {
	int m;
	char buf[Kb(32)] = {0};
	udp_t client = null, packet = events_target(fd)->udp;
	socklen_t client_len = sizeof(packet->addr);

	while ((m = recvfrom(socket2fd(fd), buf, Kb(32), packet->flags, (struct sockaddr *)packet->addr, &client_len)) < 0
		&& os_geterror() == EAGAIN) {
		async_wait(fd, 'r');
	}

	if (m > 0) {
		errno = ENOMEM;
		client = events_calloc(1, sizeof(struct udp_packet_s));
		if (!is_empty(client)) {
			client->socket = fd;
			client->flags = packet->flags;
			client->nread = m;
			memcpy((void *)client->addr, packet->addr, sizeof(client->addr));
			client->message = events_calloc(1, m + 1);
			if (!is_empty(client->message)) {
				memcpy(client->message, buf, m);
				client->message_set = true;
				client->type = DATA_UDP;
				events_target(fd)->udp = client;
				errno = 0;
			} else {
				events_free(client);
				return null;
			}
		}
	}

	return client;
}

EVENTS_INLINE char *udp_message(udp_t packet) {
	if (packet->message && packet->message_set) {
		packet->message_set = false;
		defer_free((void *)packet->message);
	}
	return packet->message;
}

EVENTS_INLINE unsigned int udp_flags(udp_t packet) {
	return packet->flags;
}

EVENTS_INLINE ssize_t udp_length(udp_t packet) {
	return packet->nread;
}

EVENTS_INLINE bool socket_is_udp(int socket) {
	if (socket <= 0) return false;
	udp_t udp = events_target(socket)->udp;
	return !is_empty(udp) && is_ptr_usable(udp) && data_type(udp) == DATA_UDP;
}

static void *udp_client(param_t args) {
	udp_t client = (udp_t)args[0].object;
	udp_packet_cb handlerFunc = (udp_packet_cb)args[1].func;

	defer_free((void *)client);
	handlerFunc(client);

	return 0;
}

EVENTS_INLINE void udp_handler(udp_packet_cb connected, udp_t client) {
	launch((launch_func_t)udp_client, 2, client, connected);
}
