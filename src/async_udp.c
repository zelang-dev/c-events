#define NO_REDEF_POSIX_FUNCTIONS
#include "events_internal.h"

int udp_connect(char *addr) {
	udp_t packet = null;
	uint32_t ip = 0;
	int port = 0;
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
	uint32_t ip = 0;
	int port = 0;
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

void udp_to(int fd, char *addr, unsigned int flags) {
	u_saddr_t usa;
	uint32_t ip = 0;
	int port = 0, ip_family = 0;
	char *host = str_parseip(addr, &ip, &port, false);
	udp_t packet = events_target(fd)->udp;
	packet->addr = events_get_sockaddr(fd);
	memset(&packet->addr->storage, 0, sizeof(packet->addr->storage));
	char buf[ARRAY_SIZE] = {0};
	if (port)
		snprintf(buf, sizeof(buf) - 1, "%s:%d", host, port);
	else
		snprintf(buf, sizeof(buf) - 1, "%s", host);

	packet->flags = flags;
	async_parse_addr(buf, &usa, &ip_family);
	memcpy(&packet->addr->storage, &usa.storage, sizeof(packet->addr->storage));
	if (!is_empty(host))
		events_free(host);
}

int async_sendto(int fd, void *buf, int n) {
	int m;
	udp_t packet = events_target(fd)->udp;
	socklen_t client_len = sizeof(sockaddr_t);

	while ((m = sendto(socket2fd(fd), (const char *)buf, n, packet->flags, (sockaddr_t *)packet->addr, client_len)) < 0
		&& os_geterror() == EAGAIN) {
		async_wait(fd, 'w');
	}
	return m;
}

int udp_send(udp_t packet, void *buf, int n) {
	int m;
	u_saddr_t *addr = events_get_sockaddr(fd2socket(packet->socket));
	socklen_t client_len = addr->sa.sa_family == AF_INET6 ? sizeof(addr->sin6) : sizeof(addr->sin);

	while ((m = sendto(fd2socket(packet->socket), (const char *)buf, n,
		packet->flags, (sockaddr_t *)&addr->sa, client_len)) < 0
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
	uchar *ip;
	char buf[Kb(48)] = {0}, buf1[64] = {0};
	udp_t client = null, packet = events_target(fd)->udp;
	packet->addr = events_get_sockaddr(fd2socket(fd));
	u_saddr_t *usa = packet->addr;
	socklen_t client_len = usa->sa.sa_family == AF_INET6 ? sizeof(usa->sin6) : sizeof(usa->sin);

	while ((m = recvfrom(socket2fd(fd), buf, sizeof(buf), packet->flags, &usa->sa, &client_len)) < 0
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
			client->message = events_calloc(1, _mem_align_up(m + 1, 2));
			client->addr = events_calloc(1, sizeof(u_saddr_t));
			if (!is_empty(client->message) && !is_empty(client->addr)) {
				memcpy(&client->addr->storage, &usa->storage, sizeof(usa->storage));
				memcpy(client->message, buf, m);
				client->message_set = true;
				client->type = DATA_UDP;
				events_target(fd)->udp = client;
				errno = 0;
			} else {
				if (!is_empty(client->message))
					events_free(client->message);

				if (!is_empty(client->addr))
					events_free(client->addr);

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
		defer_free((void *)packet->addr);
	}
	return packet->message;
}

EVENTS_INLINE unsigned int udp_flags(udp_t packet) {
	return packet->flags;
}

EVENTS_INLINE char *udp_ip(udp_t packet) {
	if (str_is_empty(packet->ipaddr))
		async_sockaddr_str(packet->ipaddr, sizeof(packet->ipaddr), packet->addr);

	return packet->ipaddr;
}

EVENTS_INLINE int udp_broadcast_set(int fd) {
	int on = 1;
	return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on));
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
