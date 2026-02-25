/* simpler and behave the same as libuv https://github.com/libuv/libuv/blob/master/docs/code/udp-dhcp/main.c

NOTE: As `libuv` state, "this example needs to be run as root." */
#include <events.h>

void on_read(udp_t req) {
	cerr("Recv from %s"CLR_LN, udp_ip(req));

    // ... DHCP specific code
    unsigned int *as_integer = (unsigned int*)udp_message(req);
    unsigned int ipbin = ntohl(as_integer[4]);
    unsigned char ip[4] = {0};
    int i;
    for (i = 0; i < 4; i++)
        ip[i] = (ipbin >> i*8) & 0xff;
    cerr("Offered IP %d.%d.%d.%d"CLR_LN, ip[3], ip[2], ip[1], ip[0]);
}

char *make_discover_msg(char *base, size_t len) {
    memset(base, 0, len);

    // BOOTREQUEST
    base[0] = 0x1;
    // HTYPE ethernet
    base[1] = 0x1;
    // HLEN
    base[2] = 0x6;
    // HOPS
    base[3] = 0x0;
    // XID 4 bytes
	if (async_getentropy(&base[4], 4))
      abort();
    // SECS
    base[8] = 0x0;
    // FLAGS
    base[10] = 0x80;
    // CIADDR 12-15 is all zeros
    // YIADDR 16-19 is all zeros
    // SIADDR 20-23 is all zeros
    // GIADDR 24-27 is all zeros
    // CHADDR 28-43 is the MAC address, use your own
    base[28] = 0xe4;
    base[29] = 0xce;
    base[30] = 0x8f;
    base[31] = 0x13;
    base[32] = 0xf6;
    base[33] = 0xd4;
    // SNAME 64 bytes zero
    // FILE 128 bytes zero
    // OPTIONS
    // - magic cookie
    base[236] = 99;
    base[237] = 127;
    base[238] = 83;
    base[239] = 99;

    // DHCP Message type
    base[240] = 53;
    base[241] = 1;
    base[242] = 1; // DHCPDISCOVER

    // DHCP Parameter request list
    base[243] = 55;
    base[244] = 4;
    base[245] = 1;
    base[246] = 3;
    base[247] = 15;
    base[248] = 6;

    return base;
}

void *on_send(param_t args) {
	char buf[257], *discover_msg = make_discover_msg(buf, sizeof(buf));
	int status, send_socket = udp_bind("0.0.0.0", 0);
	udp_to(send_socket, "255.255.255.255:67", 0);
	udp_broadcast_set(send_socket);
	if ((status = async_sendto(send_socket, discover_msg, sizeof(buf) - 1)) != 256) {
        cerr("Send error %d,  %s"CLR_LN, status, strerror(errno));
		abort();
	}

	sleep_task(10);
	return 0;
}

void *main_main(param_t args) {
	uint32_t res = async_task(on_send, 0);
	int recv_socket = udp_bind("0.0.0.0:68", 0);
	udp_t cl_socket = udp_recv(recv_socket);
	if (is_empty(cl_socket)) {
		cerr("Read error %s\n", strerror(errno));
		//abort();
		return 0;
	}

	udp_handler(on_read, cl_socket);
	while (!task_is_ready(res))
		yield_task();

	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(6);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}