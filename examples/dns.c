
/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/dns.c
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/dns/main.c */

#include <events.h>

void *main_main(param_t args) {
	char text[1024] = {0};
	int len;
	fprintf(stderr, "irc.libera.chat is..."CLR_LN);
	struct hostent *dns = async_gethostbyname("irc.libera.chat");

	fprintf(stderr, "%s"CLR_LN, gethostbyname_ip(dns));
	fds_t server = async_connect("irc.libera.chat", 6667, true);
	while ((len = async_read(server, text, sizeof(text)) > 0)) {
		fprintf(stderr, CLR"%s", text);
		memset(text, 0, sizeof(text));
	}

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
