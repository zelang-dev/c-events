
/* sames as https://github.com/zelang-dev/c-asio/tree/main/examples/dns.c
a much simpler version of libuv https://github.com/libuv/libuv/blob/master/docs/code/dns/main.c */

#include <events.h>

void main_main(param_t args) {
	char text[Kb(2)] = {0};
	int len;
	cerr("irc.libera.chat is..."CLR_LN);
	struct hostent *dns = async_gethostbyname("irc.libera.chat");

	cerr("%s"CLR_LN, gethostbyname_ip(dns));
	fds_t server = async_connect(gethostbyname_ip(dns), 6667, true);
	while ((len = async_read(server, text, sizeof(text) - 1) > 0)) {
		cout(CLR"%s", text);
		memset(text, 0, sizeof(text));
	}
	puts(CLR_LN);
}

int main(int argc, char **argv) {
	return events_start(1024, main_main, 0);
}
