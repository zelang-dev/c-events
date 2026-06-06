#include <events.h>

void main_main(param_t args) {
	struct hostent *ip = async_gethostbyname(args->char_ptr);
	printf("\n> %s <"CLR_LN, gethostbyname_ip(ip));
}

int main(int argc, char **argv) {
	if (argc != 2) {
		cerr("usage: dns_ip hostname\n");
		exit(1);
	}

	return events_start(1024, main_main, argv[1]);
}
