#include <events.h>

void *main_main(param_t args) {
	use_ca_certificate("cert.pem");
#ifndef _WIN32
	tls_selfserver_set();
#endif
	int client = tls_get("127.0.0.1:7000");
	if (socket_is_secure(client)) {
		cerr("\nConnected!"CLR_LN);
		char data[Kb(32)] = {0};
		ssize_t len = tls_reader(client, data, sizeof(data));
		if (len && str_is("world", data)) {
			if (tls_writer(client, "hello", 0) == 5) {
				cout("\nSecured transaction!"CLR_LN);
			}
		}
		tls_closer(client);
	} else {
		perror("\ntls_get");
	}

	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
