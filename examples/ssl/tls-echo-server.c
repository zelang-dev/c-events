#include <events.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

void new_connection(int socket) {
	char data[Kb(8)] = {0};
	ssize_t len = tls_reader(socket, data, sizeof(data));
	if (len > 0) {
		tls_writer(socket, data, len);
		tls_flusher(socket);
	}
}

void *main_main(param_t args) {
	int client, server, rport;
	char remote[16], addr[MAXHOSTNAMELEN];
	bool is_secure = getopt_has("-s", true);
	const char *host = is_secure ? "tls://127.0.0.1:%d" : "tcp://0.0.0.0:%d";

	if (snprintf(addr, sizeof(addr), host, DEFAULT_PORT)) {
		if (is_secure)
			use_certificate(null, 0);

		server = tls_bind(addr, DEFAULT_BACKLOG);
		if (server > 0) {
			while ((client = tls_accept(server, remote, &rport)) > 0) {
				cerr("\nconnection from %s:%d"CLR_LN, remote, rport);
				tls_handler(new_connection, client);
			}
        }
    }

    return 0;
}

int main(int argc, char **argv) {
	getopt_arguments_set(argc, argv);
	getopt_message_set("\t-s for `secure connection`\n", 0, false);

	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
