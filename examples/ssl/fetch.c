#include <events.h>

void *main_main(param_t args) {
	if (getopt_has(null, true)) {
		char data[Kb(16)] = {0};
		int client, chunks = 0;
		ssize_t len;

		use_ca_certificate("cert.pem");
		if ((client = tls_get(getopts())) > 0 && tls_writer(client, "GET /"CRLF, 0)) {
			cout(CLR_LN);
			while (!socket_is_eof(client)) {
				if ((len = tls_reader(client, data, sizeof(data) - 1)) > 0)
					cout(data);
				else
					break;

				memset(data, 0, len);
				chunks++;
			}
		}

		cout("\n\nReceived: %d chunks.\n", chunks);
	} else {
		getopt_has("help", false);
	}

	return 0;
}

int main(int argc, char **argv) {
	getopt_arguments_set(argc, argv);
	getopt_message_set("\turl - website\n", 1, false);

	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
