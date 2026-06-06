#include <httpi.h>

void main_main(param_t args) {
	if (getopt_has(null, true)) {
		char data[Kb(16)] = {0};
		int client, chunks = 0;
		http_t *parser = null;
		ssize_t len;

		use_ca_certificate("cert.pem");
		if ((client = tls_dial(getopts())) > 0 && tls_writer(client, "GET / HTTP/1.0"CRLF CRLF, 0)) {
			cout(CLR_LN);
			while (!socket_is_eof(client)) {
				if ((len = tls_reader(client, data, sizeof(data) -1)) > 0) {
					if (is_empty(parser)) {
						parser = http_for(null, 1.1);
						if (parse_http(HTTP_RESPONSE, parser, data) != DATA_INVALID) {
							cout("1 %s"CLR_LN, http_get_header(parser, "Date"));
							cout("2 %s"CLR_LN, http_get_header(parser, "Server"));
							cout("4 %s"CLR_LN, http_get_header(parser, "Set-Cookie"));
							cout("5 %s"CLR_LN, http_get_header(parser, "Expires"));
							cout("6 %s"CLR_LN, http_get_header(parser, "Cache-Control"));
							cout("8 %s"CLR_LN, http_get_header(parser, "Vary"));
							cout("11 %s"CLR_LN, http_get_header(parser, "Content-Type"));
							cout("12 %s"CLR_LN, http_get_protocol(parser));
							cout("13 %s"CLR_LN, http_get_message(parser));
							cout("13 %d"CLR_LN, http_get_code(parser));
							cout("14 %s"CLR_LN, http_get_var(parser, "Set-Cookie", "path"));
							cout("15 %s"CLR_LN, http_get_header(parser, "Content-Length"));
							cout("16 %s"CLR_LN, http_get_header(parser, "Connection"));
							cout("done!\n\n"CLR_LN);
							if ((len = strlen(http_get_body(parser))) > 0){
								cout("headers parsed, with body:"CLR_LN);
								fout(http_get_body(parser), len);
								cout("\n\n\nadditional body follows:"CLR_LN);
							} else {
								cout("body:"CLR_LN);
							}
						}
					} else {
						fout(data, len);
					}
				} else
					break;

				chunks++;
			}
		} else {
			perror("\ntls_get/tls_writer");
		}

		cout("\n\nReceived: %d chunks.\n", chunks);
	}
}

int main(int argc, char **argv) {
	getopt_arguments_set(argc, argv);
	getopt_message_set("\turl - website\n", 1, false);

	return events_start(1024, main_main, 0);
}
