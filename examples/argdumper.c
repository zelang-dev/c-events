/* trivial diagnostic tool to test _mkfifo.exe's arg passing and redirect */

#include <events.h>

int main(int argc, char **argv) {
	int i;
	char buf[10] = {0};
	for (i = 0; i < argc; ++i) {
        fprintf(stderr, "arg %d: %s\n", i, argv[i]);
	}

	printf("waiting\n");
	read(0, buf, 5);
	printf("%s world\n", buf);
	write(1, "exit\n", 5);

	fprintf(stderr, "%s, world\n", buf);
	return 0;
}
