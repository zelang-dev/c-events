#include "events.h"

int main(int argc, char *argv[]) {
	rmdir(argv[1]);
	return mkdir(argv[1], 0);
}
