
#include "events.h"

void main_main(param_t args) {
	printf("%s"CLR_LN, args->char_ptr);
}

int main(int argc, char **argv) {
	return events_start(1024, main_main, "Now quitting.");
}
