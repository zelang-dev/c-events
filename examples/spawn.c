#include "events.h"

void _on_exit(int exit_status, int term_signal) {
	cerr("\nProcess exited with status %d, signal %d"CLR_LN,
		exit_status, term_signal);
}

void main_main(param_t args) {
	execinfo_t *child = spawn("child_command", "test-dir", NULL, _on_exit);
	if (child != NULL) {
		cerr("\nLaunched process with ID %zu"CLR_LN, spawn_pid(child));
		while (!spawn_is_finish(child))
			yield();
	}
}

int main(int argc, char **argv) {
	return events_start(1024, main_main, 0);
}
