#include "events_internal.h"

static int command_line_argc;
static char **command_line_argv;
static bool command_line_set = false;
static bool command_line_ordered = false;
static int command_line_index = 1;
static int command_line_required = 1;
static char *command_line_message = NULL;
static char *command_line_option = NULL;

static void usage(const char *program, char *message) {
	fprintf(stderr, CLR_LN"Usage: %s OPTIONS\n%s"CLR_LN, program, (message == NULL ? "" : message));
	exit(1);
}

void getopt_message_set(const char *message, int minium, bool is_ordered) {
	if (!command_line_set) {
		command_line_set = true;
		command_line_message = (char *)message;
		command_line_required = minium;
		command_line_ordered = is_ordered;
	}
}

char *getopts(void) {
	return command_line_option;
}

bool getopt_has(const char *flag, bool is_single) {
	char *unknown = NULL, **flags = NULL;
	bool show_help = false, is_unknown = false, is_split = false;
	int i = 0;

	// Parse command-line flags
	if (command_line_argc > command_line_required) {
		for (i = command_line_index; i < command_line_argc; i++) {
			if (is_single && str_has(command_line_argv[i], "=")) {
				flags = str_slice(command_line_argv[i], "=", NULL);
				is_split = true;
			}

			if (flag == NULL && i == command_line_index) {
				if (is_split)
					events_free(flags);

				command_line_option = command_line_argv[i];
				if (command_line_ordered)
					command_line_index = i + 1;

				return true;
			} else if (str_is(command_line_argv[i], flag) || (is_split && str_is(flags[0], flag))) {
				if (is_split) {
					command_line_option = flags[1];
					defer_free(flags);
				} else {
					command_line_option = is_single ? command_line_argv[i] : command_line_argv[++i];
				}

				if (command_line_ordered)
					command_line_index = i + 1;
				return true;
			} else if (str_has("-h, --h, ?, help", command_line_argv[i])) {
				show_help = true;
				break;
			} else {
				is_unknown = true;
				unknown = command_line_argv[i];
			}

			if (is_split) {
				events_free(flags);
				flags = NULL;
				is_split = false;
			}
		}
	}

	if (is_split && flags != NULL)
		events_free(flags);

	if (is_unknown)
		fprintf(stderr, "\nUnknown flag provided: %s", unknown);

	if (show_help || is_unknown || command_line_argc <= 1)
		usage(command_line_argv[0], command_line_message);

	return false;
}

void getopt_arguments_set(int argc, char **argv) {
	command_line_argc = argc;
	command_line_argv = argv;
}
