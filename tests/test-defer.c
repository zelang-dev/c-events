#include <except.h>
#include "assertions.h"

char number[20];
int g_print(void *args) {
    ASSERT_NOTNULL(args);
	int arg = data_value(args).integer;
    ASSERT_EQ(true, arg >= 0);
	printf("Defer in g = %d.\n\n", arg);

	return 0;
}

int f_print(void *args) {
    ASSERT_NULL(args);
	const char *err = guard_message();
    ASSERT_STR("4", err);
    puts("In defer in f");
    fflush(stdout);
    if (try_caught(err)) {
        printf("Recovered in f = %s\n\n", err);
        fflush(stdout);
	}

	return 0;
}

void g(int i) {
    if (i > 3) {
        puts("Panicking!\n");
        snprintf(number, 20, "%d", i);
        ex_panic(number);
    }

    guard {
      defer(g_print, &i);
      printf("Printing in g = %d.\n", i);
      g(i + 1);
    } guarded;
}

void f() {
	guard {
		defer(f_print, NULL);
		puts("Calling g.");
		g(0);
		puts("Returned normally from g.");
	} guarded;
}

TEST(deferred) {
    f();
    puts("Returned normally from f.");
    return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(deferred);

	return result;
}

int main(int argc, char **argv) {
	TEST_TASK(list());
}
