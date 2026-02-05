/*

This test converted from [source](https://gitlab.inria.fr/gustedt/defer/-/blob/master/defer4.c?ref_type=heads), outlined in [C Standard WG14 meeting](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2542.pdf)

```c
#include <stdio.h>
#include <stddef.h>
#include <threads.h>
#include "stddefer.h"

void g(int i) {
  if (i > 3) {
	puts("Panicking!");
	panic(i);
  }
  guard {
	defer {
	  printf("Defer in g = %d.\n", i);
	}
	printf("Printing in g = %d.\n", i);
	g(i+1);
  }
}

void f() {
  guard {
	defer {
		puts("In defer in f");
		fflush(stdout);
	  int err = recover();
	  if (err != 0) {
		printf("Recovered in f = %d\n", err);
		fflush(stdout);
	  }
	}
	puts("Calling g.");
	g(0);
	puts("Returned normally from g.");
  }
}

int main(int argc, char* argv[static argc+1]) {
  f();
  puts("Returned normally from f.");
  return EXIT_SUCCESS;
}
```
*/

#define USE_RPMALLOC 1
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
    if (guard_caught(err)) {
        printf("Recovered in f = %s\n\n", err);
        fflush(stdout);
	}

	return 0;
}

void g(int i) {
    if (i > 3) {
        puts("Panicking!\n");
        panic(str_itoa(i));
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
	events_set_allocator(rp_malloc, rp_realloc, rp_calloc, rpfree);
	TEST_FUNC(list());
}
