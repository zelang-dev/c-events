
#include "events.h"

void *fibonacci_coro(param_t args) {
    /* Retrieve max value. */
    unsigned long max = args[0].u_long;
    unsigned long m = 1;
    unsigned long n = 1;

    while (1) {
        /* Yield the next Fibonacci number. */
        yielding(casting(m));

        unsigned long tmp = m + n;
        m = n;
        n = tmp;
        if (m >= max)
            break;
    }

    /* Yield the last Fibonacci number. */
    yielding(casting(m));

    return "hello world";
}

void *main_main(param_t args) {
	/* Set storage. */
	unsigned long maximum = 1000000000;

	/* Create the coroutine. */
	generator_t gen = generator(fibonacci_coro, 1, casting(maximum));

	int counter = 1;
	unsigned long ret = 0;
	while (ret < maximum) {
		/* Resume the coroutine. */
		/* Retrieve storage set in last coroutine yield. */
		ret = yielded(gen).u_long;

		printf("fib %d = %li\t\n", counter, ret);
		counter = counter + 1;
	}

	if (yielded(gen).object == NULL)
		printf("\n\n%s\n", results_for(gen_id()).char_ptr);

	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(1);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
