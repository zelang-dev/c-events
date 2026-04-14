#include <events.h>

#define FIB_UNTIL 25

long fib_(long t) {
    if (t == 0 || t == 1)
        return 1;
    else
        return fib_(t-1) + fib_(t-2);
}

void *fib(param_t req) {
	int n = req->integer;
	if (random() % 2)
        os_sleep(1000);
    else
        os_sleep(3000);
	long fib = fib_(n);
	fprintf(stderr, "%dth fibonacci is %lu"CLR_LN, n, fib);

	return $$(n, fib);
}

void after_fib(tuple_t req) {
	fprintf(stderr, "Done calculating %dth fibonacci, result: %d"CLR_LN,
		req[0].integer, req[1].integer);
}

void *main_main(param_t args) {
	array_t arr = array();
	int i;

	for (i = 0; i < FIB_UNTIL; i++) {
		promise *req = queue_work(futures_pool(), fib, 1, casting(i));
		$append(arr, req);
	}

	queue_wait(arr, after_fib);
	return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_init_pool(4);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}