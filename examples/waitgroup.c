#include <events.h>

void *worker(param_t args) {
    int wid = args[0].integer + 1;

    printf("Worker %d starting\n", wid);
    active_info();
    delay(10);
	printf("Worker %d done\n", wid);
	active_info();

    if (wid == 4)
        return casting(32);
    else if (wid == 3)
        return "hello world";

    return 0;
}

void *main_main(param_t args) {
    int cid[50], i;

    waitgroup_t wg = waitgroup(50);
    for (i = 0; i < 50; i++) {
        cid[i] = go(worker, 1, i);
    }
    array_t wgr = waitfor(wg);

	printf("\n\nWorkers has (%zd) results. \n\n", $size(wgr));
	printf("Worker # %d returned: %d"CLR_LN, cid[3], results_for(cid[3]).integer);
    printf("Worker # %d returned: %s"CLR_LN, cid[2], results_for(cid[2]).char_ptr);
    return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	events_set_main((main_cb)main_main);
	events_t *loop = events_init_pool(0);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
