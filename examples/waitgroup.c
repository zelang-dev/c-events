#include <events.h>

void *worker(param_t args) {
    int wid = args[0].integer + 1;

    printf("Worker %d starting\n", wid);
    tasks_info(active_task(), 1);
    sleep_task(10);
	printf("Worker %d done\n", wid);
	tasks_info(active_task(), 1);

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
	printf("Worker # %d returned: %d\n", cid[3], results_for(cid[3]).integer);
    printf("Worker # %d returned: %s\n", cid[2], results_for(cid[2]).char_ptr);
    return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	async_task(main_main, 0);
	events_t *loop = events_thread_init();
	async_run(loop);
	events_destroy(loop);

	return 0;
}
