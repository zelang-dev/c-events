/*
An expanded/converted version of `Golang` example from https://gobyexample.com/waitgroups

package main

import (
	"fmt"
	"sync"
	"time"
)

func worker(id int) {
	fmt.Printf("Worker %d starting\n", id)

	time.Sleep(time.Second)

	fmt.Printf("Worker %d done\n", id)
}

func main() {

	var wg sync.WaitGroup

	for i := 1; i <= 5; i++ {
		wg.Add(1)

		i := i

		go func() {
			defer wg.Done()
			worker(i)
		}()
	}

	wg.Wait()
*/

#include <events.h>

void *worker(param_t args) {
	int id = args[0].integer;
	printf("Worker %d starting, task id: #%d\n", id, task_id());

	delay(seconds(1));

	printf(LN_CLR"Worker %d done, task id: #%d\n", id, task_id());
	return 0;
}

void main_main(param_t args) {
	int i;

	task_group_t *wg = task_group();
	for (i = 1; i <= 5; i++) {
		async_task(worker, 1, i);
	}
	tasks_wait(wg);
}

int main(int argc, char **argv) {
	return events_start(1024, main_main, 0);
}
