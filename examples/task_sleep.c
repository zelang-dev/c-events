/*
An converted version of `Golang` example from https://www.golinuxcloud.com/goroutines-golang/

package main

import (
   "fmt"
   "time"
)

func main() {
   fmt.Println("Start of main Goroutine")
   go greetings("John")
   go greetings("Mary")
   time.Sleep(time.Second * 10)
   fmt.Println("End of main Goroutine")

}

func greetings(name string) {
   for i := 0; i < 3; i++ {
       fmt.Println(i, "==>", name)
       time.Sleep(time.Millisecond)
  }
}
*/

#include <events.h>

void *greetings(param_t args) {
    char *name = args[0].char_ptr;
    int i;
    for (i = 0; i < 3; i++) {
		printf("%d ==> %s\n", i, name);
		sleep_task(1);
    }
    return 0;
}

void *main_main(param_t args) {
	puts("Start of main_main task");
	async_task(greetings, 1, "John");
	async_task(greetings, 1, "Mary");
	sleep_task(seconds(10));
	puts("\nEnd of main_main task");
    return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	async_task(main_main, 0);
	events_t *loop = events_create(6);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
