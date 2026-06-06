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
		printf("%d ==> %s"CLR_LN, i, name);
		delay(1);
    }
    return 0;
}

void main_main(param_t args) {
	puts("Start of main_main task");
	async_task(greetings, 1, "John");
	async_task(greetings, 1, "Mary");
	delay(seconds(10));
	puts("\nEnd of main_main task");
}

int main(int argc, char **argv) {
	return events_start(1024, main_main, 0);
}
