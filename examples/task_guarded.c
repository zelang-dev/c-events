/*
An converted version of `Golang` example from https://www.developer.com/languages/go-error-handling-with-panic-recovery-and-defer/

package main

import (
 "fmt"
 "log"
)

func main() {
 divByZero()
 fmt.Println("Although panicked. We recovered. We call mul() func")
 fmt.Println("mul func result: ", mul(5, 10))
}

func div(x, y int) int {
 return x / y
}

func mul(x, y int) int {
 return x * y
}

func divByZero() {
 defer func() {
  if err := recover(); err != nil {
   log.Println("panic occurred:", err)
  }
 }()
 fmt.Println(div(1, 0))
*/

#include <except.h>

int div_err(int x, int y) {
    return x / y;
}

int mul(int x, int y) {
    return x * y;
}

void func(void *arg) {
    if (try_caught(guard_message()))
		printf("panic occurred: %s\n", try_message());
}

void divByZero(param_t arg) {
	guard {
		defer(func, arg);
		printf("%d", div_err(1, 0));
		unreachable;
	} guarded;
}

void *main_main(param_t args) {
    launch_task(divByZero, 0);
    printf("Although panicked. We recovered. We call mul() func\n");
    printf("mul func result: %d\n", mul(5, 10));
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
