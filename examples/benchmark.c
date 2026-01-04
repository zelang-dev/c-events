/*
This benchmark based off **GoLang** version at https://github.com/pkolaczk/async-runtimes-benchmarks/blob/main/go/main.go

```go
package main

import (
    "fmt"
    "os"
    "strconv"
    "sync"
    "time"
)

func main() {
    numRoutines := 100000
    if len(os.Args) > 1 {
        n, err := strconv.Atoi(os.Args[1])
        if err == nil {
            numRoutines = n
        }
    }

    var wg sync.WaitGroup
    for i := 0; i < numRoutines; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        time.Sleep(10 * time.Second)
    }()
    }
    wg.Wait()
    fmt.Println("All goroutines finished.")
}
```
*/

#include <events.h>

void *func(param_t args) {
    sleep_task(10 * seconds(10));
    return 0;
}

void *main_main(param_t args) {
    uint32_t numRoutines = 100000, i;
    if (args[0].integer > 1)
		numRoutines = (uint32_t)atoi(args[1].array_char[1]);

    waitgroup_t wg = waitgroup(numRoutines);
    for (i = 0; i < numRoutines; i++) {
        go(func, 0);
    }
    waitfor(wg);

    printf("\nAll coroutines finished.\n");
    return 0;
}

int main(int argc, char **argv) {
	events_init(1024);
	async_task(main_main, 2, casting(argc), argv);
	events_t *loop = events_create(6);
	async_run(loop);
	events_destroy(loop);

	return 0;
}
