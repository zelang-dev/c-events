# events

A *tiny*, *lightning fast* **event loop**, utilizing single interface for **epoll**, **kqueue**, **iocp**.

This project takes up where [picoev](https://github.com/kazuho/picoev) left off, it forks and remake, bringing in aspects from [FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html](https://fastcgi-archives.github.io/FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html) source [fcgi2](https://github.com/FastCGI-Archives/fcgi2), specificity, how to make **Windows** `file descriptors` aka *fake* behave like on **Linux**. As such, this **events** library handles general non-blocking file I/O.

This system supports interfacing [epoll](https://en.wikipedia.org/wiki/Epoll), [kqueue](https://en.wikipedia.org/wiki/Kqueue), and [iocp](https://en.wikipedia.org/wiki/Input/output_completion_port) *thru* [wepoll](https://github.com/piscisaureus/wepoll). In reading [Practical difference between epoll and Windows IO Completion Ports (IOCP)](https://www.ulduzsoft.com/2014/01/practical-difference-between-epoll-and-windows-io-completion-ports-iocp/) discuss things where **wepoll** seem to fill.

**c-events** provides function wrappers to some **Linux** like *functionality*, exp. `mkfifo` for **Windows**. However, this project is base around *adding/registering* an `event` for an `file descriptor`, and you reacting using general platform/OS calls.
It differs from [libev](https://software.schmorp.de/pkg/libev.html), [libeio](https://software.schmorp.de/pkg/libeio.html), [libevent](https://libevent.org/), and [libuv](http://libuv.org/). It *does not* provide complete handling using special functions. It's more geared towards a supplement to **libuv**, for more finer grain control.

Some **Libevent** [examples](https://github.com/libevent/libevent/tree/master/sample) and [tests](https://github.com/libevent/libevent/tree/master/test) have been brought in and modified for *basic* testing this library.

## Table of Contents

* [Features](#features)
  * [TODO's](#todos)
* [Design](#design)
* [Synopsis](#synopsis)
* [Usage](#usage)
* [Comparisons](#comparisons)
* [Installation](#installation)
* [Contributing](#contributing)
* [License](#license)

## Features

**events** provides a mechanism to execute a callback function when a specific event occurs on a file descriptor or after a timeout has been reached. Every event represents a set of conditions, including:

* A file descriptor being ready to read from or write to,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_WRITE, 0, accept_callback, NULL)`.
* A file descriptor has close,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_CLOSE, 0, accept_callback, NULL)`.
* A timeout expiring on file descriptor in **5** secods,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_TIMEOUT, 5, accept_callback, NULL)`.
* A signal occurring,
 `events_add(loop, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL)`.
* A user-triggered event, execute in **500** milliseconds,
 `actor_t *actor = events_actor(loop, 500, actor_cb, NULL)`, `events_repeat_actor(actor, seconds(2))`, `events_clear_actor(actor)`.

Once you call `events_init(1024)` and `events_t *loop = events_create(60)` functions to set up **c-events** and associate it with an *event* ~loop~ **thread pool**, it becomes initialized. At this point, you can add ~file descriptors~, which makes it *active* in the *loop*.

When the conditions that would trigger an event occur (e.g., its file descriptor changes state or its timeout expires), the event becomes *ready*, and its (user-provided) callback function is run. All events are *persistent*, until `events_del(listen_sock)` is called, only user-triggered are one off, if not set to repeat. MUST call `events_once(loop, 5)` to monitor for changes, add a wait time in *seconds*, SHOULD be combined with `events_is_running(loop)` to ensure all events are captured.

### TODO's

* [x] Convert **[picoev API](https://github.com/kazuho/picoev)** to **Events API**, this removes the **select(2)** part of code base.
* [x] Merge the *non-assembly* **coroutine** implementation from [c-raii](https://github.com/zelang-dev/c-raii).
* [x] Merge [wepoll](https://github.com/piscisaureus/wepoll), a **epoll** emulation for **Windows**.
* [x] Merge aspects of **[fcgi2](https://github.com/FastCGI-Archives/fcgi2)**, the *pseudo file descriptors* creation implementation.
* [x] Add/recreate *tests and examples* some derived from **[libevent](https://github.com/libevent/libevent)**.
* [x] Bug fix *tests and examples* for proper execution under **Windows** and **Linux**.
* [ ] Bug fix *tests and examples* for proper execution under **Apple macOS**.
* [ ] Complete implementation of `events_addtasks_pool()`, a *thread pool* creation function for **Events API** only.
* [ ] Complete implementation of a **Linux** `inotify_add_watch()` function for **Windows**.
* [ ] Complete implementation of `inotify_add_watch()` for **Apple macOS**.
* [ ] Implement *event* `EVENTS_FILEWATCH`, `EVENTS_DIRWATCH` *file descriptor* condition, for handling `inotify_add_watch()`.
* [ ] Completion of ALL OS *file system* function routines with matching **thread** ~async_fs_~ *version*.

## Design

This implementation is similar to what I call an outline, *how a coroutine should behave with an Event Loop interface*, as described in **libev** [THREADS, COROUTINES, CONTINUATIONS, QUEUES... INSTEAD OF CALLBACKS](http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod#THREADS_COROUTINES_CONTINUATIONS_QUE) section.

The design layout is derived from the current *work in progress* in developing [c-asio](https://github.com/zelang-dev/c-asio). This was initially setup to supplement usage of using **libuv**, since they document there **Event Loop API** `handle` isn't really *thread safe*. Few things needed reimplementing, in doing so, it revealed, *libuv* has much overhead not needed, see [Comparisons](#comparisons).

The basics of this project is base around the state of the **file descriptor**. In order to formulate execution of asynchrony aka concurrency, a *coroutine* like behavior is needed. It makes using **epoll**, **kqueue** or any **multiplex** interface system more *effective*. As just, all the additional memory allocations for structures not necessary. This includes another project [c-raii](https://github.com/zelang-dev/c-raii), the **coroutine** aspect merged in, with a few things handled and named differently now, seems some bugs was addressed with unnecessary workarounds, but now fixed correctly with less work.

Most function signatures are the same, just **passthru** to the **Operating System**. In order to get cross-platform like behavior, many calls are macros pointing to internal functions to cache parameters, and redirect to correct **OS** routine, mostly for Windows.

The Operating System **file descriptor** is represented by `fds_t` and `filefd_t`. For Windows, this system will create a `pseudo fd` that actually has all [Windows event system](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-concepts) **mechanisms** *attached*. This action allows the creation of simpler a alternative *Linux* functions for *Windows* like `mkfifo()` **IPC**, and still in development `inotify_add_watch()` **file/directory monitor**, with same signatures. It's also the basics for `spawn()` **child process** *input/output* control. The functions `events_new_fd()` and `events_assign_fd()` was mainly for **Windows**,  but also available for **Linux** using [eventfd](https://man7.org/linux/man-pages/man2/eventfd.2.html) interface, and **Apple macOS** using [Darwin Notify](https://developer.apple.com/documentation/darwinnotify) functionality.

This would also allow nonblocking file system handling. But for cross-platform simplicity, everything is a *pass-thru* to a thread pool instead. A default of `1`, which is automatically created with first `events_create()` **loop** `events_t` handle. An thread pool `os_worker_t` is created by calling `events_add_pool()` with a **loop** handle. The `os_worker_t` must be pass as first parameter to standard file system functions, a few currently implemented, all prefixed as **~async_fs_~**. These functions constructed as a wrapper call to `queue_work()` in coroutine to call thread handler. Using `events_add_pool()` is intended for *FileSystem/CPU* intensive workload offloading, NO actual **Events API** should be run in another thread, using this *thread pool*. That can be achieved using `events_addtasks_pool()`, see [TODO's](#todos).

The *behavior/process* of coroutine *execution* in **c-raii** is setup for *automatically* creating/moving and putting **coroutines** in different *threads*. In which intergrating **libuv** into **c-asio** that feature had to be completely disabled on first `yield()` encounter, it's possibale, but reqquire more complexity or **thread local storage** introduction to **libuv** source, a major breaking change. Where `events_addtasks_pool()` create a `os_tasks_t` thread pool, will be for explicitly running **Events API** in another *thread*.

The following "simple TCP proxy" example demonstrate the simplicity of using `events_add()` by way of a `async_wait()` call. The `read()` and `write()` functions only has `async_wait` called added. These routines only work correctly when user set **file descriptor** to *non-blocking*. The standard process of creating a **socket** is in embedded in `async_listener()`, `async_connect()`, `async_accept()`, and are the only functions that will set **non-blocking** by default. Functions `async_connect`, `async_accept` includes a `async_wait` call.

**Run:**

```shell
tcpproxy 1234 www.google.com 80
```

**Then visit <http://localhost:1234/> and see Google.**

```c
#include <events.h>

char *server;
int local, port;

void *rwtask(param_t v) {
 int *a, rfd, wfd, n;
 char buf[2048];

 a = v->int_ptr;
 rfd = a[0];
 wfd = a[1];
 free(a);

 while ((n = async_read(rfd, buf, sizeof buf)) > 0)
  async_write(wfd, buf, n);

 shutdown(wfd, SHUT_WR);
 close(rfd);

 return 0;
}

int *mkfd2(int fd1, int fd2) {
 int *a;

 a = malloc(2 * sizeof a[0]);
 if (a == 0) {
  fprintf(stderr, "out of memory\n");
  abort();
 }
 a[0] = fd1;
 a[1] = fd2;

 return a;
}

void *proxytask(param_t v) {
 int fd, remotefd;

 fd = v->integer;
 if ((remotefd = async_connect(server, port, true)) < 0) {
  perror("async_connect");
  close(fd);
  return 0;
 }

 fprintf(stderr, "\nconnected to %s:%d"CLR_LN, server, port);

 async_task(rwtask, 1, mkfd2(fd, remotefd));
 async_task(rwtask, 1, mkfd2(remotefd, fd));

 return 0;
}

void *main_main(param_t args) {
 fds_t cfd, fd;
 int rport;
 char remote[16];

 local = atoi(args[0].char_ptr);
 server = args[1].char_ptr;
 port = atoi(args[2].char_ptr);

 if ((fd = async_listener(OS_NULL, local, true)) < 0) {
  fprintf(stderr, "cannot listen on tcp port %d: %s\n", local, strerror(errno));
  exit(1);
 }

 while ((cfd = async_accept(fd, remote, &rport)) >= 0) {
  fprintf(stderr, "connection from %s:%d"CLR_LN, remote, rport);
  async_task(proxytask, 1, casting(cfd));
 }

 return 0;
}

int main(int argc, char **argv) {
 if (argc != 4) {
  fprintf(stderr, "usage: tcpproxy localport server remoteport\n");
  exit(1);
 }

 events_init(1024);
 events_t *loop = events_create(6);
 async_task(main_main, 3, argv[1], argv[2], argv[3]);
 async_run(loop);
 events_destroy(loop);

 return 0;
}
```

## Synopsis

```c
/* Setup custom internal memory allocation handling. */
C_API int events_set_allocator(malloc_func, realloc_func, calloc_func, free_func);

/* Sets I/O on the given fd to be non-blocking. */
C_API int events_set_nonblocking(fds_t fd);

/* Creates a new event loop (defined by each backend). */
C_API events_t *events_create(int max_timeout);

/* Destroys a loop (defined by each backend). */
C_API int events_destroy(events_t *loop);

/* Initializes events. */
C_API int events_init(int max_fd);

/* Deinitializes events. */
C_API void events_deinit(void);

/* Registers a descriptor, with event, timeout, and callback argument to event loop. */
C_API int events_add(events_t *loop, fds_t sfd, int events, int timeout_in_secs, events_cb callback, void *);

/* Unregister a file descriptor from event loop. */
C_API int events_del(fds_t sfd);

/* Check if `fd` is registered. */
C_API bool events_is_registered(events_t *loop, fds_t sfd);

/* Check if any `events` still running. */
C_API bool events_is_running(events_t *loop);

/* Updates timeout. */
C_API void events_set_timeout(fds_t sfd, int secs);

/* Sets events to be watched for given desriptor. */
C_API int events_set_event(fds_t sfd, int event);

/* Execute `event loop`, waiting `max_wait` for ~events~, `0` WILL check return immediately.
WILL return `number` of active `events`, or `-1` to indicate error condition.*/
C_API int events_once(events_t *loop, int max_wait);

/* Tries to query the system for current time using `MONOTONIC` clock,
 or whatever method ~system/platform~ provides for `REALTIME`. */
C_API uint64_t events_now(void);
C_API actor_t *events_repeat_actor(actor_t *actor, int ms);
C_API actor_t *events_actor(events_t *loop, int ms, actor_cb timer, void *args);
C_API void events_clear_actor(actor_t *actor);
C_API events_t *events_actor_loop(actor_t *actor);
C_API events_t *events_loop(fds_t sfd);
C_API int events_timeofday(struct timeval *, struct timezone *);
C_API fd_types events_fd_type(int fd);
C_API sys_signal_t *events_signals(void);

/**
 * Set up for I/O descriptor masquerading.
 * Entry in `fdTable` is reserved to represent the socket/file.
 *
 * @returns
 * - `pseudo fd` an index `id`, which masquerades as a UNIX-style
 * "small non-negative integer" file/socket descriptor.
 *
 * - `-1` indicates failure.
 *
 */
C_API int events_new_fd(FILE_TYPE type, int fd, int desiredFd);

/**
 * Set pseudo FD to create the `I/O completion port on Windows`
 * or `on Unix` to set `eventfd` to be used for async I/O.
 *
 */
C_API bool events_assign_fd(filefd_t handle, int pseudo);

/**
 * Free I/O descriptor entry in `fdTable`.
 */
C_API void events_free_fd(int pseudo);
C_API uint32_t events_get_fd(int pseudo);
C_API bool events_valid_fd(int pseudo);
C_API int events_pseudo_fd(const char *name);
C_API void events_abort(const char *message, const char *file, int line, const char *function);

/* Suspends the execution of current `Generator/Coroutine`, and passing ~data~.
WILL PANIC if not an ~Generator~ function called in.
WILL `yield` current `task` until ~data~ is retrived using `yielded()`. */
C_API void yielding(void *);

/* Creates an `Generator task` of given function with arguments,
MUST use `yielding()` to pass data, and `yielded()` to get data. */
C_API generator_t generator(param_func_t, size_t, ...);

/* Resume specified ~generator task~, returning data from `yielding`. */
C_API values_t yielded(generator_t);

/* Return `generator id` in scope for last `yielded()` execution. */
C_API uint32_t gen_id(void);

/* Return ~handle~ to current `task`. */
C_API tasks_t *active_task(void);

/* Yield execution to another `task` and ~reschedule~ current.

NOTE: This switches to thread ~schedular~ `run queue` to `execute` next `task`. */
C_API void yield_task(void);

/* Suspends the execution of current `task`, and switch to the ~scheduler~. */
C_API void suspend_task(void);

/* Explicitly give up the CPU for at least ms milliseconds.
Other tasks continue to run during this time.

- returns the actual amount of time slept, in milliseconds.

NOTE: Current `task` added to ~thread~ `sleep` queue,
will be added back to `thread` ~schedular~ `run queue` once `ms` expire. */
C_API uint32_t sleep_task(uint32_t ms);

/* Returns result of an completed `task`, by `result id`.
Must call `task_is_ready()` or `task_is_terminated()` for ~completion~ status. */
C_API values_t results_for(uint32_t id);

/* Creates/initialize the next series/collection of `task's` created to be part of `task group`,
same behavior of Go's `waitGroups`.

All `task` here behaves like regular functions, meaning they return values,
and indicate a terminated/finish status.

The initialization ends when `tasks_wait()` is called, as such current `task` will pause,
and execution will begin and wait for the group of `tasks` to finished. */
C_API task_group_t *task_group(void);

 /* Pauses current `task`, and begin execution of `tasks` in `task_group_t` object,
will wait for all to finish.

Returns `array` of `results id`, accessible using `results_for()` function. */
C_API array_t tasks_wait(task_group_t *);
C_API size_t tasks_count(task_group_t *wg);

/* Return the unique `result id` for the current `task`. */
C_API uint32_t task_id(void);

/* Check for `task` termination that has an result available. */
C_API bool task_is_ready(uint32_t id);

/* Check for `task` termination/return. */
C_API bool task_is_terminated(tasks_t *);

/* Print an `task` internal data state, only active in `debug` builds. */
C_API void tasks_info(tasks_t *t, int pos);

/* Return `current` task ~user_data~. */
C_API void *task_data(void);
C_API int task_err_code(void);
C_API ptrdiff_t task_code(void);

/* Set tasks `user_data`, a ~per~ `task` storage place,
use for a `this` like object behavior. */
C_API void task_data_set(tasks_t *t, void *data);

/* Get tasks `user_data`, a ~per~ `task` storage place,
use for a `this` like object behavior. */
C_API void *task_data_get(tasks_t *t);

/* Sets the current `task's` name.*/
C_API void task_name(char *fmt, ...);
C_API size_t tasks_cpu_count(void);

/* Check for at least `n` bytes left on the stack.
If not present, `abort` stack overflow has happen. */
C_API void tasks_stack_check(int n);

/* Register an `event loop` handle to an `new` thread pool `os_worker_t` instance,
for `blocking` cpu ~system~ handling calls. */
C_API os_worker_t *events_add_pool(events_t *loop);
C_API os_tasks_t *events_addtasks_pool(events_t *loop);

/* Return `current` thread pool handle. */
C_API os_worker_t *events_pool(void);

/* This runs the function `fn` in thread `thrd` pool,
asynchronously in a separate `task`. Returns a `result id`
that will eventually hold the result of ~thread pool work~.

Similar to: https://en.cppreference.com/w/cpp/thread/async.html
https://en.cppreference.com/w/cpp/thread/packaged_task.html

MUST call `await_for()` to get any result.

NOTE: This is setup to be just an `pass thru` for any function in an separate thread. */
C_API uint32_t queue_work(os_worker_t *thrd, param_func_t fn, size_t num_args, ...);

/* This waits aka `yield` until the `result id` termination, then retrieves
the value stored. This is mainly for `queue_work()`, but also useful elsewhere.

Similar to: https://en.cppreference.com/w/cpp/thread/future/get.html
and https://en.cppreference.com/w/cpp/thread/future/valid.html */
C_API values_t await_for(uint32_t id);

/* Creates and returns an `result id`, for an ~coroutine~ aka `task`
of given `function` with `number` of args, then `arguments`.

NOTE: The `task` will be added to `current` thread ~schedular~ `run queue`,
same behavior as GoLang's `Go` statement. */
C_API uint32_t async_task(param_func_t fn, uint32_t num_of_args, ...);

/*  Low-level call sitting underneath `async_read` and `async_write`.
 Puts task to ~sleep~ while waiting for I/O to be possible on `fd`.

 `rw` specifies type of I/O:
 - 'r' means read
 - 'w' means write

 Anything else means just exceptional conditions (hang up, etc.)
 The `'r'` and `'w'` also wake up for exceptional conditions. */
C_API void async_wait(int fd, int rw);

/* Run until there are no more `tasks` left, WILL execute `loop` events. */
C_API void async_run(events_t *loop);

/** Like regular `read()`, but puts task to ~sleep~ while waiting for
 data instead of blocking the whole program. */
C_API int async_read(int fd, void *buf, int n);

/** Like `async_read()` but always calls `async_wait()` before reading. */
C_API int async_read2(int fd, void *buf, int n);

/** Like regular `write()`, but puts task to ~sleep~ while waiting to
 write data instead of blocking the whole program. */
C_API int async_write(int fd, void *buf, int n);

/** Start a ~network~ listener `server` running on ~address~,
`port` number, with protocol, `proto_tcp` determents either TCP or UDP.

The ~address~ is a string version of a `host name` or `IP` address.
If `host name`, automatically calls `async_gethostbyname()` to preform a non-blocking DNS lockup.
If ~address~ is NULL, will bind to the given `port` on all available interfaces.

- Returns a `fd` to use with `async_accept()`. */
C_API fds_t async_listener(char *server, int port, bool proto_tcp);

/** Sleep `current` task, until next `client` connection comes in from `fd` ~async_listener()~.

- If `server` not NULL, it MUST be a buffer of `16 bytes` to hold remote IP address.
- If `port` not NULL, it's filled with report port.

Returns a `connected` ~client~ `fd`, SHOULD be used in an new `task` instance for handling.*/
C_API fds_t async_accept(fds_t fd, char *server, int *port);

/** Create a ~new~ connection to `hostname`, port, with protocol,
`proto_tcp` determents either TCP or UDP.

- Hostname can be an `ip` address or a `domain name`.
- If `domain name`, automatically calls `async_gethostbyname()` to preform a non-blocking DNS lockup. */
C_API fds_t async_connect(char *hostname, int port, bool proto_tcp);

/* Return `ip` address from `async_gethostbyname()` execution. */
C_API char *gethostbyname_ip(struct hostent *host);

/** Preform a non-blocking DNS lockup in separate `thrd` thread ~pool~ provided,
 returns ~struct~ `hostent` address. */
C_API struct hostent *async_get_hostbyname(os_worker_t *thrd, char *hostname);

/** Preform a non-blocking DNS lockup in separate `thread`,
 returns ~struct~ `hostent` address. */
C_API struct hostent *async_gethostbyname(char *hostname);

C_API int async_get_addrinfo(os_worker_t *thrd, const char *name,
 const char *service, const struct addrinfo *hints, addrinfo_t result);

C_API int async_getaddrinfo(const char *name,
 const char *service, const struct addrinfo *hints, addrinfo_t result);

C_API int async_fs_open(os_worker_t *thrd, const char *path, int flag, int mode);
C_API int fs_open(const char *path, int flag, int mode);

C_API int async_fs_read(os_worker_t *thrd, int fd, void *buf, uint32_t count);
C_API int fs_read(int fd, void *buf, uint32_t count);

C_API int async_fs_write(os_worker_t *thrd, int fd, const void *buf, uint32_t count);
C_API int fs_write(int fd, const void *buf, uint32_t count);

C_API ssize_t async_fs_sendfile(os_worker_t *thrd, int fd_out, int fd_in, off_t *offset, size_t length);
C_API ssize_t fs_sendfile(int fd_out, int fd_in, off_t *offset, size_t length);

C_API int async_fs_close(os_worker_t *thrd, int fd);
C_API int fs_close(int fd);

C_API int async_fs_unlink(os_worker_t *thrd, const char *path);
C_API int fs_unlink(const char *path);

C_API int async_fs_stat(os_worker_t *thrd, const char *path, struct stat *st);
C_API int fs_stat(const char *path, struct stat *st);

C_API int async_fs_access(os_worker_t *thrd, const char *path, int mode);
C_API int fs_access(const char *path, int mode);

C_API bool fs_exists(const char *path);
C_API size_t fs_filesize(const char *path);

C_API execinfo_t *spawn(const char *command, const char *args, spawn_cb io_func, exit_cb exit_func);
C_API uintptr_t spawn_pid(execinfo_t *child);
C_API bool spawn_is_finish(execinfo_t *child);
```

## Usage

Besides all *code snippets* above, this *example* recreate **Google's** [waitGroups](https://gobyexample.com/waitgroups>) of **goroutine's**.

<table>
<tr>
<td>

<pre><code>
#include <events.h>

void *worker(param_t args) {
 int id = args[0].integer;
 printf("Worker %d starting, task id: #%d\n", id, task_id());

 sleep_task(seconds(1));

 printf(LN_CLR"Worker %d done, task id: #%d\n", id, task_id());
 return 0;
}

void *main_main(param_t args) {
 int i;

 task_group_t *wg = task_group();
 for (i = 1; i <= 5; i++) {
  async_task(worker, 1, i);
 }
 tasks_wait(wg);

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
</code></pre>

</td>
<td>

<pre><code>
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
}
</code></pre>

</td>
</tr>
</table>

## Comparisons

Same functions and behavior as Linux `mkfifo` for Windows, of **libevent** [event-read-fifo](https://github.com/libevent/libevent/blob/release-2.2.1-alpha/sample/event-read-fifo.c) sample, it states **Windows** sections don't work.

```c
#include <events.h>

static void fifo_read(fds_t fd, int event, void *arg) {
 char buf[255];
 int len;

 fprintf(stderr, "fifo_read called with fd: %d, event: %d, arg: %p\n", socket2fd(fd), event, arg);
 len = read(fd, buf, sizeof(buf) - 1);
 if (len <= 0) {
  if (len == -1)
   perror("read");
  else if (len == 0)
   fprintf(stderr, "Connection closed\n");
  events_del(fd);
  return;
 }

 buf[len] = '\0';
 fprintf(stdout, "Read: %s\n", buf);
}

static void signal_cb(fds_t sig, int event, void *arg) {
 events_t *loop = events_loop(sig);
 unlink(mkfifo_name());
 events_destroy(loop);
}

int main(int argc, char **argv) {
 events_t *base;
 struct stat st;
 const char *fifo = "event.fifo";
 int socket;

 if (lstat(fifo, &st) == 0) {
  if ((st.st_mode & S_IFMT) == S_IFREG) {
   errno = EEXIST;
   perror("lstat");
   exit(1);
  }
 }

 unlink(fifo);
 if (mkfifo(fifo, 0600) == -1) {
  perror("mkfifo");
  exit(1);
 }

 /* Initialize the event library */
 base = events_create(6);

 socket = open(fifo, O_RDWR | O_NONBLOCK, 0);
 if (socket == -1) {
  perror("open");
  unlink(mkfifo_name());
  events_destroy(base);
  exit(1);
 }

 fprintf(stderr, "Write data to %s\n", mkfifo_name());

 /* catch SIGINT so that event.fifo can be cleaned up*/
 events_add(base, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL);

 /* Initialize one event */
 events_add(base, socket, EVENTS_READ, 0, fifo_read, NULL);

 while (events_is_running(base)) {
  events_once(base, 1);
 }

 close(socket);
 unlink(fifo);
 events_destroy(base);

 return (0);
}
```

A much simpler version of **libuv** [dns](https://github.com/libuv/libuv/blob/master/docs/code/dns/main.c) example. This is same as **c-asio** <https://github.com/zelang-dev/c-asio/tree/main/examples/dns.c> intergrating **libuv**.

```c
#include <events.h>

void *main_main(param_t args) {
 char text[1024] = {0};
 int len;
 fprintf(stderr, "irc.libera.chat is..."CLR_LN);
 struct hostent *dns = async_gethostbyname("irc.libera.chat");

 fprintf(stderr, "%s"CLR_LN, gethostbyname_ip(dns));
 fds_t server = async_connect(gethostbyname_ip(dns), 6667, true);
 while ((len = async_read(server, text, sizeof(text)) > 0)) {
  fprintf(stderr, CLR"%s", text);
  memset(text, 0, sizeof(text));
 }

 return 0;
}

int main(int argc, char **argv) {
 events_init(1024);
 events_t *loop = events_create(6);
 async_task(main_main, 0);
 async_run(loop);
 events_destroy(loop);

 return 0;
}
```

A much simpler version of **libuv** [uvcat](https://github.com/libuv/libuv/blob/master/docs/code/uvcat/main.c) example. This is same as **c-asio** <https://github.com/zelang-dev/c-asio/tree/main/examples/uvcat.c> intergrating **libuv**.

```c
#include <events.h>

void *main_main(param_t args) {
 char text[1024];
 int len, fd = fs_open(args[0].const_char_ptr, O_RDONLY, 0);
 if (fd > 0) {
  if ((len = fs_read(fd, text, sizeof(text))) > 0)
   fs_write(STDOUT_FILENO, text, len);

  return casting(fs_close(fd));
 }

 return casting(fd);
}

int main(int argc, char **argv) {
 if (argc < 2) {
  fprintf(stderr, "usage: _cat filepath\n");
  exit(1);
 }

 events_init(1024);
 events_t *loop = events_create(6);
 async_task(main_main, 1, argv[1]);
 async_run(loop);
 events_destroy(loop);

 printf(LN_CLR CLR_LN);
 return 0;
}
```

A much simpler version of **libuv** [spawn](https://github.com/libuv/libuv/blob/master/docs/code/spawn/main.c) example. This is same as **c-asio** <https://github.com/zelang-dev/c-asio/tree/main/examples/spawn.c> intergrating **libuv**.

```c
#include "events.h"

void _on_exit(int exit_status, int term_signal) {
 fprintf(stderr, "\nProcess exited with status %d, signal %d\n",
  exit_status, term_signal);
}

void *main_main(param_t args) {
 execinfo_t *child = spawn("child_command", "test-dir", NULL, _on_exit);
 if (child != NULL) {
  fprintf(stderr, "\nLaunched process with ID %zu\n", spawn_pid(child));
  while (!spawn_is_finish(child))
   yield_task();
 }

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
```

## Installation

Any **commit** with an **tag** is considered *stable* for **release** at that *version* point.

If there are no *binary* available for your platform under **Releases** then build using **cmake**,
which produces **static** libraries by default.

### Linux

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug/Release -D BUILD_TESTS=OFF -D BUILD_EXAMPLES=OFF # use to not build tests and examples
cmake --build .
```

### Windows

```shell
mkdir build
cd build
cmake .. -D BUILD_TESTS=OFF -D BUILD_EXAMPLES=OFF # use to not build tests and examples
cmake --build . --config Debug/Release
```

### As cmake project dependency

> For **CMake** versions earlier than `3.14`, see <https://cmake.org/cmake/help/v3.14/module/FetchContent.html>

Add to **CMakeLists.txt**

```c
find_package(events QUIET)
if(NOT events_FOUND)
    FetchContent_Declare(events
        URL https://github.com/zelang-dev/c-events/archive/refs/tags/0.1.0.zip
        URL_MD5 0256bd86ca474383070bb1000d3f77c5
    )
    FetchContent_MakeAvailable(events)
endif()

target_include_directories(your_project PUBLIC $<BUILD_INTERFACE:${EVENTS_INCLUDE_DIR} $<INSTALL_INTERFACE:${EVENTS_INCLUDE_DIR})
target_link_libraries(your_project PUBLIC events)
```

## Contributing

Contributions are encouraged and welcome; I am always happy to get feedback or pull requests on Github :) Create [Github Issues](https://github.com/zelang-dev/c-events/issues) for bugs and new features and comment on the ones you are interested in.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
