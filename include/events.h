#ifndef _EVENTS_H
#define _EVENTS_H

#if defined(__APPLE__) || defined(__MACH__)
#	define _DARWIN_C_SOURCE
#	define _XOPEN_SOURCE
#	if __INTEL_COMPILER
#		pragma warning(push)
#		pragma warning(disable:1478)
#	elif __clang__
#		pragma clang diagnostic push
#		pragma clang diagnostic ignored "-Wdeprecated-declarations"
#	endif
#	include <ucontext.h>
#	include <mach/clock.h>
#	include <mach/mach.h>
typedef unsigned long __sigset_t;
#elif !defined(_WIN32)
#	define _GNU_SOURCE
/* for sigsetjmp(), sigjmp_buf, and stack_t */
#	define _POSIX_C_SOURCE 200809L
/* for SA_ONSTACK */
#	define _XOPEN_SOURCE 600
#endif

#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <string.h>

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#if defined(_WIN32) || defined(_WIN64)
#	ifndef SYS_CONSOLE
		/* O.S. platform ~input/output~ console `DEVICE`. */
#		define SYS_CONSOLE "\\\\?\\CON"
		/* O.S. platform ~null~ `DEVICE`. */
#		define SYS_NULL "\\\\?\\NUL"
		/* O.S. platform ~pipe~ prefix. */
#		define SYS_PIPE "\\\\.\\pipe\\"
#		define SYS_PIPE_PRE "\\pipe\\"
#		define SYS_DIRSEP "\\"
#	endif
#	include <WinSock2.h>
#	include <ws2tcpip.h>
#	include <io.h>
#	include <direct.h>
#else
#	ifndef SYS_CONSOLE
		/* O.S. platform ~input/output~ console `DEVICE`. */
#		define SYS_CONSOLE "/dev/tty"
		/* O.S. platform ~null~ `DEVICE`. */
#		define SYS_NULL "/dev/null"
#		define SYS_DIRSEP "/"
#		ifdef __ANDROID__
			/* O.S. platform ~pipe~ prefix. */
#			define SYS_PIPE "/data/local/tmp/"
#		else
			/* O.S. platform ~pipe~ prefix. */
#			define SYS_PIPE "/tmp/"
#			define SYS_PIPE_PRE "/tmp/"
#		endif
#	endif
#	include <poll.h>
#	include <unistd.h>
#	include <arpa/inet.h>
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#   include <netdb.h>
#	include <sys/time.h>
#	include <sys/socket.h>
#	include <sys/uio.h>
#	include <sys/un.h>
#	if __APPLE__ && __MACH__
#		include <notify.h>
#		define vfork fork
#	else
#   	include <sys/eventfd.h>
#	endif
#	if defined(_SYS_EPOLL_H)
#		define epoll_close close
#	endif
#endif

#include <stdlib.h>
#include <os.h>

#define EVENTS_READ 	1
#define EVENTS_WRITE 	2
#define EVENTS_TIMEOUT 	4
#define EVENTS_CLOSED 	5
#define EVENTS_DIRWATCH 	8
#define EVENTS_FILEWATCH 	17
#define EVENTS_SIGNAL 	255
#define EVENTS_ADD		0x40000000
#define EVENTS_DEL 		0x20000000
#define EVENTS_READWRITE (EVENTS_READ | EVENTS_WRITE)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	FD_UNKNOWN, /* Unknown? */
	FD_REG,     /* Regular file */
	FD_DIR,     /* Directory */
	FD_CHR,     /* Character device */
	FD_BLK,     /* Block device */
	FD_FIFO,    /* Pipe */
	FD_LNK,     /* Symbolic link */
	FD_SOCK,	/* Socket */
	FD_CHILD,	/* process */
	FD_REG_ASYNC,	/* file non-blocking */
	FD_SOCK_ASYNC,	/* Socket non-blocking */
	FD_FIFO_ASYNC,	/* pipe non-blocking */
	FD_WATCH_ASYNC,	/* Directory watch non-blocking */
} fd_types;

typedef enum {
	FD_UNUSED = FD_UNKNOWN,
	FD_FILE_SYNC = FD_REG,
	FD_FILE_ASYNC = FD_REG_ASYNC,
	FD_SOCKET_SYNC = FD_SOCK,
	FD_SOCKET_ASYNC = FD_SOCK_ASYNC,
	FD_PIPE_SYNC = FD_FIFO,
	FD_PIPE_ASYNC = FD_FIFO_ASYNC,
	FD_PROCESS_ASYNC = FD_CHILD,
	FD_MONITOR_ASYNC = FD_WATCH_ASYNC
} FILE_TYPE;

typedef unsigned short events_id_t;
typedef struct events_loop_s events_t;
typedef struct events_fd_s events_fd_t;
typedef struct actors_s actor_t;
typedef struct timerlist_s timerlist_t;
typedef struct sys_events_s sys_events_t;
typedef struct sys_signal_s sys_signal_t;
typedef struct _request_worker os_request_t;
typedef struct task_group_s task_group_t;
typedef struct generator_s *generator_t;
typedef void *(*malloc_func)(size_t);
typedef void *(*realloc_func)(void *, size_t);
typedef void *(*calloc_func)(size_t, size_t);
typedef void (*free_func)(void *);
typedef void (*events_cb)(fds_t fd, int event, void *args);
typedef void (*actor_cb)(actor_t *, void *);
typedef void (*os_cb)(intptr_t file, int bytes, void *data);
typedef void *(*param_func_t)(param_t);
typedef events_cb sig_cb;
typedef task_group_t *waitgroup_t;

C_API sys_events_t sys_event;
C_API volatile sig_atomic_t events_got_signal;

#define panic(message)	events_abort(message, __FILE__, __LINE__, __FUNCTION__)

C_API bool events_is_destroy(void);
C_API bool events_is_shutdown(void);

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

/* Deinitialize events. */
C_API void events_deinit(void);

/* Registers a descriptor, with event, timeout, and callback argument to event loop. */
C_API int events_add(events_t *loop, fds_t sfd, int events, int timeout_in_secs, events_cb callback, void *);

/* Unregisters a file descriptor from event loop. */
C_API int events_del(fds_t sfd);

/* Check if `fd` is registered. */
C_API bool events_is_registered(events_t *loop, fds_t sfd);

/* Check if any `events` still running. */
C_API bool events_is_running(events_t *loop);

/* Updates timeout. */
C_API void events_set_timeout(fds_t sfd, int secs);

/* Sets events to be watched for given desriptor. */
C_API int events_set_event(fds_t sfd, int event);

/* Returns events being watched for given descriptor. */
C_API int events_get_event(events_t *loop __attribute__((unused)), fds_t sfd);

/* Sets callback for given descriptor. */
C_API void events_set_callback(events_t *loop __attribute__((unused)),
	fds_t sfd, events_cb callback, void **cb_arg);

/* Returns callback for given descriptor. */
C_API events_cb events_get_callback(events_t *loop __attribute__((unused)),
	fds_t sfd, void **cb_arg);

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
#if defined(__APPLE__) || defined(__MACH__)
C_API int events_timeofday(struct timeval *, void *);
#else
C_API int events_timeofday(struct timeval *, struct timezone *);
#endif
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

/* Same as `task_group()`, except all ~tasks~ executed in an `multi-threaded` ~pool~ with `main thread`,
whereas ~`task_group()`~ is single threaded, `current`.
- MUST use `go()` to create `tasks`. */
C_API waitgroup_t waitgroup(uint32_t capacity);

 /* Pauses current `task`, and begin execution of `tasks` in `task_group_t` object,
will wait for all to finish.

Returns `array` of `results id`, accessible using `results_for()` function. */
C_API array_t tasks_wait(task_group_t *);
C_API size_t tasks_count(task_group_t *wg);

/* Same as `tasks_wait()`, except require `waitgroup()` call for an ~waitgroup_t~ instance. */
C_API array_t waitfor(waitgroup_t wg);

/* Return the unique `result id` for the current `task`. */
C_API uint32_t task_id(void);

/* Check for `task` termination that has an result available. */
C_API bool task_is_ready(uint32_t id);

/* Check for `task` termination/return. */
C_API bool task_is_terminated(tasks_t *);

/* Print `task` internal data state, only active in `debug` builds. */
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

/* Return `current` ~thread~ `events_t` ~loop~ handle. */
C_API events_t *tasks_loop(void);

/* Register an `event loop` handle to an `new` thread pool `os_worker_t` instance,
for `blocking` file/cpu ~system~ handling calls. */
C_API os_worker_t *events_add_pool(events_t *loop);

/* Return `current/default` ~thread~ pool `os_worker_t` handle. */
C_API os_worker_t *events_pool(void);

/* Register an `event loop` handle to an `new` ~thread~ `tasks/coroutine` pool.
- This ~pool~ is where `go()` calls are executed in.
- This function MUST be called at least ONCE before any ~`go()`~ execution,
otherwise system will `panic/abort` on `go()`.
- The maximin number of `pools` possible is tried to Operating System `cpu cores` available. */
C_API int events_tasks_pool(events_t *loop);

/* Setup/initialize all available `cpu cores`, and return `events_t` ~loop~ handle.
- This function possibly calls `events_add_pool()` once, if not previous executed.
- All remainding `cores` assigned by calling `events_tasks_pool()`. */
C_API events_t *events_thread_init(void);

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

/* Same as `async_task()`, except the ~`coroutine`~ `added/executed` in ~thread~ pool.
WILL `panic/abort`, if `events_tasks_pool()` not set. */
C_API uint32_t go(param_func_t fn, size_t num_of_args, ...);

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

#ifdef __cplusplus
}
#endif
#endif
