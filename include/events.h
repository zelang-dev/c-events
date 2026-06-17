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
#	include <mach/clock.h>
#	include <mach/mach.h>
# 	include <mach/task.h>
# 	include <TargetConditionals.h>
# 	include <AvailabilityMacros.h>
#	if defined(__arm64__)
#		define USE_ASSEMBLY 1
# 		include <ptrauth.h>
#	endif
typedef unsigned long __sigset_t;
#elif !defined(_WIN32)
#	define _GNU_SOURCE
/* for sigsetjmp(), sigjmp_buf, and stack_t */
#	define _POSIX_C_SOURCE 200809L
/* for SA_ONSTACK */
#	define _XOPEN_SOURCE 600
#endif

# if defined(__linux__) && !defined(__ANDROID__)
#  include <pty.h>
# elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#  include <util.h>
# elif defined(__FreeBSD__) || defined(__DragonFly__)
#  include <libutil.h>
# endif

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(__i386__) \
|| defined(_M_IX86) || defined(_M_ARM64) || defined(__arm64__)) /* && !defined(_WIN32)  && !defined(__APPLE__) */
#	undef USE_ASSEMBLY
#	define USE_ASSEMBLY 1
# 	undef USE_UCONTEXT
# 	undef USE_SJLJ
# 	undef USE_FIBER
#endif

#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
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
#		define SYS_DIRSEP_C '\\'
#	endif
#	include <WinSock2.h>
#	include <ws2tcpip.h>
#	include <afunix.h>
typedef const SOCKADDR sockaddr_t;
typedef INT (*events_nameinfo_func)(const SOCKADDR *, socklen_t, PCHAR, DWORD, PCHAR, DWORD, INT);
C_API INT async_getnameinfo(const SOCKADDR *sa, socklen_t salen,
	PCHAR host, DWORD hostlen, PCHAR serv, DWORD servlen, INT flags);
#else
#	ifndef SYS_CONSOLE
		/* O.S. platform ~input/output~ console `DEVICE`. */
#		define SYS_CONSOLE "/dev/tty"
		/* O.S. platform ~null~ `DEVICE`. */
#		define SYS_NULL "/dev/null"
#		define SYS_DIRSEP "/"
#		define SYS_DIRSEP_C '/'
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
typedef const struct sockaddr sockaddr_t;
typedef int (*events_nameinfo_func)(const struct sockaddr *sa, socklen_t salen,
	char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
C_API int async_getnameinfo(sockaddr_t *sa, socklen_t salen,
	char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
#endif

#if defined(NO_RPMALLOC)
#	include <stdlib.h>
#else
#	include <rpmalloc.h>
#endif

/* Unified socket `union` address. */
typedef union usa_s {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_un sun;
	struct sockaddr_storage storage;
} u_saddr_t;

#include <future.h>

#define EVENTS_READ 	1
#define EVENTS_WRITE 	2
#define EVENTS_TIMEOUT 	4
#define EVENTS_CLOSED 	5
#define EVENTS_PATHWATCH 	0x8000
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
	FD_WATCH_SYNC,	/* Directory watch blocking */
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
	FD_MONITOR_ASYNC = FD_WATCH_ASYNC,
	FD_MONITOR_SYNC = FD_WATCH_SYNC
} FILE_TYPE;

/* stack of protected pointer */
struct ex_ptr_s {
	int type;
	ex_ptr_t *next;
	ex_unwind_func func;
	void **ptr;
};

C_API sys_events_t sys_event;
C_API volatile sig_atomic_t events_got_signal;

#define panicking(message)	events_abort(message, __FILE__, __LINE__, __FUNCTION__)

C_API bool events_is_destroy(void);
C_API bool events_is_shutdown(void);
C_API void events_task_unwind(tasks_t *);

/* Setup custom internal memory allocation handling. */
C_API int events_set_allocator(malloc_cb, realloc_cb, calloc_cb, free_cb);

/* Sets I/O on the given fd to be non-blocking. */
C_API int events_set_nonblocking(fds_t fd);

/* Sets I/O on the given fd to be blocking. */
C_API int events_set_blocking(fds_t fd);

/* Return unified `sockaddr` ~union~ address of given `fd`. */
C_API u_saddr_t *events_get_sockaddr(fds_t fd);

/* Set custom `user_data` to given `fd` ~internal~ table,
 * only assignable if `main thread` caller. */
C_API void events_set_target_data(fds_t, void *);

/* Return custom `user_data` from given `fd`. */
C_API void *events_get_target_data(fds_t);

/* Sets the timeout of a socket to the specified number of milliseconds.
 *
 * Max time waiting for the acknowledged of TCP data before the connection
 * will be forcefully closed and ETIMEDOUT is returned to the application. */
C_API int events_tcp_timeout(fds_t fd, int milliseconds);

/* Creates a new event loop (defined by each backend). */
C_API events_t *events_create(int max_timeout);

/* Destroys a loop (defined by each backend). */
C_API int events_destroy(events_t *loop);

C_API bool events_is_active(void);

/* Initializes events. */
C_API int events_init(int max_fd);

C_API int events_start(int max_fd, main_cb startup, void *args);
C_API void events_set_main(main_cb startup);

/* Deinitialize events. */
C_API void events_deinit(void);
C_API void events_ctr_c_unwind(void);

/* Registers a descriptor, with event, timeout, and callback argument to event loop. */
C_API int events_add(events_t *loop, fds_t sfd, int events, int timeout_in_secs, events_cb callback, void *);

/* Unregisters a file descriptor from event loop. */
C_API int events_del(fds_t sfd);

/* Registers a directory notification event on `path`, with `handler`, `filter` argument to event `loop`.
- MUST call `events_remove()` in `handler` to stop/remove event on directory.
- MUST call `events_del_watch()` to completely shutdown ALL `watch` notification events.
- MUST call `events_is_watching()` to check if notifications are active.

returns pseudo `inotify` descriptor. */
C_API int events_watch(events_t *loop, const char *path, watch_cb handler, void *filter);

/* Unregister/shutdown `notification event`, and `ALL` ~watch~ directories from event loop. */
C_API int events_del_watch(events_t *loop);

/* Unregister `wd` ~watch~ directory from event loop. */
C_API int events_remove(int wd);

/* Check if `inotify` for any ~watch~ directory is still active/registered. */
C_API bool events_is_watching(int inotify);

/* Return `number` of directory ~watch~ `notification events` active/registered. */
C_API int events_watch_count(int inotify);

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
C_API tasks_t *active_scheduler_task(void);

/* Print `current` task internal data state, only active in debug builds. */
C_API void active_info(void);

C_API void yield_active_info(void);

/* Yield execution to another `task/coroutine` and ~reschedule~ current.

NOTE: This switches to thread ~schedular~ `run queue` to `execute` next `task`. */
C_API void yield(void);

/* Creates an `task` of given function with arguments,
and immediately execute. */
C_API void launch(launch_func_t fn, uint32_t num_of_args, ...);

/* Suspends the execution of current `task`, and switch to the ~scheduler~. */
C_API void suspend(void);
C_API void resume(tasks_t *);

/* Explicitly give up the CPU for at least ms milliseconds.
Other tasks continue to run during this time.

- returns the actual amount of time slept, in milliseconds.

NOTE: Current `task` added to ~thread~ `sleep` queue,
will be added back to `thread` ~schedular~ `run queue` once `ms` expire. */
C_API uint32_t delay(uint32_t ms);

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

/* Return the unique `result id` for the current `task`,
or `task id`, if `result id` set disabled. */
C_API uint32_t task_id(void);

/* Check for `task` termination that has an result available. */
C_API bool task_is_ready(uint32_t id);

/* Check for `task` termination/return. */
C_API bool task_is_terminated(tasks_t *);

/* Check `task` for ~cancel~ request. */
C_API bool task_is_canceled(void);

/* Set/request `task` to ~cancel~, only valid on `tasks` having results. */
C_API void task_set_canceled(uint32_t id);

/* Print `task` internal data state, only active in `debug` builds. */
C_API void tasks_info(tasks_t *t, int pos);
C_API bool tasks_is_active(void);

/* Return `current` task ~user_data~. */
C_API void *task_data(void);
C_API void task_exception_set(void *);
C_API void task_scope_set(ex_memory_t *);
C_API ex_memory_t *task_scope(void);
C_API ptrdiff_t task_code(void);
C_API void *task_erred(tasks_t *t, int code);
C_API char *task_erred_str(void);

/* Set tasks `user_data`, a ~per~ `task` storage place,
use for a `this` like object behavior. */
C_API void task_data_set(tasks_t *t, void *data);

/* Get tasks `user_data`, a ~per~ `task` storage place,
use for a `this` like object behavior. */
C_API void *task_data_get(tasks_t *t);

/* Sets the current `task's` name.*/
C_API void task_name(char *fmt, ...);

/* Check for at least `n` bytes left on the stack.
If not present, `abort` stack overflow has happen. */
C_API void tasks_stack_check(int n);

/* Return `current` ~thread~ `events_t` ~loop~ handle. */
C_API events_t *event_loop(void);

/* Register an `event loop` handle to an `new` thread pool `future` instance,
for `blocking` file/cpu ~system~ handling calls. */
C_API future *events_create_future(events_t *loop);

/* Register an `event loop` handle to an `new` ~thread~ `tasks/coroutine` pool.
- This ~pool~ is where `go()` calls are executed in.
- This function MUST be called at least ONCE before any ~`go()`~ execution,
otherwise system will `panic/abort` on `go()`.
- The maximin number of `pools` possible is tried to Operating System `cpu cores` available. */
C_API int events_create_pool(events_t *loop);

/* Setup/initialize all available `cpu cores`, and return `events_t` ~loop~ handle.
- `count` represent calls to `events_create_future()`.
- `events_create_future()` WILL be called at least once, if `count` is `0` or not previous executed.
- All remainding `cores` assigned by calling `events_create_pool()`. */
C_API events_t *events_init_pool(uint32_t count);

/* This waits aka `yield` until the `result id` termination, then retrieves the value stored. */
C_API values_t await_for(uint32_t id);

/* Creates and returns an `result id`, for an ~coroutine~ aka `task`
of given `function` with `number` of args, then `arguments`.

NOTE: The `task` will be added to `current` thread ~schedular~ `run queue`,
same behavior as GoLang's `Go` statement. */
C_API uint32_t async_task(param_func_t fn, uint32_t num_of_args, ...);

/* Same as `async_task()`, except allows setting custom `stacksize` to use,
and does not `return/set` a result.

NOTE: `async_task()` would have resized the `default` ~stacksize~
to `x6` larger, if ~first~ aka `main task`. */
C_API void async_ex(size_t stacksize, launch_func_t fn, uint32_t num_args, ...);

/* Same as `async_task()`, except the ~`coroutine`~ `added/executed` in ~thread~ pool.
WILL `panic/abort`, if `events_create_pool()` not set. */
C_API uint32_t go(param_func_t fn, size_t num_of_args, ...);

/* Same as `go()`, except can set ~`stacksize`~, and ~`fn`~ is `executed` between
`guard/guarded` aka `try\catch` blocks. The ~`cleanup`~ is `fence(any)` for `scope` exit,
in addition to other `defer()` calls. */
C_API void go_guard(size_t stacksize, guarded_func_t fn, defer_cb cleanup, void *any);

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
