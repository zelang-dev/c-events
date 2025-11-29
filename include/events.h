#ifndef _EVENTS_H
#define _EVENTS_H

/* uses the C standard library's `setjump`/`longjmp` API.
Overhead: `~30x` in cost compared to an ordinary function call.
*/
#define USE_SJLJ

/* uses the Windows "fibers" API.
Overhead: `~15x` in cost compared to an ordinary function call.
*/
#define USE_FIBER

/* uses the POSIX "ucontext" API.
Overhead: `~300x` in cost compared to an ordinary function call.
*/
#define USE_UCONTEXT

#ifndef _WIN32
#	define _GNU_SOURCE
#	define _BSD_SOURCE
# 	undef USE_FIBER
# 	undef USE_UCONTEXT
#else
# 	undef USE_UCONTEXT
# 	undef USE_SJLJ
#endif

#if defined(USE_SJLJ)
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
#endif

#ifndef trace
#	define Statement(s) do {	\
			s	\
		}	while (0)
#	define trace Statement(printf("%s:%d: Trace\n", __FILE__, __LINE__);)
#endif

#ifdef _WIN32
#	define FD_SETSIZE      256
#	include <WinSock2.h>
#	include <ws2tcpip.h>
#	include <io.h>
#	include <direct.h>
#else
#	if defined(__APPLE__) || defined(__MACH__)
#		include <mach/clock.h>
#		include <mach/mach.h>
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
#   include <sys/eventfd.h>
#	if defined(_SYS_EPOLL_H)
#		define epoll_close close
#	endif
#endif

#include <os.h>
#include <stdlib.h>
#include <string.h>

#define EVENTS_IS_INITD (sys_event.max_fd != 0)
#define EVENTS_IS_INITD_AND_FD_IN_RANGE(fd)	\
  (((unsigned)fd) < (unsigned)sys_event.max_fd)
#define EVENTS_TOO_MANY_LOOPS (sys_event.num_loops != 0) /* use after ++ */
#define EVENTS_FD_BELONGS_TO_LOOP(loop, fd)		\
  ((loop)->loop_id == sys_event.fds[fd].loop_id)

#define EVENTS_TIMEOUT_VEC_OF(loop, idx)		\
  ((loop)->timeout.vec + (idx) * sys_event.timeout_vec_size)
#define EVENTS_TIMEOUT_VEC_OF_VEC_OF(loop, idx)	\
  ((loop)->timeout.vec_of_vec + (idx) * sys_event.timeout_vec_of_vec_size)
#define EVENTS_RND_UP(v, d) (((v) + (d) - 1) / (d) * (d))

#define EVENTS_PAGE_SIZE 		4096
#define EVENTS_CACHE_LINE_SIZE 	32 /* in bytes, ok if greater than the actual */
#define EVENTS_SIMD_BITS 		128
#define EVENTS_TIMEOUT_VEC_SIZE 128
#define EVENTS_SHORT_BITS (sizeof(short) * 8)

#define EVENTS_READ 	1
#define EVENTS_WRITE 	2
#define EVENTS_TIMEOUT 	4
#define EVENTS_CLOSED 	5
#define EVENTS_WATCH 	8
#define EVENTS_SIGNAL 	255
#define EVENTS_ADD		0x40000000
#define EVENTS_DEL 		0x20000000
#define EVENTS_READWRITE (EVENTS_READ | EVENTS_WRITE)

#define EVENTS_TIMEOUT_IDX_UNUSED (UCHAR_MAX)

#if defined(_MSC_VER) && !defined(__clang__) && !defined(__attribute__)
#	define __attribute__(a)
#endif

#define socket2fd(sock) ((int)sock)
#define _2fd(sock) 		((int*)sock)
#define fd2socket(fd) 	((sockfd_t)fd)
#define _2socket(fd) 	((sockfd_t*)fd)

#ifndef seconds
#	define seconds(ms)	(1000 * ms)
#endif

#ifndef minutes
#	define minutes(ms)	(60000 * ms)
#endif

#ifndef hours
#	define hours(ms)	(3600000 * ms)
#endif

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
	FD_CHILD	/* process */
} fd_types;

typedef unsigned short events_id_t;
typedef struct events_loop_s events_t;
typedef struct events_fd_s events_fd_t;
typedef struct actors_s actor_t;
typedef struct timerlist_s timerlist_t;
typedef struct sys_events_s sys_events_t;
typedef struct sys_signal_s sys_signal_t;
typedef struct _thread_worker os_worker_t;
typedef struct _request_worker os_request_t;
typedef void *(*malloc_func)(size_t);
typedef void *(*realloc_func)(void *, size_t);
typedef void *(*calloc_func)(size_t, size_t);
typedef void (*free_func)(void *);
typedef void (*events_cb)(sockfd_t fd, int event, void *args);
typedef void (*actor_cb)(actor_t *, void *);
typedef void (*os_cb)(intptr_t file, int bytes, void *data);
typedef void *(*param_func_t)(param_t);
typedef intptr_t(*intptr_func_t)(intptr_t);
typedef events_cb sig_cb;

C_API sys_events_t sys_event;
C_API volatile sig_atomic_t events_got_signal;

C_API bool events_is_destroy(void);
C_API bool events_is_shutdown(void);

/* Setup custom internal memory allocation handling. */
C_API int events_set_allocator(malloc_func, realloc_func, calloc_func, free_func);

/* Sets file descriptor to nonblocking. */
C_API int events_set_nonblocking(sockfd_t sfd);

/* Creates a new event loop (defined by each backend). */
C_API events_t *events_create(int max_timeout);

/* Destroys a loop (defined by each backend). */
C_API int events_destroy(events_t *loop);

/* Initializes events. */
C_API int events_init(int max_fd);

/* Deinitialize events. */
C_API void events_deinit(void);

/* Registers a descriptor, with event, timeout, and callback argument to event loop. */
C_API int events_add(events_t *loop, sockfd_t sfd, int events, int timeout_in_secs, events_cb callback, void *);

/* Unregisters a file descriptor from event loop. */
C_API int events_del(sockfd_t sfd);

/* Check if `fd` is registered. */
C_API bool events_is_registered(events_t *loop, sockfd_t sfd);

/* Check if any `events` still running. */
C_API bool events_is_running(events_t *loop);

/* Updates timeout. */
C_API void events_set_timeout(sockfd_t sfd, int secs);

/* Sets events to be watched for given desriptor. */
C_API int events_set_event(sockfd_t sfd, int event);

/* Returns events being watched for given descriptor. */
C_API int events_get_event(events_t *loop __attribute__((unused)), sockfd_t sfd);

/* Sets callback for given descriptor. */
C_API void events_set_callback(events_t *loop __attribute__((unused)),
	sockfd_t sfd, events_cb callback, void **cb_arg);

/* Returns callback for given descriptor. */
C_API events_cb events_get_callback(events_t *loop __attribute__((unused)),
	sockfd_t sfd, void **cb_arg);

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
C_API events_t *events_loop(sockfd_t sfd);
C_API int events_timeofday(struct timeval *, struct timezone *);
C_API fd_types events_fd_type(int fd);
C_API sys_signal_t *events_signals(void);

C_API tasks_t *active_task(void);
C_API void yield_task(void);
C_API void suspend_task(void);
C_API unsigned int sleep_task(unsigned int ms);
C_API unsigned int async_task(param_func_t fn, unsigned int num_of_args, ...);
C_API values_t await_for(unsigned int id);
C_API void async_run(events_t *loop);
C_API values_t results_for(unsigned int id);
C_API task_group_t *task_group(void);
C_API array_t tasks_wait(task_group_t *);
C_API unsigned int task_id(void);
C_API bool task_is_ready(unsigned int id);
C_API bool task_is_terminated(tasks_t *);
C_API void task_info(tasks_t *t, int pos);
C_API void task_name(char *fmt, ...);
C_API size_t tasks_cpu_count(void);
C_API void tasks_stack_check(int n);

C_API os_worker_t *events_addthreads_loop(events_t *loop);
C_API os_worker_t *events_addtasks_loop(events_t *loop);

C_API unsigned int queue_work(os_worker_t *thrd, param_func_t fn, size_t num_args, ...);
C_API char *async_gethostbyname(os_worker_t *thrd, char *hostname);

#ifdef __cplusplus
}
#endif
#endif
