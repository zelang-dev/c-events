
#ifndef _ASYNC_IO_H
#define _ASYNC_IO_H

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

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

#define EVENTS_TIMEOUT_IDX_UNUSED (UCHAR_MAX)

#if defined(_MSC_VER) && !defined(__clang__) && !defined(__attribute__)
#	define __attribute__(a)
#endif

#define socket2fd(sock) ((int)sock)
#define _2fd(sock) 		((int*)sock)
#define fd2socket(fd) 	((fds_t)fd)
#define _2socket(fd) 	((fds_t*)fd)

#ifndef seconds
#	define seconds(ms)	(1000 * ms)
#endif

#ifndef minutes
#	define minutes(ms)	(60000 * ms)
#endif

#ifndef hours
#	define hours(ms)	(3600000 * ms)
#endif

#ifndef trace
#	define Statement(s) do {	\
			s	\
		}	while (0)
#	define trace 		Statement(printf(CLR_LN"%s:%d Trace ", __FILE__, __LINE__);)
#	define unreachable 	Statement(printf(CLR_LN"How did we get here? In %s on line %d\n", __FILE__, __LINE__);)
#endif

#include <async_tls.h>
#ifdef _WIN32
#	include <os_windows.h>
#else
#	include <os_unix.h>
#endif

#if defined(_MSC_VER)
#   define EVENTS_INLINE __forceinline
#elif defined(__GNUC__)
#	if defined(__STRICT_ANSI__) || !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#		define EVENTS_INLINE __inline__ __attribute__((always_inline))
#	else
#		define EVENTS_INLINE inline __attribute__((always_inline))
#	endif
#elif defined(__WATCOMC__) || defined(__DMC__)
#	define EVENTS_INLINE __inline
#else
#	define EVENTS_INLINE
#endif

/* Number used only to assist checking for stack overflows,
will also indicate a tasks is valid, not freed. */
#define TASK_MAGIC_NUMBER 0x7E3CB1A9

#ifndef TASK_STACK_SIZE
/* Stack size when creating a coroutine aka `task`. */
#   define TASK_STACK_SIZE (8 * 1024)
#endif

#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

#ifndef INFINITE
#	define INFINITE -1
#endif

/* Events task status states. */
typedef enum {
	TASK_ERRED = DATA_INVALID, /* The task has erred. */
	TASK_DEAD, /* The coroutine is uninitialized or deleted. */
	TASK_NORMAL,   /* The coroutine is active but not running (that is, it has switch to another coroutine, suspended). */
	TASK_RUNNING,  /* The coroutine is active and running. */
	TASK_SUSPENDED, /* The coroutine is suspended (in a startup, or it has not started running yet). */
	TASK_SLEEPING, /* The coroutine is sleeping and scheduled to run later. */
	TASK_FINISH, /* The coroutine has completed and returned. */
	TASK_EVENT, /* The coroutine is in an Event Loop callback. */
} task_states;

typedef enum {
	ASYNC_UDP = DATA_UDP,
	ASYNC_TCP,
	ASYNC_PIPE,
	ASYNC_FILE,
	ASYNC_TLS,
} async_types;

typedef enum {
	WATCH_INVALID = 0,
	WATCH_ADDED = 0x10000,
	WATCH_MODIFIED = 0x4000,
	WATCH_REMOVED = 0x400000,
	WATCH_MOVED = 0x400
} events_monitors;

typedef struct {
	int pseudo;
	size_t bytes;	/* Size of file, in bytes. */
	size_t mtime;	/* Time of last modification. */
	size_t ctime;	/* Time of last status change. */
	char filename[NAME_MAX];
} dirent_entry;

typedef struct coro_events_s coroutine_t;
typedef struct events_task_s tasks_t;
typedef struct execinfo_s execinfo_t;
typedef struct _thread_worker os_worker_t;
typedef struct _thread_tasks_worker os_tasks_t;
typedef void (*exit_cb)(int exit_status, int term_signal);
typedef void (*watch_cb)(int wd, events_monitors mask, const char *namepath, void *filter);
typedef void (*exec_io_cb)(fds_t writeto, size_t nread, char *outputfrom);
typedef void (*sigcall_t)(void);
typedef exec_io_cb spawn_cb;
typedef const struct sockaddr sockaddr_t;
typedef struct udp_packet_s *udp_t;
typedef void (*udp_packet_cb)(udp_t);

#ifndef null
#	define null	NULL
#endif

#ifndef MAX_PATH
#	define MAX_PATH          260
#endif

#ifndef ARRAY_SIZE
#	define ARRAY_SIZE	MAX_PATH
#endif

#define open			os_open
#define close 			os_close
#define connect			os_connect
#define read 			os_read
#define mkfifo(a, b)	os_mkfifo(a, b)

#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

C_API uint32_t inotify_mask(inotify_t *);
C_API uint32_t inotify_length(inotify_t *);
C_API char *inotify_name(inotify_t *);
C_API bool inotify_added(inotify_t *);
C_API bool inotify_removed(inotify_t *);
C_API bool inotify_modified(inotify_t *);
C_API inotify_t *inotify_next(inotify_t *);
C_API int inotify_close(int fd);

/**
 * Set up the library for use.
 *
 * `Windows`
 * Sockets initialized, pseudo file descriptors setup, etc.
 *
 * `Linux` Async I/O table allocated and initialized.
 *
 * @returns `0` if success, `-1` if not.
 *
 */
C_API int os_init(void);

/**
 * Shutdown the library.
 * Memory freed, handles closed.
 */
C_API void os_shutdown(void);

/**
 * Remote connection establishment.
 * Create the socket/pipe pathname and connect to the remote application if possible.
 *
 * @returns `-1` if fail or a `fd` if connection succeeds.
 *
 */
C_API int os_connect(fds_t s, const struct sockaddr *name, int namelen);

/**
 * Pass through to the appropriate NT or unix read function.
 *
 * @returns number of byes read, `0`, or `-`1 failure
 * see `errno` contains actual error.
 *
 */
C_API int os_read(int fd, char *buf, size_t len);

/**
 * Synchronous OS write, a pass through to write function.
 *
 * @returns number of byes read, `0`, or `-1` failure
 * `errno` contains actual error.
 *
 */
C_API int os_write(int fd, char *buf, size_t len);

/**
 * Closes the descriptor.
 *
 * `Windows`
 * Closes the descriptor with routine appropriate for descriptor's type.
 * Socket or file is closed.
 *
 * - Entry in `fdTable` is marked as free.
 *
 * `Linux`
 * This is a pass through to the Unix close.
 *
 * @returns `0` for success, `-1` on failure
 *
 */
C_API int os_close(int fd);

/**
 * Pull I/O completion events off the ~queue~ and dispatch/call `handlers`.
 */
C_API int os_iodispatch(int ms);
C_API int os_mkfifo(const char *name, mode_t mode);

/**
 * @param command program to be executed.
 * @param args command line arguments, separate with comma like: `"arg1,arg2,arg3,..."`
 * @param info use `exec_info()` to setup `environment` and redirect `stdio` for the new process.
 */
C_API process_t exec(const char *command, const char *args, execinfo_t *info);

/**
 * @param env ~environment~ for the new process. `key=value`, separated with semicolon like:
 * `"Key1=Value1;Key2=Value2;Key3=Value3;..."`. If `NULL` parents environment used.
 * @param is_datached start child as ~detached~ background `process`
 * @param io_in for ~redirecting~ `stdin` or pass `inherit`
 * @param io_out for ~redirecting~ `stdout` or pass `inherit`
 * @param io_err for ~redirecting~ `stderr` or pass `inherit`
 */
C_API execinfo_t *exec_info(const char *env, bool is_datached, filefd_t io_in, filefd_t io_out, filefd_t io_err);
C_API int exec_wait(process_t ps, uint32_t timeout_ms, int *exit_code);

C_API char *mkfifo_name(void);
C_API filefd_t mkfifo_fd(void);
C_API int os_geterror(void);

/** Like regular `read()`, but puts task to ~sleep~ while waiting for
 data instead of blocking the whole program. */
C_API int async_read(int fd, void *buf, int n);

/** Like `async_read()` but always calls `async_wait()` before reading. */
C_API int async_read2(int fd, void *buf, int n);

/** Like regular `write()`, but puts task to ~sleep~ while waiting to
 write data instead of blocking the whole program. */
C_API int async_write(int fd, void *buf, int n);

/** Start/bind a ~network~ server listening on ~address~,
`port` number, `backlog` count, with protocol, `proto_tcp` determents either TCP or UDP.

The ~address~ is a string version of a `host name` or `IP` address.
If `host name`, automatically calls `async_gethostbyname()` to preform a non-blocking DNS lockup.
If ~address~ is NULL, will bind to the given `port` on all available interfaces.

- Returns a `fd` to use with `async_accept()`. */
C_API fds_t async_bind(char *address, int port, int backlog, bool proto_tcp);

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

C_API int async_fs_mkdir(os_worker_t *thrd, const char *path, mode_t mode);
C_API int fs_mkdir(const char *path, mode_t mode);

C_API int async_fs_rmdir(os_worker_t *thrd, const char *path);
C_API int fs_rmdir(const char *path);

C_API int async_fs_stat(os_worker_t *thrd, const char *path, struct stat *st);
C_API int fs_stat(const char *path, struct stat *st);

C_API int async_fs_access(os_worker_t *thrd, const char *path, int mode);
C_API int fs_access(const char *path, int mode);

C_API bool fs_exists(const char *path);
C_API size_t fs_filesize(const char *path);
C_API int fs_writefile(const char *path, char *text);
C_API char *fs_readfile(const char *path);
C_API bool fs_touch(const char *path);

/* Monitor `path` recursively for changes, WILL execute `handler` with `filter` on detections.
- This call is executed in `tasks` ~thread~ `pool`, aka `goroutine`.
- WILL only STOP on `watch directory` removal, or `task` ~canceled~ by calling `fs_events_cancel()`.
- Call `fs_events_path()` inside `handler` to get directory name.

Returns ~task~ `result id`. */
C_API int fs_events(const char *path, watch_cb handler, void *filter);
C_API int fs_events_cancel(uint32_t rid);
C_API const char *fs_events_path(int wd);

C_API execinfo_t *spawn(const char *command, const char *args, spawn_cb io_func, exit_cb exit_func);
C_API uintptr_t spawn_pid(execinfo_t *child);
C_API bool spawn_is_finish(execinfo_t *child);

C_API int udp_bind(char *addr, unsigned int flags);
C_API int udp_connect(char *addr);
C_API void udp_with(int fd, char *addr, unsigned int flags);

C_API int udp_send(udp_t, void *buf, int n);
C_API udp_t udp_recv(int fd);
C_API void udp_handler(udp_packet_cb connected, udp_t);

C_API int async_sendto(int fd, void *buf, int n);
C_API int async_recvfrom(int fd, void *buf, int n, udp_t *client);

C_API char *udp_message(udp_t);
C_API ssize_t udp_length(udp_t);
C_API unsigned int udp_flags(udp_t);
C_API bool socket_is_udp(int socket);

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _ASYNC_IO_H */
