
#ifndef _OS_H
#define _OS_H

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#include <arrays.h>

#if defined(_WIN32) || defined(_WIN64)
#	if !defined(__cplusplus)
#		define __STDC__ 1
#	endif
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

/* Number used only to assist checking for stack overflows. */
#define TASK_MAGIC_NUMBER 0x7E3CB1A9

#ifndef TASK_STACK_SIZE
/* Stack size when creating a coroutine. */
#   define TASK_STACK_SIZE (8 * 1024)
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
} async_types;

typedef void (*os_cb)(intptr_t file, int bytes, void *data);
typedef void (*sigcall_t)(void);
typedef void *(*data_func_t)(void *);
typedef void *(*param_func_t)(param_t);
typedef intptr_t(*intptr_func_t)(intptr_t);
typedef struct coro_events_s coroutine_t;
typedef struct events_task_s tasks_t;
typedef struct execinfo_s execinfo_t;

#ifdef _WIN32 /* !_WIN32 */
#	include <windows.h>
typedef enum {
	FD_UNUSED,
	FD_FILE_SYNC,
	FD_FILE_ASYNC,
	FD_SOCKET_SYNC,
	FD_SOCKET_ASYNC,
	FD_PIPE_SYNC,
	FD_PIPE_ASYNC,
	FD_PROCESS_ASYNC
} FILE_TYPE;

typedef SOCKET sockfd_t;
typedef DWORD mode_t;
typedef HANDLE filefd_t;
typedef filefd_t pid_t;
typedef pid_t process_t;
typedef int socklen_t;
typedef DWORD tls_emulate_t;
#ifdef _WIN32_PLATFORM_X86
/* see TLS_MAXIMUM_AVAILABLE */
#define EMULATED_THREADS_TSS_DTOR_SLOTS 1088
typedef void (*emulate_dtor)(void *);
#else
typedef void(__stdcall *emulate_dtor)(PVOID lpFlsData);
#endif
#define inherit  INVALID_HANDLE_VALUE
#define OS_NULL  NULL

/* Type used for the number of file descriptors. */
typedef unsigned long int nfds_t;

#	ifndef access
#		define access 		_access
#	endif
#	ifndef dup
#		define dup 			_dup
#	endif
#	ifndef dup2
#		define dup2			_dup2
#	endif
#	ifndef ftruncate
#		define ftruncate 	_chsize
#	endif
#	ifndef fileno
#		define fileno 		_fileno
#	endif
#	ifndef getcwd
#		define getcwd 		_getcwd
#	endif
#	ifndef chdir
#		define chdir 		_chdir
#	endif
#	ifndef unlink
#		define unlink 		_unlink
#	endif
#	ifndef isatty
#		define isatty 		_isatty
#	endif
#	ifndef lseek
#		define lseek 		_lseek
#	endif
#	ifndef realpath
#		define realpath(a, b)	_fullpath((b), (a), FILENAME_MAX)
#	endif
#	ifndef lstat
#ifdef _WIN64
#		define  stat 		_stat64i32
#		define  lstat(a,b) 	_stat64i32((const char *)(a), (struct stat*)(b))
#else
#		define  stat 		_stat32i64
#		define  lstat(a,b) 	_stat32i64((const char *)(a), (struct stat*)(b))
#endif
#	endif
#	ifndef mkdir
#		define mkdir(a, b) 	_mkdir(a)
#	endif
#	ifndef pipe
#		define pipe(fds) 	posix_pipe(fds)
#	endif
#	ifndef O_NONBLOCK
#		define O_NONBLOCK 	0x100000
#	endif
#	ifndef O_CLOEXEC
#		define O_CLOEXEC 	0x200000
#	endif
#	ifndef O_ASYNC
#		define O_ASYNC		0x500000  /* no delay */
#	endif
#	ifndef O_DIRECTORY
#		define O_DIRECTORY	_O_OBTAIN_DIR
#	endif
#	ifndef O_DIRECT
#		define O_DIRECT		FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING
#	endif
#	ifndef FD_CLOEXEC
#		define FD_CLOEXEC 1
#	endif
#	ifndef ssize_t
#		ifdef _WIN64
#			define ssize_t __int64
#		else
#			define ssize_t long
#		endif
#	endif
#	ifndef SHUT_RDWR
#		define SHUT_RDWR SD_BOTH
#	endif
#	ifndef SHUT_RD
#		define SHUT_RD   SD_RECEIVE
#	endif
#	ifndef SHUT_WR
#		define SHUT_WR   SD_SEND
#	endif
#	if !defined(SOCK_NONBLOCK) || !defined(SOCK_CLOEXEC)
#		define NEED_SOCKET_FLAGS
#		define SOCK_CLOEXEC            0x8000  /* set FD_CLOEXEC */
#		define SOCK_NONBLOCK           0x4000  /* set O_NONBLOCK */
#	endif
#ifdef __ANDROID__
typedef uint16_t in_port_t;
#endif
#ifndef poll
#	define poll	posix_poll
#endif
#ifndef closesocket
#	define closesocket(x) closesocket(x)
#endif
#else /* !_WIN32 */
#include <sys/inotify.h>
#include <sys/wait.h>
typedef int sockfd_t;
typedef sockfd_t filefd_t;
typedef pid_t process_t;
typedef pthread_key_t tls_emulate_t;
typedef void (*emulate_dtor)(void *);
#define inherit  -1
#define OS_NULL  0
#endif

#ifndef STDIN_FILENO
#	define STDIN_FILENO  0
#endif

#ifndef STDOUT_FILENO
#	define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#	define STDERR_FILENO 2
#endif

#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

#ifndef INFINITE
#	define INFINITE -1
#endif

#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

#if __APPLE__ && __MACH__
#   include <sys/ucontext.h>
#elif defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)
#   if defined(_X86_)
#       define DUMMYARGS
#   else
#       define DUMMYARGS long dummy0, long dummy1, long dummy2, long dummy3,
#   endif

typedef struct ucontext_s ucontext_t;
typedef struct __stack {
	void *ss_sp;
	size_t ss_size;
	int ss_flags;
} stack_t;

typedef CONTEXT mcontext_t;
typedef unsigned long __sigset_t;

C_API int getcontext(ucontext_t *ucp);
C_API int setcontext(const ucontext_t *ucp);
C_API int makecontext(ucontext_t *, void (*)(), int, ...);
C_API int swapcontext(ucontext_t *, const ucontext_t *);

#include <process.h>
#define __os_stdcall  __stdcall
typedef HANDLE os_thread_t;
typedef int (__os_stdcall *os_thread_proc)(void *);
typedef struct os_cpumask os_cpumask;
struct os_cpumask {
	size_t value;
};
#else
#include <ucontext.h>
#include <pthread.h>
#include <sys/syscall.h>

#if defined __linux__
typedef cpu_set_t os_cpumask;
#elif defined __unix__
#include <sys/param.h>
#include <pthread_np.h>
typedef cpuset_t os_cpumask;
#endif

typedef pthread_t os_thread_t;
#define __os_stdcall
typedef int (__os_stdcall *os_thread_proc)(void *);
#endif

#define open			os_open
#define mkfifo(a, b)	os_mkfifo(a, b)


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
C_API int os_connect(sockfd_t s, const struct sockaddr *name, int namelen);

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
 * Asynchronous I/O `read` operation is queued for completion.
 *
 * This initiates an asynchronous read on the file handle which may
 * be a socket or named pipe.
 *
 * We also must save the `proc` and `data`, so later when
 * the io completes, we know who to call.
 *
 * @returns `-1` if error, `0` otherwise.
 *
 */
C_API int os_asyncread(int fd, void *buf, int len, int offset, os_cb proc, void *data);

/**
 * Asynchronous I/O `write` operation is queued for completion.
 *
 * This initiates an asynchronous write on the "fake" file
 * descriptor (which may be a file, socket, or named pipe).
 *
 * We also must save the `proc` and `data`, so later
 *	when the io completes, we know who to call.
 *
 *	We don't look at any results here (the WriteFile generally
 *	completes immediately) but do all completion processing
 *	in os_io_dispatch when we get the io completion port done
 *	notifications.  Then we call the callback.
 *
 * @returns `-1` if error, `0` otherwise.
 *
 */
C_API int os_asyncwrite(int fd, void *buf, int len, int offset, os_cb proc, void *data);

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
C_API int exec_wait(process_t ps, unsigned int timeout_ms, int *exit_code);

C_API char *mkfifo_name(void);
C_API filefd_t mkfifo_handle(void);

#ifdef _WIN32
#define read 	os_read
#define write 	os_write
#define close 	os_close

C_API int socketpair(int domain, int type, int protocol, sockfd_t sockets[2]);
C_API int is_socket(int fd);
C_API int os_open(const char *path, ...);

/**
 * Set pseudo FD and create the I/O completion port to be used for async I/O.
 */
C_API bool assign_fd(HANDLE handle, int pseudo);
C_API bool valid_fd(int fd);
C_API unsigned int get_fd(int pseudo);

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
C_API int new_fd(FILE_TYPE type, int fd, int desiredFd);

/**
 * Free I/O descriptor entry in `fdTable`.
 */
C_API void free_fd(int fd);

C_API ssize_t pread(int d, void *buf, size_t nbytes, off_t offset);
C_API ssize_t pwrite(int d, const void *buf, size_t nbytes, off_t offset);
C_API int pipe2(int fildes[2], int flags);
C_API int posix_pipe(int fildes[2]);
C_API int posix_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
C_API int posix_close(int fd);
C_API ssize_t posix_read(int fd, void *buf, size_t count);
C_API ssize_t posix_write(int fd, const void *buf, size_t count);
C_API int posix_getsockopt(int sockfd, int level, int optname,
	void *optval, socklen_t *optlen);
C_API int posix_setsockopt(int sockfd, int level, int optname,
	const void *optval, socklen_t optlen);
C_API int posix_poll(struct pollfd *pfds, nfds_t nfds, int timeout_ms);
#else
C_API int os_open(const char *path, int flags, mode_t mode);
#endif

#if !defined(thread_local) /* User can override thread_local for obscure compilers */
	 /* Running in multi-threaded environment */
#	if defined(__STDC__) /* Compiling as C Language */
#		if defined(_MSC_VER) /* Don't rely on MSVC's C11 support */
#			define thread_local __declspec(thread)
#		elif __STDC_VERSION__ < 201112L /* If we are on C90/99 */
#			if defined(__clang__) || defined(__GNUC__) /* Clang and GCC */
#				define thread_local __thread
#			else /* Otherwise, we ignore the directive (unless user provides their own) */
#				define thread_local
#				define emulate_tls 1
#			endif
#		elif __APPLE__ && __MACH__
#			define thread_local __thread
#		else /* C11 and newer define thread_local in threads.h */
#			define HAS_C11_THREADS 1
#			include <threads.h>
#		endif
#	elif defined(__cplusplus) /* Compiling as C++ Language */
#		if __cplusplus < 201103L /* thread_local is a C++11 feature */
#			if defined(_MSC_VER)
#				define thread_local __declspec(thread)
#			elif defined(__clang__) || defined(__GNUC__)
#				define thread_local __thread
#			else /* Otherwise, we ignore the directive (unless user provides their own) */
#				define thread_local
#				define emulate_tls 1
#			endif
#		else /* In C++ >= 11, thread_local in a builtin keyword */
  			/* Don't do anything */
#		endif
#		define HAS_C11_THREADS 1
#	endif
#endif

#if !defined(tls_local)
#if defined(__TINYC__) || defined(emulate_tls)
#	define tls_local_return(type, var)    return (type *)os_tls_get(emulate_##var##_tss);
#	define tls_local_get(type, var, _initial, prefix)	\
        prefix type* var(void) {						\
            if (events_##var##_tls == 0) {				\
                events_##var##_tls = sizeof(type);		\
                if (os_tls_alloc(&events_##var##_tss, (emulate_dtor)events_free) == 0)	\
                    atexit(var##_reset);				\
                else									\
                    goto err;							\
            }                                           \
            void *ptr = os_tls_get(events_##var##_tss); \
            if (ptr == NULL) {                          \
                ptr = events_calloc(1, events_##var##_tls);		\
                if (ptr == NULL)                        \
                    goto err;                           \
                if ((os_tls_set(events_##var##_tss, ptr)) != 0)	\
                    goto err;                           \
            }                                           \
            return (type *)ptr;                         \
        err:                                            \
            return NULL;                                \
        }

#	define tls_local_delete(type, var, _initial, prefix)	\
        prefix void var##_reset(void) {					\
            if(events_##var##_tls != 0) { 				\
                events_##var##_tls = 0;   				\
                os_tls_free(events_##var##_tss);		\
                events_##var##_tss = -1;   				\
            }                               			\
        }

#   define tls_local_setup(type, var, _initial, prefix)	\
        static type events_##var##_buffer;				\
        prefix int events_##var##_tls = 0;				\
        prefix tls_emulate_t events_##var##_tss = 0;	\
        tls_local_delete(type, var, _initial, prefix)	\
        prefix EVENTS_INLINE void var##_set(type *value) {	\
            *var() = *value;							\
        }												\
        prefix EVENTS_INLINE bool is_##var##_null(void) {	\
            return (type *)os_tls_get(events_##var##_tss) == (type *)_initial;	\
        }

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#	define tls_local(type, var, _initial)					\
        tls_local_setup(type, var, _initial, )	\
        tls_local_get(type, var, _initial, )

#   define tls_local_simple(type, var, _initial)	\
        tls_local_setup(type, var, _initial, )  	\
        tls_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define tls_static(type, var, _initial)		\
        static type *var(void);					\
        static void var##_reset(void);			\
        static bool is_##var##_null(void);		\
        tls_local_setup(type, var, _initial, static)	\
        tls_local_get(type, var, _initial, static)

#   define tls_static_simple(type, var, _initial)    tls_static(type, var, _initial)

#	define tls_local_proto(type, var, prefix) 		\
        prefix int events_##var##_tls;        	\
        prefix tls_emulate_t events_##var##_tss;	\
        prefix type var(void);                 	\
        prefix void var##_reset(void);			\
        prefix void var##_set(type value);		\
        prefix bool is_##var##_null(void);

	/* Creates a emulated `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#	define tls_local_extern(type, variable) tls_local_proto(type *, variable, C_API)
	/* Creates a emulated `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#	define tls_local_external(type, variable) tls_local_proto(type, variable, C_API)
#else
#   define tls_local_return(type, var)    return (type)events_##var##_tls;
#   define tls_local_get(type, var, _initial, prefix)	\
        prefix EVENTS_INLINE type var(void) {			\
            if (events_##var##_tls == _initial) {		\
                events_##var##_tls = &events_##var##_buffer;	\
            }                                   		\
            tls_local_return(type, var)        			\
        }

#   define tls_local_setup(type, var, _initial, prefix)	\
        prefix thread_local type events_##var##_tls = _initial;	\
        prefix EVENTS_INLINE void var##_reset(void) {	\
            events_##var##_tls = NULL;					\
        }												\
        prefix EVENTS_INLINE void var##_set(type value) {	\
            events_##var##_tls = value;					\
        }												\
        prefix EVENTS_INLINE bool is_##var##_null(void) {	\
            return events_##var##_tls == _initial;		\
        }

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define tls_local(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        tls_local_setup(type *, var, _initial, )		\
        tls_local_get(type *, var, _initial, )

#   define tls_local_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        tls_local_setup(type, var, _initial, )			\
        tls_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define tls_static(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        tls_local_setup(type *, var, _initial, static)	\
        tls_local_get(type *, var, _initial, static)

#   define tls_static_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        tls_local_setup(type, var, _initial, static)	\
        tls_local_get(type, var, _initial, static)

#   define tls_local_proto(type, var, prefix)          	\
        prefix thread_local type events_##var##_tls;	\
        prefix void var##_reset(void);					\
        prefix void var##_set(type value);           	\
        prefix bool is_##var##_null(void);             	\
        prefix type var(void);

	/* Creates a native `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#   define tls_local_extern(type, variable) tls_local_proto(type *, variable, C_API)
	/* Creates a native `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#   define tls_local_external(type, variable) tls_local_proto(type, variable, C_API)
#endif
#endif /* tls_local */

C_API int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor);
C_API void os_tls_free(tls_emulate_t key);
C_API void *os_tls_get(tls_emulate_t key);
C_API int os_tls_set(tls_emulate_t key, void *val);

/** Create a thread, returns `NULL` on error. */
C_API os_thread_t os_create(os_thread_proc proc, void *param);

/** Join with the thread, set timeout, optional get exit_code,
returns `0` if thread exited, `errno` is set to `ETIMEDOUT` if time has expired. */
C_API int os_join(os_thread_t t, unsigned int timeout_ms, int *exit_code);

/** Detach thread. */
C_API int os_detach(os_thread_t t);

/** Add CPU number to mask. */
C_API void os_cpumask_set(os_cpumask *mask, unsigned int i);

/** Set CPU affinity. */
C_API int os_affinity(os_thread_t t, const os_cpumask *mask);

/** Get the current thread descriptor. */
C_API uintptr_t os_self();

/** Suspend the thread for the specified time. */
C_API int os_sleep(unsigned int msec);

/** Exit current thread with `result` code. */
C_API void os_exit(unsigned int exit_code);
C_API int os_geterror(void);

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _OS_H */
