
#ifndef _OS_H
#define _OS_H

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
#	define trace Statement(printf(CLR_LN"%s:%d Trace ", __FILE__, __LINE__);)
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

/* Number used only to assist checking for stack overflows,
will also indicate a tasks is valid, not freed. */
#define TASK_MAGIC_NUMBER 0x7E3CB1A9

#ifndef TASK_STACK_SIZE
/* Stack size when creating a coroutine aka `task`. */
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

typedef void (*exit_cb)(int exit_status, int term_signal);
typedef void (*sigcall_t)(void);
typedef struct coro_events_s coroutine_t;
typedef struct events_task_s tasks_t;
typedef struct execinfo_s execinfo_t;
typedef struct _thread_worker os_worker_t;
typedef struct _thread_tasks_worker os_tasks_t;

#ifdef _WIN32 /* !_WIN32 */
#	include <windows.h>

typedef SOCKET fds_t;
typedef DWORD mode_t;
typedef HANDLE filefd_t;
typedef filefd_t pid_t;
typedef uint32_t uid_t;
typedef pid_t process_t;
typedef int socklen_t;
typedef DWORD tls_emulate_t;

#if defined(_MSC_VER)
#	define S_IRUSR S_IREAD  /* read, user */
#	define S_IWUSR S_IWRITE /* write, user */
#	define S_IXUSR 0 /* execute, user */
#	define S_IRGRP 0 /* read, group */
#	define S_IWGRP 0 /* write, group */
#	define S_IXGRP 0 /* execute, group */
#	define S_IROTH 0 /* read, others */
#	define S_IWOTH 0 /* write, others */
#	define S_IXOTH 0 /* execute, others */
#	define S_IRWXU 0
#	define S_IRWXG 0
#	define S_IRWXO 0
#endif
#ifdef _WIN32_PLATFORM_X86
/* see TLS_MAXIMUM_AVAILABLE */
#define EMULATED_THREADS_TSS_DTOR_SLOTS 1088
typedef void (*emulate_dtor)(void *);
#else
typedef void(__stdcall *emulate_dtor)(PVOID lpFlsData);
#endif
#define inherit  INVALID_HANDLE_VALUE
#define INVALID  INVALID_HANDLE_VALUE
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
#	ifndef fsync
#		define fsync 		_commit
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
#		define pipe(fds) 	os_pipe(fds)
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
#ifndef closesocket
#	define closesocket(x) closesocket(x)
#endif
#define WNOHANG 		0
#define P_PID 			0
#define WEXITED 		0
#define CLD_EXITED 		0
#define EFD_CLOEXEC 	0
#define EFD_NONBLOCK 	0
#define	IN_ISDIR		0 /* event occurred against dir */
#define	IN_CREATE		FILE_NOTIFY_CHANGE_CREATION /* Subfile was created */
#define IN_DELETE		FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME /* Subfile was deleted */
#define IN_MODIFY 		FILE_NOTIFY_CHANGE_SECURITY | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE /* File was modified */
#define IN_MOVED_FROM 	FILE_NOTIFY_CHANGE_FILE_NAME /* File was moved from X */
#define IN_MOVED_TO		FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_CREATION /* File was moved to Y */
#define IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO) /* moves */

/*
 * All of the events - we build the list by hand so that we can add flags in
 * the future and not break backward compatibility.  Apps will get only the
 * events that they originally wanted.  Be sure to add new events here!
 */
#define IN_ALL_EVENTS 	\
	(FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME /*rename, delete, create*/ \
		| FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE \
		| FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY)
typedef FILE_NOTIFY_INFORMATION inotify_t;
#else /* !_WIN32 */
#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ __APPLE__ || __MACH__
#define IN_CREATE		NOTE_WRITE /* Subfile was created */
#define IN_DELETE		(NOTE_DELETE | NOTE_REVOKE | NOTE_RENAME) /* Subfile was deleted */
#define IN_MODIFY 		NOTE_ATTRIB | NOTE_EXTEND | NOTE_LINK /* File was modified */
#define IN_MOVED_FROM 	NOTE_RENAME /* File was moved from X */
#define IN_MOVED_TO		NOTE_WRITE | NOTE_EXTEND /* File was moved to Y */
#define IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO) /* moves */

/*
 * All of the events - we build the list by hand so that we can add flags in
 * the future and not break backward compatibility.  Apps will get only the
 * events that they originally wanted.  Be sure to add new events here!
 */
#define IN_ALL_EVENTS	(NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE)
#	if __APPLE__ || __MACH__
#		undef in
#		include <CoreServices/CoreServices.h>
#		define in ,
#		include <mach/mach_time.h>
#	endif

/*
 * struct inotify_event - structure read from the inotify device for each event
 *
 * When you are watching a directory, you will receive the filename for events
 * such as IN_CREATE, IN_DELETE, IN_OPEN, IN_CLOSE, ..., relative to the wd.
 */
typedef struct inotify_event {
	int		wd;		/* watch descriptor */
	uint32_t	mask;		/* watch mask */
	uint32_t	cookie;		/* cookie to synchronize two events */
	uint32_t	len;		/* length (including nulls) of name */
	char	name[];	/* stub for possible name */
} inotify_t;
#else
#	include <sys/sendfile.h>
#	include <sys/inotify.h>
typedef struct inotify_event inotify_t;
#endif

#include <sys/wait.h>
typedef int fds_t;
typedef fds_t filefd_t;
typedef pid_t process_t;
typedef pthread_key_t tls_emulate_t;
typedef void (*emulate_dtor)(void *);
#define inherit  -1
#define INVALID  -1
#define OS_NULL	 0
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

#if defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)
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
typedef PADDRINFOA *addrinfo_t;
typedef int id_t;
#else
#if __APPLE__ && __MACH__
#   include <sys/ucontext.h>
#endif

#include <ucontext.h>
#include <pthread.h>
#include <sys/syscall.h>

#if defined __linux__
typedef cpu_set_t os_cpumask;
#elif defined __unix__
#include <sys/param.h>
#include <pthread_np.h>
typedef cpuset_t os_cpumask;
#elif __APPLE__ && __MACH__
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
typedef struct cpu_set {
	uint32_t count;
} cpu_set_t;
typedef cpu_set_t os_cpumask;
#endif

#if !defined(EV_RECEIPT)
#	define EV_RECEIPT 0
#endif

#if !defined(O_EVTONLY)
#	define O_EVTONLY O_RDONLY
#endif

typedef pthread_t os_thread_t;
#define __os_stdcall
typedef int (__os_stdcall *os_thread_proc)(void *);
typedef struct addrinfo **__restrict__ addrinfo_t;
#endif

#ifdef _WIN32
#define write 	os_write

#define R_OK    4
#define W_OK    2
#ifndef X_OK
#	define X_OK    0
#endif
#define F_OK    0

C_API int os_create_pipe(LPCSTR lpName, HANDLE *outRead, HANDLE *outWrite);
C_API int os_open(const char *path, ...);
C_API int os_pipe(int fildes[2]);
C_API int is_socket(int fd);

C_API int socketpair(int domain, int type, int protocol, fds_t sockets[2]);
C_API ssize_t pread(int d, void *buf, size_t nbytes, off_t offset);
C_API ssize_t pwrite(int d, const void *buf, size_t nbytes, off_t offset);
C_API ssize_t sendfile(int fd_out, int fd_in, off_t *offset, size_t length);
C_API int pipe2(int fildes[2], int flags);

C_API int inotify_init(void);
C_API int inotify_init1(int flags);
C_API int inotify_add_watch(int fd, const char *name, uint32_t mask);
C_API int inotify_rm_watch(int fd, int wd);

#else
#define inotify_add_watch	__inotify_add_watch
#define inotify_rm_watch	__inotify_rm_watch
C_API int os_open(const char *path, int flags, mode_t mode);
C_API int __inotify_add_watch(int fd, const char *name, uint32_t mask);
C_API int __inotify_rm_watch(int fd, int wd);
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

#if !defined(thrd_local)
#if defined(__TINYC__) || defined(emulate_tls)
#	define thrd_local_return(type, var)    return (type *)os_tls_get(emulate_##var##_tss);
#	define thrd_local_get(type, var, _initial, prefix)	\
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

#	define thrd_local_delete(type, var, _initial, prefix)	\
        prefix void var##_reset(void) {					\
            if(events_##var##_tls != 0) { 				\
                events_##var##_tls = 0;   				\
                os_tls_free(events_##var##_tss);		\
                events_##var##_tss = -1;   				\
            }                               			\
        }

#   define thrd_local_setup(type, var, _initial, prefix)	\
        static type events_##var##_buffer;				\
        prefix int events_##var##_tls = 0;				\
        prefix tls_emulate_t events_##var##_tss = 0;	\
        thrd_local_delete(type, var, _initial, prefix)	\
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
#	define thrd_local(type, var, _initial)					\
        thrd_local_setup(type, var, _initial, )	\
        thrd_local_get(type, var, _initial, )

#   define thrd_local_simple(type, var, _initial)	\
        thrd_local_setup(type, var, _initial, )  	\
        thrd_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define thrd_static(type, var, _initial)		\
        static type *var(void);					\
        static void var##_reset(void);			\
        static bool is_##var##_null(void);		\
        thrd_local_setup(type, var, _initial, static)	\
        thrd_local_get(type, var, _initial, static)

#   define thrd_static_simple(type, var, _initial)    thrd_static(type, var, _initial)

#	define thrd_local_proto(type, var, prefix) 		\
        prefix int events_##var##_tls;        	\
        prefix tls_emulate_t events_##var##_tss;	\
        prefix type var(void);                 	\
        prefix void var##_reset(void);			\
        prefix void var##_set(type value);		\
        prefix bool is_##var##_null(void);

	/* Creates a emulated `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#	define thrd_local_extern(type, variable) thrd_local_proto(type *, variable, C_API)
	/* Creates a emulated `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#	define thrd_local_external(type, variable) thrd_local_proto(type, variable, C_API)
#else
#   define thrd_local_return(type, var)    return (type)events_##var##_tls;
#   define thrd_local_get(type, var, _initial, prefix)		\
        prefix EVENTS_INLINE type var(void) {			\
            if (events_##var##_tls == _initial) {		\
                events_##var##_tls = &events_##var##_buffer;	\
            }                                   		\
            thrd_local_return(type, var)        			\
        }

#   define thrd_local_setup(type, var, _initial, prefix)		\
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
#   define thrd_local(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type *, var, _initial, )		\
        thrd_local_get(type *, var, _initial, )

#   define thrd_local_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type, var, _initial, )			\
        thrd_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define thrd_static(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type *, var, _initial, static)	\
        thrd_local_get(type *, var, _initial, static)

#   define thrd_static_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type, var, _initial, static)	\
        thrd_local_get(type, var, _initial, static)

#   define thrd_local_proto(type, var, prefix)          	\
        prefix thread_local type events_##var##_tls;	\
        prefix void var##_reset(void);					\
        prefix void var##_set(type value);           	\
        prefix bool is_##var##_null(void);             	\
        prefix type var(void);

	/* Creates a native `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#   define thrd_local_extern(type, variable) thrd_local_proto(type *, variable, C_API)
	/* Creates a native `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#   define thrd_local_external(type, variable) thrd_local_proto(type, variable, C_API)
#endif
#endif /* thrd_local */

typedef enum {
	WATCH_INVALID = 0,
	WATCH_ADDED = 1,
	WATCH_MODIFIED = 3,
	WATCH_REMOVED = 2
} events_monitors;

typedef void (*watch_cb)(int, events_monitors, const char *);
typedef void (*exec_io_cb)(fds_t writeto, size_t nread, char *outputfrom);
typedef exec_io_cb spawn_cb;

#ifndef nil
#	define nil	{0}
#endif

#ifndef null
#	define null	NULL
#endif

#ifndef ARRAY_SIZE
#	define ARRAY_SIZE	MAX_PATH
#endif

#define open			os_open
#define close 			os_close
#define connect			os_connect
#define read 			os_read
#define mkfifo(a, b)	os_mkfifo(a, b)

C_API uint32_t inotify_mask(inotify_t *);
C_API uint32_t inotify_length(inotify_t *);
C_API char *inotify_name(inotify_t *);
C_API bool inotify_added(inotify_t *);
C_API bool inotify_removed(inotify_t *);
C_API bool inotify_modified(inotify_t *);
C_API inotify_t *inotify_next(inotify_t *);

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

C_API int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor);
C_API void os_tls_free(tls_emulate_t key);
C_API void *os_tls_get(tls_emulate_t key);
C_API int os_tls_set(tls_emulate_t key, void *val);

/** Create a thread, returns `OS_NULL` on error. */
C_API os_thread_t os_create(os_thread_proc proc, void *param);

/** Join with the thread, set timeout, optional get exit_code,
returns `0` if thread exited, `errno` is set to `ETIMEDOUT` if time has expired. */
C_API int os_join(os_thread_t t, uint32_t timeout_ms, int *exit_code);

/** Detach thread. */
C_API int os_detach(os_thread_t t);

/** Add CPU number to mask. */
C_API void os_cpumask_set(os_cpumask *mask, uint32_t i);

/** Set CPU affinity. */
C_API int os_affinity(os_thread_t t, const os_cpumask *mask);

/** Get the current thread descriptor. */
C_API uintptr_t os_self();

/** Suspend the thread for the specified time. */
C_API int os_sleep(uint32_t msec);

/** Exit current thread with `result` code. */
C_API void os_exit(uint32_t exit_code);
C_API int os_geterror(void);

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
C_API int fs_writefile(const char *path, char *text);
C_API int fs_events(const char *path, watch_cb moniter);

C_API execinfo_t *spawn(const char *command, const char *args, spawn_cb io_func, exit_cb exit_func);
C_API uintptr_t spawn_pid(execinfo_t *child);
C_API bool spawn_is_finish(execinfo_t *child);

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _OS_H */
