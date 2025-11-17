
#ifndef _OS_H
#define _OS_H

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif



#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

typedef void (*os_cb)(intptr_t file, int bytes, void *data);
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
#define inherit  INVALID_HANDLE_VALUE

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
#	ifndef getpid
#		define getpid 		GetCurrentProcessId
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
#define inherit  -1
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

typedef struct execinfo_s {
#ifdef _WIN32
	/* List of process arguments */
	char *argv;
#else
	/* List of process arguments */
	char **argv;
#endif
	/* Set working directory */
	const char *workdir;

	/* List of environment variables */
	const char **env;

	/* Create detached background process */
	bool detached;

	/* Standard file descriptors */
	filefd_t in, out, err;

	/* child process id */
	process_t ps;

	/* child pseudo fd */
	sockfd_t fd;
} execinfo_t;

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
 * Create listener pipe and IPC address.
 *
 * `Windows`
 * WILL create a named pipe and return a file descriptor
 * to it to the caller for local process communication.
 *
 * `Linux`
 * WILL create a domain socket or a TCP/IP socket bound to
 * "localhost" and return a file descriptor to it to the
 * caller for local process communication.
 *
 * @returns pseudo `file descriptor` or `-1` on error, see `errno`
 *
 */
C_API int os_create_ipc(const char *bind_path, int backlog);

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
#define open			os_open
#define mkfifo(a, b)	os_mkfifo(a, b)

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
C_API int posix_mkfifo(const char *name, mode_t mode);
C_API HANDLE mkfifo_handle(void);
#else
C_API int os_open(const char *path, int flags, mode_t mode);
#endif

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _OS_H */
