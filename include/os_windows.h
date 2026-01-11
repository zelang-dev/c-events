
#ifndef _OS_WINDOWS_H
#define _OS_WINDOWS_H

#if defined(_WIN32) || defined(_WIN64) /* WINDOWS ONLY */

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#if !defined(__cplusplus)
#	define __STDC__ 1
#endif
#include <windows.h>
#include "wepoll.h"

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
#define write 	os_write

#define R_OK    4
#define W_OK    2
#ifndef X_OK
#	define X_OK    0
#endif
#define F_OK    0

#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

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

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* WINDOWS ONLY */

#endif /* _OS_WINDOWS_H */
