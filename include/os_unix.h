
#ifndef _OS_UNIX_H
#define _OS_UNIX_H

#if !defined(_WIN32) /* UNIX ONLY */

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
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

#if __APPLE__ && __MACH__
#   include <sys/ucontext.h>
#endif
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

#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

#ifndef INFINITE
#	define INFINITE -1
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

#define __os_stdcall
typedef pthread_t os_thread_t;
typedef int (__os_stdcall *os_thread_proc)(void *);
typedef struct addrinfo **__restrict__ addrinfo_t;

#define inotify_init		__inotify_init
#define inotify_init1		__inotify_init1
#define inotify_add_watch	__inotify_add_watch
#define inotify_rm_watch	__inotify_rm_watch

#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

C_API int os_open(const char *path, int flags, mode_t mode);
C_API int __inotify_init(void);
C_API int __inotify_init1(int flags);
C_API int __inotify_add_watch(int fd, const char *name, uint32_t mask);
C_API int __inotify_rm_watch(int fd, int wd);

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif
#endif /* UNIX ONLY */

#endif /* _OS_UNIX_H */
