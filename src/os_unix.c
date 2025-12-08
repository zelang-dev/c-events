#include "events_internal.h"

#undef accept
#undef listen
#undef read
#undef write
#undef close
#undef open
#undef connect
#undef mkfifo

static sigset_t events_siglock, events_siglock_all;
static struct sigaction events_sig_sa = {0}, events_sig_osa = {0};
static volatile sig_atomic_t signal_running = false;
static sys_signal_t events_sig[max_event_sig] = {0};
volatile sig_atomic_t events_got_signal = 0;

#define events_sigblock		sigfillset(&events_siglock);	\
    pthread_sigmask(SIG_SETMASK, &events_siglock, &events_siglock_all)
#define events_sigunblock	pthread_sigmask(SIG_SETMASK, &events_siglock_all, NULL)

/*
 * This structure holds an entry for each oustanding async I/O operation.
 */
typedef struct {
	fd_types type;
	os_cb proc;	    /* callout completion procedure */
	void *data;	    /* caller private data */
	int fd;
	int len;
	int offset;
	void *buf;
	int inUse;
	execinfo_t process[1];
} FD_TABLE;

/*
 * Entries in the async I/O table are allocated 2 per file descriptor.
 *
 * Read Entry Index  = fd * 2
 * Write Entry Index = (fd * 2) + 1
 */
#define AIO_RD_IX(fd) (fd * 2)
#define AIO_WR_IX(fd) ((fd * 2) + 1)

static int ioTableSize = 16;
static int asyncIoInUse = false;
static FD_TABLE *fdTable = NULL;

static int os_initialized = false;

static fd_set readFdSet;
static fd_set writeFdSet;

static fd_set readFdSetPost;
static int numRdPosted = 0;
static fd_set writeFdSetPost;
static int numWrPosted = 0;
static int volatile maxFd = -1;

static int acceptMutex = 0;

static void grow_ioTable(void) {
	int oldTableSize = ioTableSize;

	ioTableSize = ioTableSize * 2;
	fdTable = (FD_TABLE *)events_realloc(fdTable, ioTableSize * sizeof(FD_TABLE));
	if (fdTable == NULL) {
		errno = ENOMEM;
		return;
	}
	memset((char *)&fdTable[oldTableSize], 0,
		oldTableSize * sizeof(FD_TABLE));
}

static void os_sigusr1handler(int signo) {
	os_shutdown();
}

static void os_sigpipehandler(int signo) {
	;
}

static void install_signal_handler(int signo, const struct sigaction *act, int force) {
	struct sigaction sa;

	sigaction(signo, NULL, &sa);

	if (force || sa.sa_handler == SIG_DFL) {
		sigaction(signo, act, NULL);
	}
}

static void os_signal_handlers(int force) {
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = os_sigpipehandler;
	install_signal_handler(SIGPIPE, &sa, force);

	sa.sa_handler = os_sigusr1handler;
	install_signal_handler(SIGUSR1, &sa, force);
}

int os_init(void) {
	if (os_initialized)
		return 0;

	fdTable = (FD_TABLE *)events_malloc(ioTableSize * sizeof(FD_TABLE));
	if (fdTable == NULL) {
		errno = ENOMEM;
		return -1;
	}

	memset((char *)fdTable, 0, ioTableSize * sizeof(FD_TABLE));

	FD_ZERO(&readFdSet);
	FD_ZERO(&writeFdSet);
	FD_ZERO(&readFdSetPost);
	FD_ZERO(&writeFdSetPost);

	os_signal_handlers(false);

	os_initialized = true;

	return 0;
}

void os_shutdown(void) {
	if (!os_initialized)
		return;

	events_free(fdTable);
	fdTable = NULL;
	os_initialized = false;
	return;
}

/**
 * On platforms that implement concurrent calls to accept on
 * a shared listening ipc `Fd`, returns 0.
 *
 * On other platforms, acquires an exclusive lock across all processes sharing a
 * listening ipcFd, blocking until the lock has been acquired.
 *
 * return `0` for successful call, `-1` in case of system error (fatal).
 */
static int acquire_lock(int sock) {
	do {
		struct flock lock;
		lock.l_type = F_WRLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;

		if (fcntl(sock, F_SETLKW, &lock) != -1)
			return 0;
	} while (errno == EINTR
		&& !acceptMutex
		&& !events_is_shutdown());

	return -1;
}

/**
 * On platforms that implement concurrent calls to accept
 * on a shared listening ipcFd, does nothing. On other platforms,
 * releases an exclusive lock acquired by AcquireLock.
 *
 * return `0` for successful call, `-1` in case of system error (fatal).
 */
static int release_lock(int sock) {
	do {
		struct flock lock;
		lock.l_type = F_UNLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;

		if (fcntl(sock, F_SETLK, &lock) != -1)
			return 0;
	} while (errno == EINTR);

	return -1;
}

EVENTS_INLINE int os_iodispatch(int ms) {
	return 0;
}

EVENTS_INLINE int os_mkfifo(const char *name, mode_t mode) {
	events_init(256);
	snprintf(sys_event.pNamed, sizeof(sys_event.pNamed), "%s%s", SYS_PIPE, name);
	return mkfifo(sys_event.pNamed, mode);
}

EVENTS_INLINE int os_open(const char *path, int flags, mode_t mode) {
	if (str_has((const char *)sys_event.pNamed, (char *)path)) {
		sys_event.pHandle = open((const char *)sys_event.pNamed, flags, mode);
		return sys_event.pHandle;
	}

	return open(path, flags, mode);
}

EVENTS_INLINE int os_connect(fds_t s, const struct sockaddr *name, int namelen) {
	return connect(s, name, namelen);
}

static int new_fd(int fd) {
	int i, index = -1;

	events_fd_t *target = events_target(fd);
	acquire_lock(fd);
	while (target->loop && target->loop->active_descriptors >= ioTableSize)
		grow_ioTable();

	if (fd > 0 && fd < ioTableSize && fdTable[fd].type == FD_UNKNOWN) {
		index = fd;
	} else {
		for (i = 1; i < ioTableSize; ++i) {
			if (fdTable[i].type == FD_UNKNOWN) {
				index = i;
				break;
			}
		}
	}

	if (index != -1) {
		fdTable[index].proc = NULL;
		fdTable[index].data = NULL;
		fdTable[index].fd = fd;
		fdTable[index].len = -1;
		fdTable[index].offset = -1;
		fdTable[index].buf = NULL;
		fdTable[index].inUse = 0;
		fdTable[index].type = FD_CHILD;
		fdTable[index].process->fd = index;
		fdTable[index].process->env = NULL;
		fdTable[index].process->detached = false;
		fdTable[index].process->write_input[0] = inherit;
		fdTable[index].process->write_input[1] = inherit;
		fdTable[index].process->read_output[0] = inherit;
		fdTable[index].process->read_output[1] = inherit;
		fdTable[index].process->error = inherit;
		fdTable[index].process->ps = -1;
	}

	release_lock(fd);
	return index;
}

static EVENTS_INLINE unsigned int get_fd(int pseudo) {
	return fdTable[pseudo].process->ps;
}

static inline process_t os_exec_info(const char *filename, execinfo_t *info) {
	process_t p = vfork();
	if (p != 0) {
		if (info->argv != NULL)
			events_free(info->argv);

		if (info->env != NULL)
			events_free(info->env);

		info->ps = p;
		info->argv = NULL;
		info->env = NULL;
		return (process_t)info->fd;
	}

	if (info->detached && setsid() < 0) {
		goto end;
	} else {
		struct sigaction sa = {0};
		sa.sa_handler = SIG_DFL;
		sigaction(SIGPIPE, &sa, NULL);

		if (info->write_input[1] != -1)
			dup2(info->write_input[1], STDIN_FILENO);
		if (info->read_output[1] != -1)
			dup2(info->read_output[1], STDOUT_FILENO);
		if (info->error != -1)
			dup2(info->error, STDERR_FILENO);
	}

	if (info->workdir != NULL && 0 != chdir(info->workdir))
		goto end;

	execve(filename, (char **)info->argv, (char **)info->env);

end:
	_exit(255);
	return 0;
}

EVENTS_INLINE execinfo_t *exec_info(const char *env, bool is_detached,
	filefd_t io_in, filefd_t io_out, filefd_t io_err) {
	int pseudofd = new_fd(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
	execinfo_t *info = fdTable[pseudofd].process;
	info->detached = is_detached;
	if (env != NULL && str_has(env, "=") && str_has(env, ";"))
		info->env = (const char **)str_slice(env, ";", NULL);

	if (io_in)
		info->write_input[1] = io_in;

	if (io_out)
		info->read_output[1] = io_out;

	if (io_err)
		info->error = io_err;

	info->fd = pseudofd;
	return info;
}

EVENTS_INLINE process_t exec(const char *command, const char *args, execinfo_t *info) {
	char *cmd_arg = str_cat((args == NULL ? 2 : 3), command, ",", args);
	if (info == NULL)
		info = exec_info(NULL, false, inherit, inherit, inherit);

	info->argv = str_slice(cmd_arg, ",", NULL);
	events_free(cmd_arg);

	return os_exec_info(command, info);
}

int exec_wait(process_t ps, unsigned int timeout_ms, int *exit_code) {
	siginfo_t s;
	int r, f = 0;

	if (fdTable[(intptr_t)ps].process->detached)
		return 0;

	if (timeout_ms == 0) {
		f = WNOHANG;
		s.si_pid = 0;
	}
	do {
		r = waitid(P_PID, (id_t)get_fd(ps), &s, WEXITED | f);
	} while (r != 0 && errno == EINTR);
	if (r != 0)
		return -1;

	if (s.si_pid == 0) {
		errno = ETIMEDOUT;
		return -1;
	}

	if (exit_code != NULL) {
		if (s.si_code == CLD_EXITED)
			*exit_code = s.si_status;
		else
			*exit_code = -s.si_status;
	}
	return 0;
}

static void events_sig_handler(int sig) {
	if (signal_running)
		exit(1);

	signal_running = true;
	int i;

	events_sigblock;
	events_got_signal++;
	for (i = 0; i < max_event_sig; i++) {
		if (events_sig[i].sig == sig && events_sig[i].proc != NULL) {
			events_got_signal--;
			events_sig[i].is_running = true;
			events_sig[i].proc(sig, EVENTS_SIGNAL, events_sig[i].data);
			events_sig[i].is_running = false;
			break;
		}
	}
	events_sigunblock;
	signal_running = false;
}

void events_del_signal(int sig, int i) {
	if (events_sig[i].sig == sig) {
		events_sig[i].proc = NULL;
		events_sig[i].is_running = false;
		events_sig[i].data = NULL;
		events_sig[i].sig = -1;
		events_sig_sa.sa_handler = SIG_DFL;
		if (sigemptyset(&events_sig_sa.sa_mask) != 0)
			fprintf(stderr, "Cannot setup handler for signal no %d\n", sig);
		else if (sigaction(sig, &events_sig_sa, NULL) != 0)
			fprintf(stderr, "Cannot restore handler for signal no %d\n", sig);
	}
}

sys_signal_t *events_signals(void) {
	return events_sig;
}

int events_add_signal(int sig, sig_cb proc, void *data) {
	int i;
	for (i = 0; i < max_event_sig; i++) {
		if (!events_sig[i].proc || events_sig[i].sig == sig)
			break;
	}

	if (i == max_event_sig) {
		fprintf(stderr,
			"Cannot install exception handler for signal no (%d), "
			"too many signal exception handlers installed (max %d)\n",
			sig, max_event_sig);
		return -1;
	}

	events_sigblock;
	/*
	 * Make signal handlers persistent.
	 */
	events_sig_sa.sa_handler = events_sig_handler;
	events_sig_sa.sa_flags = SA_RESTART;
	if (sigemptyset(&events_sig_sa.sa_mask) != 0) {
		fprintf(stderr, "Cannot setup handler for signal no (%d)\n", sig);
		events_sigunblock;
		return -1;
	} else if (sigaction(sig, &events_sig_sa, NULL) != 0) {
		fprintf(stderr, "Cannot install handler for signal no (%d)\n", sig);
		events_sigunblock;
		return -1;
	} else {
		events_sig[i].proc = proc;
		events_sig[i].data = data;
		events_sig[i].loop = NULL;
		events_sig[i].is_running = false;
		events_sig[i].sig = sig;
	}
	events_sigunblock;
	return i;
}

EVENTS_INLINE int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor) {
	if (!key) return -1;

	return (pthread_key_create(key, dtor) == 0) ? 0 : -1;
}

EVENTS_INLINE void os_tls_free(tls_emulate_t key) {
	void *ptr = os_tls_get(key);
	if (ptr != NULL)
		events_free(ptr);

	pthread_key_delete(key);
}

EVENTS_INLINE void *os_tls_get(tls_emulate_t key) {
	return pthread_getspecific(key);
}

EVENTS_INLINE int os_tls_set(tls_emulate_t key, void *val) {
	return (pthread_setspecific(key, val) == 0) ? 0 : -1;
}

EVENTS_INLINE os_thread_t os_create(os_thread_proc proc, void *param) {
	os_thread_t t = 0;
	typedef void *(*start_routine) (void *);
	pthread_attr_t *pattr = NULL;

	if (0 != pthread_create(&t, pattr, (start_routine)(void *)proc, param))
		t = OS_NULL;

end:
	if (pattr != NULL)
		pthread_attr_destroy(pattr);

	return t;
}

/** Add msec value to 'timespec' object */
EVENTS_INLINE void _timespec_addms(struct timespec *ts, size_t ms) {
	ts->tv_sec += ms / 1000;
	ts->tv_nsec += (ms % 1000) * 1000 * 1000;
	if (ts->tv_nsec >= 1000 * 1000 * 1000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000 * 1000 * 1000;
	}
}

EVENTS_INLINE int os_join(os_thread_t t, unsigned int timeout_ms, int *exit_code) {
	void *result;
	int r;

	if (timeout_ms == (unsigned int)-1) {
		r = pthread_join(t, &result);
	}

#if defined(__linux__) && !defined(ANDROID)
	else if (timeout_ms == 0) {
		r = pthread_tryjoin_np(t, &result);
		if (r == EBUSY)
			r = ETIMEDOUT;
	}
#endif

#if defined(__linux__)  && !defined(ANDROID)
	else {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		_timespec_addms(&ts, timeout_ms);
		r = pthread_timedjoin_np(t, &result, &ts);
	}
#else
	else {
		r = pthread_join(t, &result);
	}
#endif

	if (r != 0) {
		errno = r;
		return -1;
	}

	if (exit_code != NULL)
		*exit_code = (int)(size_t)result;
	return 0;
}

EVENTS_INLINE uintptr_t os_self() {
	return (uintptr_t)pthread_self();
}

EVENTS_INLINE void os_exit(unsigned int exit_code) {
	pthread_exit((void *)(intptr_t)exit_code);
}

EVENTS_INLINE int os_detach(os_thread_t t) {
	return pthread_detach(t);
}

EVENTS_INLINE void os_cpumask_set(os_cpumask *mask, unsigned int i) {
	CPU_SET(i, mask);
}

EVENTS_INLINE int os_affinity(os_thread_t t, const os_cpumask *mask) {
#ifdef ANDROID
	errno = ENOSYS;
	return -1;
#else
	return pthread_setaffinity_np(t, sizeof(*mask), mask);
#endif
}

EVENTS_INLINE int os_sleep(unsigned int msec) {
	struct timespec ts = {
		.tv_sec = msec / 1000,
		.tv_nsec = (msec % 1000) * 1000000,
	};
	return nanosleep(&ts, NULL);
}

EVENTS_INLINE int os_geterror(void) {
	return errno;
}