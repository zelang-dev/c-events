#include "events_internal.h"

#undef accept
#undef listen
#undef read
#undef write
#undef close
#undef open
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

/**
 * Using the pathname bind_path, fill in the sockaddr_un structure
 * *servAddrPtr and the length of this structure *servAddrLen.
 *
 * @returns `0` for normal return, `-1` for failure (bind_path too long).
 *
 */
static int os_build_sockaddr_un(const char *bind_path,
	struct sockaddr_un *servAddrPtr, int *servAddrLen) {
	int bindpath_len = strlen(bind_path);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI, DEC */
	if (bindpath_len >= sizeof(servAddrPtr->sun_path)) {
		return -1;
	}
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
	if (bindpath_len > sizeof(servAddrPtr->sun_path)) {
		return -1;
	}
#endif
	memset((char *)servAddrPtr, 0, sizeof(*servAddrPtr));
	servAddrPtr->sun_family = AF_UNIX;
	memcpy(servAddrPtr->sun_path, bind_path, bindpath_len);
	if (servAddrPtr->sun_path[0] == '*') { // abstract socket address
		servAddrPtr->sun_path[0] = '\0';
	}
#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI, DEC */
	*servAddrLen = sizeof(servAddrPtr->sun_len)
		+ sizeof(servAddrPtr->sun_family)
		+ bindpath_len + 1;
	servAddrPtr->sun_len = *servAddrLen;
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
	*servAddrLen = sizeof(servAddrPtr->sun_family) + bindpath_len;
#endif
	return 0;
}
union SockAddrUnion {
	struct  sockaddr_un	unixVariant;
	struct  sockaddr_in	inetVariant;
};

int os_create_ipc(const char *bind_path, int backlog) {
	int listenSock, servLen;
	union   SockAddrUnion sa;
	int	    tcp = false;
	unsigned long tcp_ia = 0;
	char *tp;
	short   port = 0;
	char    host[MAXPATHLEN];

	strcpy(host, bind_path);
	if ((tp = strchr(host, ':')) != 0) {
		*tp++ = 0;
		if ((port = atoi(tp)) == 0) {
			*--tp = ':';
		} else {
			tcp = true;
		}
	}
	if (tcp) {
		if (!*host || !strcmp(host, "*")) {
			tcp_ia = htonl(INADDR_ANY);
		} else {
			tcp_ia = inet_addr(host);
			if (tcp_ia == INADDR_NONE) {
				struct hostent *hep;
				hep = gethostbyname(host);
				if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
					fprintf(stderr, "Cannot resolve host name %s -- exiting!\n", host);
					return -(1);
				}
				if (hep->h_addr_list[1]) {
					fprintf(stderr, "Host %s has multiple addresses ---\n", host);
					fprintf(stderr, "you must choose one explicitly!!!\n");
					return -(1);
				}
				tcp_ia = ((struct in_addr *)(hep->h_addr))->s_addr;
			}
		}
	}

	if (tcp) {
		listenSock = socket(AF_INET, SOCK_STREAM, 0);
		if (listenSock >= 0) {
			int flag = 1;
			if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&flag, sizeof(flag)) < 0) {
				fprintf(stderr, "Can't set SO_REUSEADDR.\n");
				return -(1001);
			}
		}
	} else {
		listenSock = socket(AF_UNIX, SOCK_STREAM, 0);
	}
	if (listenSock < 0) {
		return -1;
	}

	/*
	 * Bind the listening socket.
	 */
	if (tcp) {
		memset((char *)&sa.inetVariant, 0, sizeof(sa.inetVariant));
		sa.inetVariant.sin_family = AF_INET;
		sa.inetVariant.sin_addr.s_addr = tcp_ia;
		sa.inetVariant.sin_port = htons(port);
		servLen = sizeof(sa.inetVariant);
	} else {
		unlink(bind_path);
		if (os_build_sockaddr_un(bind_path, &sa.unixVariant, &servLen)) {
			fprintf(stderr, "Listening socket's path name is too long.\n");
			return -(1000);
		}
	}
	if (bind(listenSock, (struct sockaddr *)&sa.unixVariant, servLen) < 0
		|| listen(listenSock, backlog) < 0) {
		perror("bind/listen");
		return (errno);
	}

	return listenSock;
}

int os_asyncread(int fd, void *buf, int len, int offset, os_cb proc, void *data) {
	int index = AIO_RD_IX(fd);

	assert(fdTable != NULL);
	asyncIoInUse = true;

	if (fd > maxFd)
		maxFd = fd;

	while (index >= ioTableSize) {
		grow_ioTable();
	}

	assert(fdTable[index].inUse == 0);
	fdTable[index].proc = proc;
	fdTable[index].data = data;
	fdTable[index].fd = fd;
	fdTable[index].len = len;
	fdTable[index].offset = offset;
	fdTable[index].buf = buf;
	fdTable[index].inUse = 1;
	FD_SET(fd, &readFdSet);
	return 0;
}

int os_asyncwrite(int fd, void *buf, int len, int offset, os_cb proc, void *data) {
	int index = AIO_WR_IX(fd);

	asyncIoInUse = true;

	if (fd > maxFd)
		maxFd = fd;

	while (index >= ioTableSize) {
		grow_ioTable();
	}

	assert(fdTable[index].inUse == 0);
	fdTable[index].proc = proc;
	fdTable[index].data = data;
	fdTable[index].fd = fd;
	fdTable[index].len = len;
	fdTable[index].offset = offset;
	fdTable[index].buf = buf;
	fdTable[index].inUse = 1;
	FD_SET(fd, &writeFdSet);
	return 0;
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
		fdTable[index].process->in = inherit;
		fdTable[index].process->out = inherit;
		fdTable[index].process->err = inherit;
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

		if (info->in != -1)
			dup2(info->in, STDIN_FILENO);
		if (info->out != -1)
			dup2(info->out, STDOUT_FILENO);
		if (info->err != -1)
			dup2(info->err, STDERR_FILENO);
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
		info->in = io_in;

	if (io_out)
		info->out = io_out;

	if (io_err)
		info->err = io_err;

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