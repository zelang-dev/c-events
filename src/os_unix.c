#include "events_internal.h"

#undef accept
#undef listen
#undef read
#undef write
#undef close
#undef open
#undef connect
#undef mkfifo
#undef inotify_add_watch
#undef inotify_rm_watch
#undef inotify_init
#undef inotify_init1

#if !defined(_WIN32) /* UNIX ONLY */

static void clear_pseudo_events(void);
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
	char *path;		/* mkfifo path or cached filename */
	int fd;
	int event_fd; 	/* `eventfd` fd descriptor */
	int _fd;
	int len;
	int offset;
	int flags;
	int changes;
	int inUse;
	char *buf;
	size_t file_count;
#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
	inotify_t inotify[1]; /* for watched directory handles */
	watch_dir_t *dir; /* for watched directory entries */
#endif
	array_t inotify_wd; /* for watched directory handles */
	execinfo_t process[1];
} FD_TABLE;

static int ioTableSize = 256;
static FD_TABLE *fdTable = NULL;
static int hIoCompPort = -1;
#if __APPLE__ && __MACH__
static int hIoCompPort_token = -1;
#endif

static int os_initialized = false;

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
}

int os_init(void) {
	if (os_initialized)
		return 0;

	os_initialized = true;
	fdTable = (FD_TABLE *)events_malloc(ioTableSize * sizeof(FD_TABLE));
	if (fdTable == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (hIoCompPort == -1) {
#if __APPLE__ && __MACH__
		int status, rtoken;
		status = notify_register_file_descriptor("com.events.io.port", &hIoCompPort, 0, &hIoCompPort_token);
		if (status != NOTIFY_STATUS_OK) {
			errno = status;
			hIoCompPort = -1;
		}
#else
		hIoCompPort = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
#endif
		if (hIoCompPort == -1) {
			perror("os_init! eventfd");
			os_shutdown();
			return -1;
		}
	}

	memset((char *)fdTable, 0, ioTableSize * sizeof(FD_TABLE));
	os_signal_handlers(false);

	return 0;
}

void os_shutdown(void) {
	if (!os_initialized)
		return;

	os_initialized = false;
	clear_pseudo_events();
	if (hIoCompPort != -1) {
		close(hIoCompPort);
		hIoCompPort = -1;
	}

	events_free(fdTable);
	fdTable = NULL;
}

static int acquire_lock(int sock) {
	do {
		struct flock lock;
		lock.l_type = F_WRLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;

		if (fcntl(sock, F_SETLKW, &lock) != -1)
			return 0;
	} while (errno == EINTR	&& !events_is_shutdown());

	return -1;
}

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
	int fake;
	snprintf(sys_event.pNamed, sizeof(sys_event.pNamed), "%s%s", SYS_PIPE, name);
	if ((fake = events_new_fd(FD_PIPE_ASYNC, hIoCompPort, - 1)) != -1)
		fdTable[fake].path = str_dup_ex(sys_event.pNamed);

	return mkfifo(sys_event.pNamed, mode);
}

EVENTS_INLINE int os_open(const char *path, int flags, mode_t mode) {
	int fake = events_pseudo_fd(path);
	if (fake != -1) {
		if (fdTable[fake].type == FD_PIPE_ASYNC) {
			sys_event.pHandle = open(fdTable[fake].path, flags, mode);
			fdTable[fake].fd = sys_event.pHandle;
			return sys_event.pHandle;
		}
	}

	return open(path, flags, mode);
}

#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
void inotify_update(const char *path, watch_dir_t *watched,
	inotify_t *event, char *subpath, size_t path_max) {
	int fd = event->ident;
	DIR *dir;				/* dir structure we are reading */
	struct dirent *entry;	/* directory entry currently being processed */
	struct stat st;
	size_t i, index = 0;
	size_t index_max = $size(watched->files);
	array_t old_files = watched->files;

	dir = opendir((const char *)watched->path);
	if (NULL == dir) {
		event->udata = (void *)path;
		return;
	}

	errno = 0;
	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR) {
			continue;
		} else if (entry->d_type == DT_REG) {
			if (index >= index_max)
				break;

			dirent_entry *file = (dirent_entry *)old_files[index++].object;
			if (str_is(file->filename, entry->d_name)) {
				snprintf(subpath, path_max, "%s%s%s", path, SYS_DIRSEP, file->filename);
				if (!stat(subpath, &st)
					&& (st.st_size != file->bytes || st.st_ctime != file->ctime || st.st_mtime != file->mtime)) {
					file->bytes = st.st_size;
					file->ctime = st.st_ctime;
					file->mtime = st.st_mtime;
					old_files[index - 1].object = file;
					fdTable[fd].inUse = !atomic_load(&sys_event.num_loops);
					if (!atomic_load(&sys_event.num_loops))
						fdTable[fd].path = str_dup_ex((const char *)subpath);
					else
						fdTable[fd].process->workdir = file->filename;
					break;
				}
			} else {
				bool is_addably = true;
				fdTable[fd].inUse = 0;
				fdTable[fd].process->workdir = (const char *)entry->d_name;
				for (i = index - 1; i < index_max; i++) {
					if (str_is((const char *)entry->d_name, (const char *)((dirent_entry *)old_files[i].object)->filename)) {
						is_addably = false;
						break;
					}
				}

				snprintf(subpath, path_max, "%s%s%s", path, SYS_DIRSEP, file->filename);
				if (stat(subpath, &st)) {
					fdTable[fd].inUse = fd;
					fdTable[fd].path = str_dup_ex((const char *)subpath);
					events_free((void *)file);
					$remove(watched->files, (index - 1));
					break;
				}

				if (is_addably) {
					snprintf(subpath, path_max, "%s%s%s", path, SYS_DIRSEP, entry->d_name);
					if (!stat(subpath, &st)) {
						file = (dirent_entry *)events_calloc(1, sizeof(dirent_entry));
						file->bytes = st.st_size;
						file->ctime = st.st_ctime;
						file->mtime = st.st_mtime;
						snprintf(file->filename, NAME_MAX, "%s", entry->d_name);
						$append(watched->files, file);
						break;
					}
				}
			}
		}
	}

	fdTable[fd].offset = $size(watched->files);
	fdTable[fd].file_count = index_max;
	if (fdTable[fd].inUse) {
		event->udata = (void *)fdTable[fd].path;
	} else {
		event->udata = (void *)fdTable[fd].process->workdir;
		if (event->udata == null) {
			for (i = 0; i < index_max; i++) {
				snprintf(subpath, path_max, "%s%s%s", path, SYS_DIRSEP, ((dirent_entry *)old_files[i].object)->filename);
				if (stat(subpath, &st)) {
					fdTable[fd].inUse = fd;
					fdTable[fd].path = str_dup_ex((const char *)subpath);
					void *mem = old_files[i].object;
					$remove(watched->files, i);
					events_free(mem);
					fdTable[fd].offset = $size(watched->files);
					event->udata = (void *)fdTable[fd].path;
					break;
				}
			}
		}

		fdTable[fd].process->workdir = NULL;
	}

	closedir(dir);
}

static EVENTS_INLINE void *_inotify_update(param_t args) {
	inotify_update(args[0].const_char_ptr, (watch_dir_t *)args[1].object, (inotify_t *)args[2].object,
		args[3].char_ptr, args[4].max_size);
	return 0;
}

void *inotify_task(param_t args) {
	int fd = args[0].integer, inotifyfd = fdTable[fd]._fd;
	inotify_t *event = (inotify_t *)args[1].object;
	events_t *loop = (events_t *)args[4].object;
	const char *name = args[5].const_char_ptr;
	watch_dir_t *watched = (watch_dir_t *)args[6].object;
	char subpath[PATH_MAX]; /* buffer for building complete subdir and file names */

	await_for(queue_work(events_pool(), _inotify_update, 5, name, watched, event, subpath, PATH_MAX));
	inotify_handler(fd, event, (watch_cb)args[2].func, args[3].object);
	if (fdTable[fd].path != null) {
		events_free(fdTable[fd].path);
		fdTable[fd].path = null;
	}

	return 0;
}
#endif

int os_read(int fd, char *buf, size_t len) {
	if (events_valid_fd(fd)) {
		int ret;
#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
		if (fdTable[fd].type == FD_MONITOR_ASYNC)
			ret = kevent(fdTable[fd].fd, NULL, 0, (inotify_t *)buf, fdTable[fd].changes, NULL);
		else
			ret = read(fdTable[fd].fd, buf, len);

		if (fdTable[fd].type == FD_MONITOR_ASYNC && ret > 0) {
			char subpath[PATH_MAX];
			inotify_t *event = (inotify_t *)buf;
			watch_dir_t *dir = (watch_dir_t *)event->udata;
			const char *name = (const char *)dir->path;
			int wd = events_get_fd(event->ident);
			if (fdTable[wd].path != null) {
				events_free(fdTable[wd].path);
				fdTable[wd].path = null;
			}

			inotify_update(name, dir, event, subpath, PATH_MAX);
		}
#else
		ret = read(fdTable[fd].fd, buf, len);
		if (fdTable[fd].type != FD_CHILD) {
			fdTable[fd].buf = buf;
			fdTable[fd].process->rid = ret;
		}
#endif
		return ret;
	}

	return read(fd, buf, len);
}

EVENTS_INLINE int os_close(int fd) {
	if (fd == -1) return 0;
	int r, can_clear = events_valid_fd(fd);
	if (can_clear)
		events_free_fd(fd);

	r = close(events_get_fd(fd));
	if (can_clear) {
		fdTable[fd].type = (fd_types)FD_UNUSED;
		fdTable[fd].fd = TASK_ERRED;
	}

	return r;
}

EVENTS_INLINE int os_connect(fds_t s, const struct sockaddr *name, int namelen) {
	return connect(s, name, namelen);
}

static void clear_pseudo_events(void) {
	int i;
	acquire_lock(hIoCompPort);
	for (i = 0; i < ioTableSize; ++i) {
		if (fdTable[i].type != FD_UNUSED) {
			events_free_fd(i);
			fdTable[i].type = (fd_types)FD_UNUSED;
		}
	}
	release_lock(hIoCompPort);
}

int events_pseudo_fd(const char *name) {
	char buffer[260] = {0};
	int i;

	snprintf(buffer, sizeof(buffer), "%s%s", SYS_PIPE, name);
	for (i = 0; i < ioTableSize; ++i) {
		if (fdTable[i].type != FD_UNUSED && fdTable[i].path != NULL
			&& (str_is(buffer, fdTable[i].path) || str_is(name, fdTable[i].path)))
			return i;
	}

	return -1;
}

int events_new_fd(FILE_TYPE type, int fd, int desiredFd) {
	int i, index = -1;
	events_fd_t *target = events_target(fd);
	acquire_lock(fd);
	while (target->loop && target->loop->active_descriptors >= ioTableSize)
		grow_ioTable();

	if (desiredFd >= 0 && desiredFd < ioTableSize
		&& fdTable[desiredFd].type == FD_UNUSED) {
		index = desiredFd;
	} else if (fd > 0) {
		if (fd < ioTableSize && fdTable[fd].type == FD_UNUSED) {
			index = fd;
		} else {
			int i;

			for (i = 1; i < ioTableSize; ++i) {
				if (fdTable[i].type == FD_UNUSED) {
					index = i;
					break;
				}
			}
		}
	}

	if (index != -1) {
		fdTable[index].proc = NULL;
		fdTable[index].data = NULL;
		fdTable[index].fd = desiredFd;
		fdTable[index].event_fd = fd;
		fdTable[index].len = DATA_INVALID;
		fdTable[index]._fd = 0;
		fdTable[index].offset = 0;
		fdTable[index].flags = 0;
		fdTable[index].changes = 0;
		fdTable[index].buf = NULL;
		fdTable[index].path = NULL;
#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
		fdTable[index].file_count = 0;
		fdTable[index].dir = NULL;
		memset(fdTable[index].inotify, 0, sizeof(inotify_t));
#endif
		fdTable[index].inotify_wd = NULL;
		fdTable[index].inUse = 0;
		fdTable[index].type = (fd_types)type;
		fdTable[index].process->fd = index;
		fdTable[index].process->env = NULL;
		fdTable[index].process->io_func = NULL;
		fdTable[index].process->exit_func = NULL;
		fdTable[index].process->detached = false;
		fdTable[index].process->is_spawn = false;
		fdTable[index].process->write_input[0] = inherit;
		fdTable[index].process->write_input[1] = inherit;
		fdTable[index].process->read_output[0] = inherit;
		fdTable[index].process->read_output[1] = inherit;
		fdTable[index].process->error = inherit;
		fdTable[index].process->ps = DATA_INVALID;
	}

	release_lock(fd);
	if (index == -1)
		errno = EINVAL;

	return index;
}

EVENTS_INLINE bool events_valid_fd(int pseudo) {
	return (pseudo >= 0) && (pseudo < ioTableSize)
		&& fdTable[pseudo].type != FD_UNUSED
		&& fdTable[pseudo].fd != TASK_ERRED;
}

EVENTS_INLINE bool events_assign_fd(filefd_t handle, int pseudo) {
	if ((pseudo >= 0) && (pseudo < ioTableSize)) {
		fdTable[pseudo].fd = handle;
#if __APPLE__ && __MACH__
		int status = notify_register_file_descriptor("com.events.io.port", &fdTable[pseudo].event_fd, NOTIFY_REUSE, &fdTable[pseudo].inUse);
		if (status != NOTIFY_STATUS_OK) {
			errno = status;
			return false;
		}
#else
		fdTable[pseudo].event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
#endif
		return true;
	}

	perror("events_assign_fd");
	return false;
}

EVENTS_INLINE uint32_t events_get_fd(int pseudo) {
	return events_valid_fd(pseudo) ? fdTable[pseudo].fd : pseudo;
}

void events_free_fd(int pseudo) {
	if ((pseudo >= 0) && (pseudo < ioTableSize)
		&& fdTable[pseudo].type != FD_UNUSED) {
		acquire_lock(pseudo);
		if (fdTable[pseudo].type == FD_MONITOR_ASYNC
			|| fdTable[pseudo].type == FD_MONITOR_SYNC)
			fdTable[pseudo].inUse = fdTable[pseudo].event_fd;
		else if (fdTable[pseudo].type != FD_PIPE_ASYNC)
			close(fdTable[pseudo].event_fd);

		if (fdTable[pseudo].type == FD_MONITOR_ASYNC && fdTable[pseudo].inotify_wd != NULL) {
			$delete(fdTable[pseudo].inotify_wd);
			fdTable[pseudo].inotify_wd = NULL;
		}

		fdTable[pseudo].event_fd = TASK_ERRED;
		if (fdTable[pseudo].path != NULL) {
			events_free(fdTable[pseudo].path);
			fdTable[pseudo].path = NULL;
		}
		release_lock(pseudo);
	}
}

static inline process_t os_exec_info(const char *filename, execinfo_t *info) {
	process_t p = vfork();
	if (p != 0) {
		if (info->argv != NULL)
			events_free(info->argv);

		if (info->env != NULL)
			events_free(info->env);

		fdTable[info->fd].fd = p;
		info->ps = p;
		info->argv = NULL;
		info->env = NULL;
		return (process_t)info->fd;
	}

	if (info->detached && setsid() < 0) {
		goto end;
	} else {
		struct sigaction sa = {0};
		bool is_spawn = info->is_spawn;
		sa.sa_handler = SIG_DFL;
		sigaction(SIGPIPE, &sa, NULL);

		if (info->write_input[(is_spawn ? 0 : 1)] != -1) {
			if (dup2(info->write_input[(is_spawn ? 0 : 1)], STDIN_FILENO) < 0) {
				perror("dup2");
				goto end;
			}

			// Close the unwanted write side
			if (is_spawn)
				close(info->write_input[1]);
		}

		if (info->read_output[1] != -1) {
			if (dup2(info->read_output[1], STDOUT_FILENO) < 0){
				perror("dup2");
				goto end;
			}

			// Close the unwanted read side
			if (is_spawn)
				close(info->read_output[0]);
		}

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
#if __APPLE__ && __MACH__
	int pseudofd = events_new_fd((FILE_TYPE)FD_CHILD, hIoCompPort_token, -1);
#else
	int pseudofd = events_new_fd(FD_CHILD, eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK), -1);
#endif
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

int exec_wait(process_t ps, uint32_t timeout_ms, int *exit_code) {
	siginfo_t s;
	int r, f = 0;

	if (fdTable[(intptr_t)ps].process->detached)
		return 0;

	if (timeout_ms == 0) {
		f = WNOHANG;
		s.si_pid = 0;
	}
	do {
		r = waitid(P_PID, (id_t)fdTable[(intptr_t)ps].process->ps, &s, WEXITED | f);
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

	os_close((intptr_t)ps);
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

EVENTS_INLINE int os_join(os_thread_t t, uint32_t timeout_ms, int *exit_code) {
	void *result;
	int r;

	if (timeout_ms == (uint32_t)-1) {
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

EVENTS_INLINE void os_exit(uint32_t exit_code) {
	pthread_exit((void *)(intptr_t)exit_code);
}

EVENTS_INLINE int os_detach(os_thread_t t) {
	return pthread_detach(t);
}

#if defined(__APPLE__) || defined(__MACH__)
#include <sys/sysctl.h>

static EVENTS_INLINE void CPU_ZERO(cpu_set_t *cs) { cs->count = 0; }
static EVENTS_INLINE void CPU_SET(int num, cpu_set_t *cs) { cs->count |= (1 << num); }
static EVENTS_INLINE int CPU_ISSET(int num, cpu_set_t *cs) { return (cs->count & (1 << num)); }

int sched_getaffinity(pid_t pid, size_t cpu_size, cpu_set_t *cpu_set) {
	int32_t core_count = 0;
	size_t  len = sizeof(core_count);
	int i, ret = sysctlbyname(SYSCTL_CORE_COUNT, &core_count, &len, 0, 0);
	if (ret) {
		errno = ret;
		perror("sched_getaffinity");
		return -1;
	}

	cpu_set->count = 0;
	for (i = 0; i < core_count; i++) {
		cpu_set->count |= (1 << i);
	}

	return 0;
}

int pthread_setaffinity_np(pthread_t thread, size_t cpu_size, cpu_set_t *cpu_set) {
	thread_port_t mach_thread;
	int core = 0;

	for (core = 0; core < 8 * cpu_size; core++) {
		if (CPU_ISSET(core, cpu_set)) break;
	}

	thread_affinity_policy_data_t policy = {core};
	mach_thread = pthread_mach_thread_np(thread);
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
		(thread_policy_t)&policy, 1);
	return 0;
}
#endif

EVENTS_INLINE void os_cpumask_set(os_cpumask *mask, uint32_t i) {
	CPU_SET(i, mask);
}

EVENTS_INLINE int os_affinity(os_thread_t t, const os_cpumask *mask) {
#ifdef ANDROID
	errno = ENOSYS;
	return -1;
#else
	return pthread_setaffinity_np(t, sizeof(*mask), (cpu_set_t *)mask);
#endif
}

EVENTS_INLINE int os_sleep(uint32_t msec) {
	struct timespec ts = {
		.tv_sec = msec / 1000,
		.tv_nsec = (msec % 1000) * 1000000,
	};
	return nanosleep(&ts, NULL);
}

EVENTS_INLINE int os_geterror(void) {
	return errno;
}

EVENTS_INLINE int events_watch_count(int inotify) {
	return is_data(fdTable[inotify].inotify_wd) ? $size(fdTable[inotify].inotify_wd) : 0;
}

#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
EVENTS_INLINE uint32_t inotify_mask(inotify_t *event) {
	return event->fflags;
}

EVENTS_INLINE bool inotify_added(inotify_t *event) {
	return (event->fflags & IN_CREATE)
		&& (fdTable[event->ident].file_count < fdTable[event->ident].offset);
}

EVENTS_INLINE bool inotify_removed(inotify_t *event) {
	return (event->fflags & IN_DELETE)
		|| (fdTable[event->ident].file_count > fdTable[event->ident].offset);
}

EVENTS_INLINE bool inotify_modified(inotify_t *event) {
	return (event->fflags & IN_MODIFY);
}

EVENTS_INLINE char *inotify_name(inotify_t *event) {
	return (char *)event->udata;
}

EVENTS_INLINE uint32_t inotify_length(inotify_t *event) {
	return (event == null || !is_ptr_usable(event) || event->flags & EV_ERROR)
		? 0 : event->ident;
}

EVENTS_INLINE inotify_t *inotify_next(inotify_t *event) {
	return null;
}

void inotify_handler(int fd, inotify_t *event, watch_cb handler, void *filter) {
	char subpath[PATH_MAX] = {0};
	events_monitors action = WATCH_INVALID;
	int mask = (WATCH_MODIFIED | WATCH_REMOVED | WATCH_ADDED | WATCH_MOVED);

	if ((event->fflags & IN_CREATE)
		&& (fdTable[event->ident].file_count < fdTable[event->ident].offset))
		action = WATCH_ADDED;
	else if ((event->fflags & IN_DELETE)
		|| (fdTable[event->ident].file_count > fdTable[event->ident].offset))
		action = WATCH_REMOVED;
	else if ((event->fflags & IN_MOVE))
		action = WATCH_MOVED;
	else if ((event->fflags & IN_MODIFY))
		action = WATCH_MODIFIED;

	if (action) {
		if (fdTable[fd].inUse)
			snprintf(subpath, PATH_MAX, "%s", (const char *)event->udata);
		else
			snprintf(subpath, PATH_MAX, "%s%s%s", fdTable[fd].dir->path, SYS_DIRSEP, (const char *)event->udata);

		handler(fd, action | ~mask, (const char *)trim(subpath), filter);
		event->udata = NULL;
	}
}

EVENTS_INLINE void *kqueue_watch_filter(events_t *loop) {
	return (events_valid_fd(loop->inotify_fd) &&
		fdTable[loop->inotify_fd].type == FD_MONITOR_ASYNC) ? fdTable[loop->inotify_fd].data : null;
}

EVENTS_INLINE watch_cb kqueue_watch_callback(events_t *loop) {
	return (events_valid_fd(loop->inotify_fd)
		&& fdTable[loop->inotify_fd].type == FD_MONITOR_ASYNC) ? (watch_cb)fdTable[loop->inotify_fd].proc : null;
}

EVENTS_INLINE void kqueue_watch_init(events_t *loop, watch_cb handler, void *filter) {
	if (events_valid_fd(loop->inotify_fd) && fdTable[loop->inotify_fd].type == FD_MONITOR_ASYNC) {
		fdTable[loop->inotify_fd].data = filter;
		fdTable[loop->inotify_fd].proc = (os_cb)handler;
	}
}

EVENTS_INLINE int inotify_init(void) {
	events_init(256);
	/* Create a new kernel event queue */
	int kq = !atomic_load(&sys_event.num_loops) ? kqueue() : events_backend_fd(tasks_loop());
	if (kq == -1)
		return TASK_ERRED;

	return events_new_fd(FD_MONITOR_ASYNC, kq, kq);
}

EVENTS_INLINE int inotify_init1(int flags) {
	(void)flags;
	return inotify_init();
}

EVENTS_INLINE int inotify_wd(int pseudo) {
	return events_valid_fd(pseudo) && fdTable[pseudo].type == FD_MONITOR_ASYNC ? fdTable[pseudo]._fd : pseudo;
}

EVENTS_INLINE int inotify_flags(int pseudo) {
	return events_valid_fd(pseudo) && fdTable[pseudo].type == FD_MONITOR_SYNC ? fdTable[pseudo].flags : 0;
}

EVENTS_INLINE void *inotify_data(int pseudo) {
	return events_valid_fd(pseudo) && fdTable[pseudo].type == FD_MONITOR_SYNC ? (void *)fdTable[pseudo].dir : null;
}

int inotify_del_monitor(int wd) {
	if (events_valid_fd(wd) && fdTable[wd].type == FD_MONITOR_SYNC) {
		inotify_rm_watch(fdTable[wd]._fd, wd);
		if ($size(fdTable[fdTable[wd]._fd].inotify_wd) == 0)
			return inotify_close(fdTable[wd]._fd);

		return 0;
	}

	return TASK_ERRED;
}

EVENTS_INLINE const char *fs_events_path(int wd) {
	return (const char *)fdTable[wd].dir->path;
}

int inotify_close(int fd) {
	if (events_valid_fd(fd)) {
		foreach(watch in fdTable[fd].inotify_wd) {
			events_del(fdTable[watch.integer].fd);
			os_close(watch.integer);
			$remove(fdTable[fd].inotify_wd, iwatch);
		}

		os_close(fd);
		return 0;
	}

	return TASK_ERRED;
}

static void inotify_recursive(int fd, const char *path, uint32_t mask,
	watch_dir_t *watched, char *buf, size_t buf_max, events_t *loop) {
	DIR *dir;				/* dir structure we are reading */
	struct dirent *entry;	/* directory entry currently being processed */
	int newfd = watched->fd;

	fdTable[newfd].file_count = $size(watched->files);
	dir = opendir(path);
	if (NULL == dir)
		return;

	errno = 0;
	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR) {
			if (str_is("..", entry->d_name) || str_is(".", entry->d_name)) {
				continue;
			} else if (snprintf(buf, buf_max, "%s%s%s", path, SYS_DIRSEP, entry->d_name)) {
				int wd = open(buf, O_EVTONLY);
				if (wd == -1)
					continue;

				watched->dirs++;
				int pseudo = events_new_fd(FD_MONITOR_SYNC, wd, wd);
				fdTable[pseudo]._fd = fd;
				fdTable[pseudo].flags = mask;
				fdTable[pseudo].dir = events_calloc(1, sizeof(watch_dir_t));
				fdTable[pseudo].dir->fd = wd;
				fdTable[pseudo].dir->type = DATA_WATCH;
				snprintf(fdTable[pseudo].dir->path, PATH_MAX, "%s", buf);
				fdTable[fd].flags = mask;
				fdTable[fd]._fd = pseudo;
				if (!atomic_load(&sys_event.num_loops)) {
					fdTable[fd].changes++;
					EV_SET(fdTable[fd].inotify, wd, EVFILT_VNODE, EV_ADD | EV_ENABLE, mask, 0,
						(void *)fdTable[pseudo].dir);
					if (kevent(fdTable[fd].fd, fdTable[fd].inotify, 1, NULL, 0, NULL) == -1) {
						fdTable[fd].changes--;
						os_close(pseudo);
						continue;
					}
				} else if (atomic_load(&sys_event.num_loops) > 0) {
					if (kqueue_add_watch(loop, wd) == -1) {
						os_close(pseudo);
						continue;;
					}

					$append_signed(fdTable[fd].inotify_wd, pseudo);
				}

				inotify_recursive(fd, (const char *)fdTable[pseudo].dir->path, mask,
					fdTable[pseudo].dir, buf, buf_max, loop);
			}
		} else if (entry->d_type == DT_REG) {
			struct stat st;
			dirent_entry *file = events_calloc(1, sizeof(dirent_entry));
			snprintf(buf, buf_max, "%s%s%s", path, SYS_DIRSEP, entry->d_name);
			if (watched->files == NULL)
				watched->files = array();

			if (!stat(buf, &st)) {
				snprintf(file->filename, NAME_MAX, "%s", entry->d_name);
				file->bytes = st.st_size;
				file->ctime = st.st_ctime;
				file->mtime = st.st_mtime;
				$append(watched->files, file);
			}
		}
	}
	fdTable[newfd].file_count = $size(watched->files);
	closedir(dir);
}

static EVENTS_INLINE void *_inotify_recursive(param_t args) {
	inotify_recursive(args[0].integer, args[1].const_char_ptr, args[2].u_int, (watch_dir_t *)args[3].object,
		args[4].char_ptr, args[5].max_size, (events_t *)args[6].object);
	return 0;
}

int kqueue_add_watch(events_t *loop, int fd) {
	if (!EVENTS_IS_INITD_AND_FD_IN_RANGE(fd)) { return -1; }

	int event = EVENTS_PATHWATCH;
	events_fd_t *target = events_target(fd);
	target->is_pathwatcher = true;
	target->is_iodispatch = false;
	target->backend_used = false;
	target->callback = (events_cb)kqueue_watch_callback(loop);
	target->cb_arg = kqueue_watch_filter(loop);
	target->loop = loop;
	target->loop_id = loop->loop_id;
	target->events = 0;
	target->timeout_idx = EVENTS_TIMEOUT_IDX_UNUSED;
	if (events_update_internal(loop, fd, event | EVENTS_ADD) != 0) {
		target->loop = NULL;
		target->loop_id = 0;
		return -1;
	}

	loop->active_descriptors++;
	return 0;
}

int inotify_add_watch(int fd, const char *name, uint32_t mask) {
	struct stat st;
	char subpath[PATH_MAX];	/* buffer for building complete subdir and file names */
	if (((atomic_load(&sys_event.num_loops) > 0) ? !fs_stat(name, &st) : !stat(name, &st))
		&& (st.st_mode & S_IFMT) == S_IFDIR) {
		int newfd, wd = open(name, O_EVTONLY);
		if (wd == -1)
			return wd;

		newfd = events_new_fd(FD_MONITOR_SYNC, wd, wd);
		fdTable[newfd].flags = mask;
		fdTable[newfd]._fd = fd;
		fdTable[newfd].dir = events_calloc(1, sizeof(watch_dir_t));
		fdTable[newfd].dir->fd = wd;
		fdTable[newfd].dir->type = DATA_WATCH;
		int len = snprintf(fdTable[newfd].dir->path, PATH_MAX, "%s", name);
		if (fdTable[newfd].dir->path[len - 1] == '/')
			fdTable[newfd].dir->path[len - 1] = '\0';

		fdTable[fd].flags = mask;
		fdTable[fd]._fd = newfd;
		if (!atomic_load(&sys_event.num_loops)) {
			fdTable[fd].changes++;
			fdTable[fd].file_count = fdTable[newfd].file_count;
			EV_SET(fdTable[fd].inotify, wd, EVFILT_VNODE, EV_ADD | EV_ENABLE, mask, 0,
				(void *)fdTable[newfd].dir);
			if (kevent(fdTable[fd].fd, fdTable[fd].inotify, 1, NULL, 0, NULL) == -1) {
				fdTable[fd].changes--;
				os_close(newfd);
				return TASK_ERRED;
			}

			inotify_recursive(fd, fdTable[newfd].dir->path, mask, fdTable[newfd].dir, subpath, PATH_MAX, null);
		} else if (atomic_load(&sys_event.num_loops) > 0) {
			events_t *loop = tasks_loop();
			if (kqueue_add_watch(loop, wd) == -1) {
				os_close(newfd);
				return TASK_ERRED;
			}

			if (fdTable[fd].inotify_wd == NULL)
				fdTable[fd].inotify_wd = array();

			$append_signed(fdTable[fd].inotify_wd, newfd);
			await_for(queue_work(events_pool(), _inotify_recursive, 7, casting(fd), fdTable[newfd].dir->path,
				casting(mask), fdTable[newfd].dir, subpath, PATH_MAX, loop));
		}

		return newfd;
	}

	return TASK_ERRED;
}

EVENTS_INLINE int inotify_rm_watch(int fd, int wd) {
	if (wd < 0)
		return inotify_close(fd);

	if (!atomic_load(&sys_event.num_loops) && events_valid_fd(wd)) {
		EV_SET(fdTable[fd].inotify, fdTable[wd].fd, EVFILT_VNODE, EV_DELETE, fdTable[wd].flags, 0, 0);
		kevent(fdTable[fd].fd, fdTable[fd].inotify, 1, NULL, 0, NULL);
		fdTable[fd].changes--;
		return os_close(wd);
	} else if (atomic_load(&sys_event.num_loops) > 0 && events_valid_fd(wd)) {
		foreach(watch in fdTable[fd].inotify_wd) {
			if (watch.integer == wd) {
				events_del(fdTable[wd].fd);
				if (fdTable[wd].dir != NULL) {
					kqueue_watch_free(fdTable[wd].dir);
					fdTable[wd].dir = NULL;
				}

				os_close(wd);
				$remove(fdTable[fd].inotify_wd, iwatch);
				return 0;
			}
		}
	}

	return TASK_ERRED;
}

void kqueue_watch_free(watch_dir_t *dir) {
	if (data_type(dir) == DATA_WATCH) {
		dir->type = DATA_INVALID;
		foreach(watch in dir->files) {
			events_free(watch.object);
		}

		dir->files = NULL;
		events_free(dir);
	}
}
#else
EVENTS_INLINE uint32_t inotify_mask(inotify_t *event) {
	return event->mask;
}

EVENTS_INLINE bool inotify_added(inotify_t *event) {
	return (event->mask & (IN_CREATE | IN_MOVED_TO));
}

EVENTS_INLINE bool inotify_removed(inotify_t *event) {
	return (event->mask & (IN_DELETE | IN_MOVED_FROM));
}

EVENTS_INLINE bool inotify_modified(inotify_t *event) {
	return (event->mask & IN_MODIFY);
}

EVENTS_INLINE char *inotify_name(inotify_t *event) {
	return event->name;
}

EVENTS_INLINE uint32_t inotify_length(inotify_t *event) {
	return (event == null || !is_ptr_usable(event)) ? 0 : event->len;
}

EVENTS_INLINE inotify_t *inotify_next(inotify_t *event) {
	int i;
	for (i = 0; i < ioTableSize; ++i) {
		if (fdTable[i].type == FD_MONITOR_SYNC && fdTable[i].buf == (char *)event) {
			char *buf = fdTable[i].buf;
			size_t numRead = fdTable[i].process->rid;
			event += sizeof(inotify_t) + event->len;
			return ((char *)event < buf + numRead) ? event : NULL;
		}
	}

	return null;
}

void inotify_handler(int fd, inotify_t *event, watch_cb handler, void *filter) {
	char subpath[PATH_MAX] = nil, buffer[Kb(8)] = nil;
	int len = read(fd, buffer, sizeof(buffer));
	if (len < 0)
		return;

	char *p = buffer;
	while (p < buffer + len) {
		events_monitors action = WATCH_INVALID;
		int mask = (WATCH_MODIFIED | WATCH_REMOVED | WATCH_ADDED | WATCH_MOVED);
		inotify_t *evt = (inotify_t *)p;
		if (evt->len) {
			if (evt->mask & (IN_CREATE))
				action = WATCH_ADDED;
			else if (evt->mask & (IN_DELETE | IN_DELETE_SELF))
				action = WATCH_REMOVED;
			else if (evt->mask & (IN_MOVE | IN_MOVE_SELF))
				action = WATCH_MOVED;
			else if (evt->mask & (IN_MODIFY | IN_ATTRIB))
				action = WATCH_MODIFIED;

			if (action) {
				if (!fdTable[evt->wd].changes)
					snprintf(subpath, PATH_MAX, "%s%s%s", fdTable[evt->wd].path, SYS_DIRSEP, evt->name);

				handler(evt->wd, action | ~mask, (const char *)(fdTable[evt->wd].changes ? evt->name : subpath), filter);
			}
		}
		p += sizeof(inotify_t) + evt->len;
	}
}

EVENTS_INLINE int __inotify_init(void) {
	events_init(256);
	int realfd = inotify_init();
	if (realfd == -1)
		return realfd;

	return events_new_fd(FD_MONITOR_ASYNC, realfd, realfd);
}

EVENTS_INLINE int __inotify_init1(int flags) {
	events_init(256);
	int realfd = inotify_init1(flags);
	if (realfd == -1)
		return realfd;

	return events_new_fd(FD_MONITOR_ASYNC, realfd, realfd);
}

int inotify_del_monitor(int wd) {
	if (fdTable[wd].type == FD_MONITOR_SYNC) {
		__inotify_rm_watch(fdTable[wd]._fd, wd);
		if ($size(fdTable[fdTable[wd]._fd].inotify_wd) == 0)
			return events_del(fdTable[wd]._fd);

		return 0;
	}

	return TASK_ERRED;
}

int inotify_close(int fd) {
	if (events_valid_fd(fd)) {
		foreach(watch in fdTable[fd].inotify_wd) {
			events_free_fd(watch.integer);
			fdTable[watch.integer].type = FD_UNUSED;
			fdTable[watch.integer].fd = TASK_ERRED;
			$remove(fdTable[fd].inotify_wd, iwatch);
		}

		os_close(fd);
		return 0;
	}

	return TASK_ERRED;
}

static void inotify_recursive(int fd, const char *path, uint32_t mask) {
	DIR *dir;				/* dir structure we are reading */
	struct dirent *entry;	/* directory entry currently being processed */
	char subpath[NAME_MAX];	/* buffer for building complete subdir and file names */

	dir = opendir(path);
	if (NULL == dir)
		return;

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR) {
			if (str_is("..", entry->d_name) || str_is(".", entry->d_name)) {
				continue;
			} else if (snprintf(subpath, NAME_MAX, "%s%s%s", path, SYS_DIRSEP, entry->d_name)) {
				int wd = inotify_add_watch(events_get_fd(fd), subpath, mask);
				if (wd == -1)
					continue;

				int pseudo = events_new_fd(FD_MONITOR_SYNC, wd, wd);
				$append_signed(fdTable[fd].inotify_wd, pseudo);
				fdTable[pseudo]._fd = fd;
				fdTable[pseudo].path = str_dup_ex(subpath);
				inotify_recursive(fd, (const char *)subpath, mask);
			}
		}
	}

	closedir(dir);
}

static EVENTS_INLINE void *_inotify_recursive(param_t args) {
	inotify_recursive(args[0].integer, args[1].const_char_ptr, args[2].u_int);
	return 0;
}

int __inotify_add_watch(int fd, const char *name, uint32_t mask) {
	int wd = inotify_add_watch(events_get_fd(fd), name, (atomic_load(&sys_event.num_loops) > 0 ? IN_ONLYDIR | mask : mask));
	if (wd == -1)
		return wd;

	int pseudo = events_new_fd(FD_MONITOR_SYNC, wd, wd);
	if (atomic_load(&sys_event.num_loops) > 0) {
		if (fdTable[fd].inotify_wd == NULL)
			fdTable[fd].inotify_wd = array();

		$append_signed(fdTable[fd].inotify_wd, pseudo);
		fdTable[pseudo]._fd = fd;
		fdTable[pseudo].changes = 1;
		fdTable[pseudo].path = str_dup_ex(name);
		await_for(queue_work(events_pool(), _inotify_recursive, 3, casting(fd), fdTable[pseudo].path, casting(mask)));
	}

	return pseudo;
}

EVENTS_INLINE int __inotify_rm_watch(int fd, int wd) {
	if (wd < 0)
		return inotify_close(fd);

	int realFd = events_get_fd(fd), realWd = events_get_fd(wd);
	if (atomic_load(&sys_event.num_loops) > 0 && events_valid_fd(wd)) {
		foreach(watch in fdTable[fd].inotify_wd) {
			if (watch.integer == wd) {
				$remove(fdTable[fd].inotify_wd, iwatch);
				break;
			}
		}
	}

	if (events_valid_fd(wd)) {
		events_free_fd(wd);
		fdTable[wd].type = FD_UNUSED;
		fdTable[wd].fd = TASK_ERRED;
	}

	return inotify_rm_watch(realFd, realWd);
}
#endif

#endif /* UNIX ONLY */