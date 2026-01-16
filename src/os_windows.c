#include "events_internal.h"

#undef read
#undef write
#undef close
#undef open
#undef connect

#if defined(_WIN32) || defined(_WIN64) /* WINDOWS ONLY */
static CRITICAL_SECTION events_siglock;
static volatile sig_atomic_t signal_running = false;
volatile sig_atomic_t events_got_signal = 0;

#define events_sigblock		EnterCriticalSection(&events_siglock)
#define events_sigunblock	LeaveCriticalSection(&events_siglock)

static HANDLE hIoCompPort = INVALID_HANDLE_VALUE;
static int ioTableSize = 256;

/**
 * An enumeration of the file types
 * supported by the FD_TABLE structure.
 *
 * NOTE: Not all currently supported.
 * This allows for future functionality.
 */
typedef union {
	HANDLE fileHandle;
	SOCKET sock;
	uint32_t value;
} DESCRIPTOR;

struct OVERLAPPED_REQUEST {
	OVERLAPPED overlapped;
	unsigned long instance;	/* file instance (won't match after a close) */
	os_cb proc;	/* callback routine */
	void *data;	/* callback argument */
	char *buf;	/* additional data */
	size_t length;	/* additional data length */
};

/*
 * Structure used to map file handle and socket handle
 * values into values that can be used to create unix-like
 * select bitmaps, read/write for both sockets/files.
 */
struct FD_TABLE {
	DESCRIPTOR fid;
	FILE_TYPE type;
	char *path; 		/* mkfifo path or cached filename */
	char *buffer;
	DWORD length;
	DWORD Errno;
	unsigned long instance;
	int status;
	int flags;
	intptr_t offset;			/* only valid for async file writes */
	array_t inotify;	/* for watched directory handles */
	LPDWORD offsetHighPtr;	/* pointers to offset high and low words */
	LPDWORD offsetLowPtr;	/* only valid for async file writes (logs) */
	struct OVERLAPPED_REQUEST ovList[1];	/* List of associated OVERLAPPED_REQUESTs */
	execinfo_t process[1];
};

static struct FD_TABLE *fdTable = NULL;
static CRITICAL_SECTION fdTableCritical;
static int stdioFd = 0;
static FILE_TYPE listenType = FD_UNUSED;

// This should be a DESCRIPTOR
static HANDLE hListen = INVALID_HANDLE_VALUE;
static HANDLE psHandle = INVALID_HANDLE_VALUE;
static BOOLEAN os_initialized = false;
static sys_signal_t events_sig[max_event_sig] = {0};

sys_events_t sys_event;

static EVENTS_INLINE void events_signal_set(void) {
	events_sigblock;
	atomic_flag_test_and_set(&sys_event.loop_signaled);
	events_sigunblock;
}

static EVENTS_INLINE void events_signal_clear(void) {
	events_sigblock;
	atomic_flag_clear(&sys_event.loop_signaled);
	events_sigunblock;
}

static void grow_ioTable(void) {
	int oldTableSize = ioTableSize;

	ioTableSize = ioTableSize * 2;
	fdTable = (struct FD_TABLE *)events_realloc(fdTable, ioTableSize * sizeof(struct FD_TABLE));
	if (fdTable == NULL) {
		errno = ENOMEM;
		return;
	}

	memset((char *)&fdTable[oldTableSize], 0,
		oldTableSize * sizeof(struct FD_TABLE));
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

static void clear_pseudo_events(void) {
	int i;
	EnterCriticalSection(&fdTableCritical);
	for (i = 0; i < ioTableSize; ++i) {
		if (fdTable[i].type != FD_UNUSED) {
			fdTable[i].status = -1;
			PostQueuedCompletionStatus(hIoCompPort, -1, i, &fdTable[i].ovList->overlapped);
			if (fdTable[i].inotify != NULL) {
				foreach(watch in fdTable[i].inotify) {
					os_close(watch.integer);
				}
				$delete(fdTable[i].inotify);
				fdTable[i].inotify = NULL;
			}
			fdTable[i].type = FD_UNUSED;
		}
	}
	LeaveCriticalSection(&fdTableCritical);
}

EVENTS_INLINE bool events_valid_fd(int pseudo) {
	return (pseudo >= 0) && (pseudo < ioTableSize) ? fdTable[pseudo].type != FD_UNUSED : false;
}

bool events_assign_fd(filefd_t handle, int pseudo) {
	if (pseudo == -1
		|| !CreateIoCompletionPort(handle, hIoCompPort, pseudo, 0)) {
		errno = GetLastError();
		perror("events_assign_fd");
		if (pseudo != -1)
			events_free_fd(pseudo);

		CloseHandle(handle);
		return false;
	}

	return true;
}

EVENTS_INLINE uint32_t events_get_fd(int pseudo) {
	return events_valid_fd(pseudo) ? fdTable[pseudo].fid.value : pseudo;
}

int events_new_fd(FILE_TYPE type, int fd, int desiredFd) {
	int index = -1;
	events_fd_t *target = events_target(fd);
	EnterCriticalSection(&fdTableCritical);
	while (target->loop && target->loop->active_descriptors >= ioTableSize)
		grow_ioTable();

	/*
	 * If desiredFd is set, try to get this entry (this is used for
	 * mapping stdio handles). Otherwise try to get the fd entry.
	 * If this is not available, find a the first empty slot.  .
	 */
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
		fdTable[index].fid.value = fd;
		fdTable[index].type = type;
		fdTable[index].path = NULL;
		fdTable[index].buffer = NULL;
		fdTable[index].Errno = NO_ERROR;
		fdTable[index].status = 0;
		fdTable[index].flags = 0;
		fdTable[index].offset = DATA_INVALID;
		fdTable[index].offsetHighPtr = fdTable[index].offsetLowPtr = NULL;
		fdTable[index].inotify = NULL;
		fdTable[index].ovList->overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
		fdTable[index].ovList->length = 0;
		fdTable[index].process->fd = TASK_ERRED;
		fdTable[index].process->env = NULL;
		fdTable[index].process->req = NULL;
		fdTable[index].process->detached = false;
		fdTable[index].process->is_spawn = false;
		fdTable[index].process->write_input[0] = inherit;
		fdTable[index].process->write_input[1] = inherit;
		fdTable[index].process->read_output[0] = inherit;
		fdTable[index].process->read_output[1] = inherit;
		fdTable[index].process->error = inherit;
		fdTable[index].process->context = NULL;
		fdTable[index].process->ps = INVALID_HANDLE_VALUE;
		if (type == FD_MONITOR_ASYNC)
			fdTable[index].inotify = array();
	}

	LeaveCriticalSection(&fdTableCritical);
	if (index == -1)
		errno = EINVAL;

	return index;
}

void events_free_fd(int pseudo) {
	/* Catch it if fd is a bogus value */
	assert((pseudo >= 0) && (pseudo < ioTableSize));

	EnterCriticalSection(&fdTableCritical);
	if (fdTable[pseudo].type != FD_UNUSED) {
		switch (fdTable[pseudo].type) {
			case FD_FILE_SYNC:
			case FD_FILE_ASYNC:
			case FD_PIPE_ASYNC:
			case FD_MONITOR_SYNC:
				if (fdTable[pseudo].path != NULL)
					events_free(fdTable[pseudo].path);
				fdTable[pseudo].path = NULL;
				break;
			case FD_PIPE_SYNC:
			case FD_MONITOR_ASYNC:
			case FD_PROCESS_ASYNC:
				if (fdTable[pseudo].buffer != NULL)
					events_free(fdTable[pseudo].buffer);
				fdTable[pseudo].buffer = NULL;
				break;
			default:
				break;
		}

		assert(fdTable[pseudo].path == NULL);
		assert(fdTable[pseudo].buffer == NULL);
		fdTable[pseudo].type = FD_UNUSED;
		fdTable[pseudo].Errno = NO_ERROR;
		fdTable[pseudo].offsetHighPtr = fdTable[pseudo].offsetLowPtr = NULL;
	}

	LeaveCriticalSection(&fdTableCritical);
}

int os_init(void) {
	if (os_initialized)
		return 0;

	fdTable = (struct FD_TABLE *)events_calloc((size_t)ioTableSize, sizeof(struct FD_TABLE));
	if (fdTable == NULL) {
		errno = ENOMEM;
		return -1;
	}

	InitializeCriticalSection(&fdTableCritical);
	InitializeCriticalSection(&events_siglock);

	/*
	 * Create the I/O completion port to be used for our I/O queue.
	 */
	if (hIoCompPort == INVALID_HANDLE_VALUE) {
		hIoCompPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (hIoCompPort == INVALID_HANDLE_VALUE) {
			perror("os_init! CreateIoCompletionPort");
			os_shutdown();
			return -1;
		}
	}

	os_initialized = true;
	return 0;
}

void os_shutdown(void) {
	if (!os_initialized)
		return;

	clear_pseudo_events();
	if (hIoCompPort != INVALID_HANDLE_VALUE) {
		CloseHandle(hIoCompPort);
		hIoCompPort = INVALID_HANDLE_VALUE;
	}

	if (hListen != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(hListen);
		CancelIo(hListen);
	}

	events_free(fdTable);
	DeleteCriticalSection(&fdTableCritical);
	DeleteCriticalSection(&events_siglock);
	os_initialized = false;
}

EVENTS_INLINE int is_socket(int fd) {
	if (fd < 3)
		return 0;
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents((SOCKET)fd, NULL, &events) == 0);
}

EVENTS_INLINE int os_connect(fds_t s, const struct sockaddr *name, int namelen) {
	if (sys_event.num_loops == 0 || !events_valid_fd(s))
		return connect(s, name, namelen);

	return os_accept_pipe(s);
}

int os_read(int fd, char *buf, size_t len) {
	int pseudofd, ret = TASK_ERRED;
	DWORD bytesRead;
	if (sys_event.num_loops == 0 || fdTable[fd].type == FD_UNUSED || is_socket(fd)) {
		if (is_socket(fd)) {
			if ((ret = recv(fd, buf, len, 0)) == SOCKET_ERROR)
				os_geterror();
			return ret;
		}

		if (!events_valid_fd(fd))
			return _read(fd, buf, len);
	}

	assert((fd >= 0) && (fd < ioTableSize));
	switch (fdTable[fd].type) {
		case FD_MONITOR_ASYNC:
			pseudofd = fdTable[fd].instance;
			if (ReadDirectoryChangesW(fdTable[pseudofd].fid.fileHandle, buf, len, true, fdTable[pseudofd].flags, &bytesRead, NULL, NULL))
				ret = bytesRead;
			else
				fdTable[fd].Errno = GetLastError();

			if (ret != TASK_ERRED) {
				if (fdTable[pseudofd].path == null) {
					fdTable[pseudofd].path = events_calloc(1, (ARRAY_SIZE * 2) + 1);
					fdTable[pseudofd].length = ARRAY_SIZE * 2;
				}

				fdTable[pseudofd].process->buffer = buf;
				fdTable[pseudofd].process->rid = ret;
			}
			break;
		case FD_FILE_SYNC:
		case FD_FILE_ASYNC:
		case FD_PIPE_SYNC:
		case FD_PIPE_ASYNC:
			if (ReadFile(fdTable[fd].fid.fileHandle, buf, len, &bytesRead, NULL))
				ret = bytesRead;
			else
				fdTable[fd].Errno = GetLastError();
			break;
		default:
			assert(0);
	}

	return ret;
}

int os_write(int fd, char *buf, size_t len) {
	int ret = -1;
	DWORD bytesWritten;
	if (sys_event.num_loops == 0 || fdTable[fd].type == FD_UNUSED || is_socket(fd)) {
		if (is_socket(fd)) {
			if ((ret = send(fd, buf, len, 0)) == SOCKET_ERROR)
				os_geterror();
			return ret;
		}
		return _write(fd, buf, len);
	}

	assert(fd >= 0 && fd < ioTableSize);
	switch (fdTable[fd].type) {
		case FD_FILE_SYNC:
		case FD_FILE_ASYNC:
		case FD_PIPE_SYNC:
		case FD_PIPE_ASYNC:
			if (WriteFile(fdTable[fd].fid.fileHandle, buf, len, &bytesWritten, NULL)) {
				ret = bytesWritten;
			} else {
				fdTable[fd].Errno = GetLastError();
			}
			break;
		default:
			assert(0);
	}

	return ret;
}

int os_close(int fd) {
	int ret = 0;
	if (fd == -1) return 0;

	if (sys_event.num_loops == 0 || !events_valid_fd(fd)) {
		if (is_socket(fd)) {
			if ((ret = closesocket(fd)) == SOCKET_ERROR)
				os_geterror();
			return ret;
		}

		if (!events_valid_fd(fd))
			return _close(fd);
	}

	/*
	 * Catch it if fd is a bogus value
	 */
	assert((fd >= 0) && (fd < ioTableSize));
	switch (fdTable[fd].type) {
		case FD_PIPE_ASYNC:
			/*
			* Make sure that the client (ie. a Web Server in this case) has
			* read all data from the pipe before we disconnect.
			*/
			if (!FlushFileBuffers(fdTable[fd].fid.fileHandle)) return -1;
			if (!DisconnectNamedPipe(fdTable[fd].fid.fileHandle)) return -1;
		case FD_PIPE_SYNC:
		case FD_FILE_SYNC:
		case FD_FILE_ASYNC:
		case FD_PROCESS_ASYNC:
		case FD_MONITOR_ASYNC:
		case FD_MONITOR_SYNC:
			CloseHandle(fdTable[fd].fid.fileHandle);
			break;
		default:
			ret = -1;		/* fake failure */
	}

	events_free_fd(fd);
	return ret;
}

static void *inotify_task(param_t args) {
	int fd = args[0].integer, inotifyfd = fdTable[fd].offset;
	events_t *loop = (events_t *)args[3].object;

	inotify_handler(fd, (inotify_t *)args[1].object, (watch_cb)args[2].func);
	if (events_is_registered(loop, fd)) {
		ReadDirectoryChangesW(fdTable[fd].fid.fileHandle,
			fdTable[inotifyfd].buffer,
			fdTable[inotifyfd].length,
			true,
			fdTable[fd].flags,
			NULL,
			&fdTable[fd].ovList->overlapped,
			NULL);
	}

	return 0;
}

int os_iodispatch(int ms) {
	size_t fd;
	unsigned long bytes;
	POVERLAPPED_REQUEST pOv;
	int err;

	/*
	 * We can loop in here, but not too long, as wait handlers
	 * must run, so don't wait the full timeout.
	 */
	while (ms >= 0) {
		if (!GetQueuedCompletionStatus(hIoCompPort, &bytes, &fd, (LPOVERLAPPED *)&pOv, ms) && !pOv) {
			err = WSAGetLastError();
			return 0; /* timeout */
		}

		assert((fd >= 0) && (fd < ioTableSize));

		/* still valid */
		if (pOv) {
			if (atomic_flag_load_explicit(&sys_event.loop_signaled, memory_order_relaxed)) {
				events_signal_clear();
				return 0;
			}

			events_fd_t *target = events_target((fdTable[fd].type == FD_FILE_ASYNC ? fdTable[fd].fid.value : fd));
			int revents = (target->events & EVENTS_READ ? EVENTS_READ : 0)
				| (target->events & EVENTS_WRITE ? EVENTS_WRITE : 0)
				| (target->events & EVENTS_CLOSED ? EVENTS_CLOSED : 0);

			switch (fdTable[fd].type) {
				case FD_FILE_ASYNC:
					(pOv->proc)((intptr_t)fdTable[fd].fid.value, bytes, pOv->data);
					break;
				case FD_PIPE_SYNC:
				case FD_PROCESS_ASYNC:
					(target->callback)((intptr_t)fdTable[fd].fid.value, bytes, pOv->data);
					break;
				case FD_MONITOR_ASYNC:
				case FD_MONITOR_SYNC:
					//inotify_handler((int)fd, (inotify_t *)fdTable[fdTable[fd].offset].buffer, (watch_cb)target->callback, target->loop);
					async_task(inotify_task, 4, casting(fd), fdTable[fdTable[fd].offset].buffer, target->callback, target->loop);
					break;
				default:
					if (revents != 0 && !target->is_pathwatcher && target->is_iodispatch && target->loop_id != 0)
						(target->callback)((target->backend_used ? fdTable[fd].fid.value : fd), revents, target->cb_arg);
					break;
			}

			if (fdTable[fd].type == FD_PIPE_ASYNC) {
				DisconnectNamedPipe((HANDLE)target->_backend);
				os_accept_pipe(fd);
			}
		}

		fd = 0;
	}

	return 0;
}

static int os_accept_pipe(int fd) {
	int ipcFd = -1;
	if (!ConnectNamedPipe(fdTable[fd].fid.fileHandle, (sys_event.num_loops > 0 ? (LPOVERLAPPED)fdTable[fd].ovList : NULL))) {
		switch (GetLastError()) {
			case ERROR_PIPE_CONNECTED:
				// A client connected after CreateNamedPipe but
				// before ConnectNamedPipe. Its a good connection.
			case ERROR_IO_PENDING:
				// The NamedPipe was opened with an Overlapped structure
				// and there is a pending io operation.
			case ERROR_PIPE_LISTENING:
				// The pipe handle is in nonblocking mode.
				break;
			case ERROR_NO_DATA:
				// The previous client closed its handle (and we failed
				// to call DisconnectNamedPipe)
			default:
				perror("ConnectNamedPipe");
				return -1;
		}
	}

	ipcFd = events_new_fd(FD_PIPE_ASYNC, (intptr_t)fdTable[fd].fid.fileHandle, -1);
	if (ipcFd == -1) {
		DisconnectNamedPipe(fdTable[fd].fid.fileHandle);
	}

	return ipcFd;
}

int os_create_pipe(LPCSTR lpName, HANDLE *outRead, HANDLE *outWrite) {
	char io_outin[260] = {0};
	snprintf(io_outin, sizeof(io_outin), "%s%s-%d", SYS_PIPE, lpName, getpid());
	// Create the named pipe. This will return the handle we use for reading from the pipe.
	HANDLE read = CreateNamedPipeA(
		io_outin, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, Kb(64), Kb(64), NMPWAIT_USE_DEFAULT_WAIT, NULL);

	if (read == INVALID_HANDLE_VALUE) {
		errno = GetLastError();
		return -1;
	}

	// Now create a handle for the other end of the pipe. We are going to pass that handle to the
	// process we are creating, so we need to specify that the handle can be inherited.
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	HANDLE write = CreateFileA(io_outin, GENERIC_WRITE | FILE_FLAG_OVERLAPPED, 0, &saAttr, OPEN_EXISTING, 0, 0);
	if (write == INVALID_HANDLE_VALUE) {
		errno = GetLastError();
		CloseHandle(read);
		return -1;
	}

	*outRead = read;
	*outWrite = write;
	return 0;
}

int os_mkfifo(const char *name, mode_t mode) {
	events_init(256);
	HANDLE pipeHandle;
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true}; // true: allow handles to be inherited
	const char *piped = "%s%s";
	int fake;

	snprintf(sys_event.pNamed, sizeof(sys_event.pNamed), piped, SYS_PIPE, name);
	pipeHandle = CreateNamedPipeA((LPCSTR)sys_event.pNamed,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, Kb(64), Kb(64), NMPWAIT_USE_DEFAULT_WAIT, &sa);

	if (pipeHandle != INVALID_HANDLE_VALUE) {
		sys_event.listenType = FD_PIPE_ASYNC;
		sys_event.pHandle = pipeHandle;
		if ((fake = events_new_fd(FD_PIPE_ASYNC, (intptr_t)hIoCompPort, -1)) != -1) {
			fdTable[fake].path = str_dup_ex(sys_event.pNamed);
			fdTable[fake].fid.fileHandle = sys_event.pHandle;
			return 0;
		}
	}

	errno = GetLastError();
	return -1;
}

static int _os_open(const char *path, int mode, int shared) {
	int fd, osmode = 0;
	int type_mode = FD_FILE_ASYNC;
	int creation_mode = OPEN_EXISTING;
	int file_mode = FILE_ATTRIBUTE_NORMAL;
	int share_mode = shared ? FILE_SHARE_READ | FILE_SHARE_WRITE: 0;
	SECURITY_ATTRIBUTES sec = {0};
	sec.nLength = sizeof sec;
	if (mode & O_RDONLY || mode & O_RDWR)
		osmode |= GENERIC_READ;

	if (mode & O_WRONLY || mode & O_RDWR)
		osmode |= GENERIC_WRITE;

	if (mode & O_CREAT)
		creation_mode = CREATE_ALWAYS;

	if (mode & O_EXCL)
		creation_mode = CREATE_NEW;

	if (mode & O_TRUNC)
		creation_mode |= TRUNCATE_EXISTING;

	if (mode & O_DIRECTORY) {
		osmode |= FILE_LIST_DIRECTORY;
		file_mode |= FILE_FLAG_BACKUP_SEMANTICS;
	}

	if (mode & O_ASYNC || share_mode || mode & O_DIRECTORY)
		osmode |= FILE_FLAG_OVERLAPPED;

	if (share_mode)
		file_mode |= SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;

	HANDLE h = CreateFileA(path, osmode, share_mode, &sec, creation_mode, file_mode, NULL);
	if (share_mode)
		type_mode = FD_PIPE_ASYNC;

	fd = events_new_fd((FILE_TYPE)type_mode, (intptr_t)h, -1);
	return events_assign_fd(h, fd) ? fd : -1;
}

int os_open(const char *path, ...) {
	va_list ap;
	int fake, pipe, flags, mode = 0, ipc = str_has(path, SYS_PIPE_PRE);

	if ((fake = events_pseudo_fd(path)) != -1) {
		if (fdTable[fake].type == FD_PIPE_ASYNC) {
			pipe = os_accept_pipe(fake);
			return events_assign_fd(fdTable[fake].fid.fileHandle, pipe) ? pipe : -1;
		}
	}

	va_start(ap, path);
	flags = va_arg(ap, int);
	if (flags & O_CREAT)
		mode = va_arg(ap, int);
	va_end(ap);

	if (ipc || flags & O_ASYNC || flags & O_DIRECTORY)
		return _os_open(path, flags, ipc);

	flags |= O_BINARY;
	if (flags & O_CLOEXEC) {
		flags &= ~O_CLOEXEC;
		flags |= O_NOINHERIT;
	}

	flags &= ~O_NONBLOCK;
	return _open(path, flags, mode);
}

/** Start a new process with the specified command line */
static process_t os_exec_child(const char *filename, char *cmd, execinfo_t *i) {
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION info = {0};
	BOOL is_spawn = i->is_spawn, inherit_handles = 0;

	si.cb = sizeof(STARTUPINFO);
	if (!i->detached) {
		si.wShowWindow = SW_HIDE;
		if (i->write_input[1] != INVALID_HANDLE_VALUE || i->read_output[1] != INVALID_HANDLE_VALUE || i->error != INVALID_HANDLE_VALUE) {
			si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
			si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
			si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
			si.dwFlags |= STARTF_USESTDHANDLES;
			inherit_handles = 1;
		}

		if (i->write_input[(is_spawn ? 0 : 1)] != inherit) {
			si.hStdInput = i->write_input[(is_spawn ? 0 : 1)];
			SetHandleInformation(i->write_input[(is_spawn ? 0 : 1)], HANDLE_FLAG_INHERIT, 1);
		}

		if (i->read_output[1] != inherit) {
			si.hStdOutput = i->read_output[1];
			SetHandleInformation(i->read_output[1], HANDLE_FLAG_INHERIT, 1);
		}

		if (i->error != inherit) {
			si.hStdError = i->error;
			SetHandleInformation(i->error, HANDLE_FLAG_INHERIT, 1);
		}
	}

	BOOL b = CreateProcessA(filename, cmd, NULL, NULL, inherit_handles, i->detached ? DETACHED_PROCESS : 0,
		/*env*/ i->env,
		/*startup dir*/ NULL,
		&si,
		&info);

	if (!b) {
		errno = GetLastError();
		return INVALID_HANDLE_VALUE;
	}

	if (is_spawn && i->io_func) {
		CloseHandle(i->write_input[0]);
		CloseHandle(i->read_output[1]);
		fdTable[i->fd].buffer = events_calloc(1, Kb(64) + 1);
		fdTable[i->fd].ovList->length = Kb(64);
		fdTable[i->fd].ovList->data = i;
		fdTable[i->fd].ovList->buf = fdTable[i->fd].buffer;
		fdTable[i->fd].fid.fileHandle = i->read_output[0];
		i->req = fdTable[i->fd].ovList;
	}

	CloseHandle(info.hThread);
	return info.hProcess;
}

static EVENTS_INLINE process_t os_exec_info(const char *filename, execinfo_t *info) {
	process_t ps = os_exec_child(filename, info->argv, info);
	if(info->argv != NULL)
		events_free(info->argv);
	if(info->env != NULL)
		events_free(info->env);

	if (ps == INVALID_HANDLE_VALUE)
		return OS_NULL;

	info->ps = ps;
	fdTable[info->fd].fid.fileHandle = ps;
	return (process_t)info->fd;
}

EVENTS_INLINE execinfo_t *exec_info(const char *env, bool is_datached,
	filefd_t io_in, filefd_t io_out, filefd_t io_err) {
	int pseudofd = events_new_fd(FD_PROCESS_ASYNC, (intptr_t)hIoCompPort, -1);
	execinfo_t *info = fdTable[pseudofd].process;

	info->detached = is_datached;
	if (env != NULL && str_has(env, "=") && str_has(env, ";"))
		info->env = (const char **)str_slice(env, ";", NULL);

	if (io_in != inherit)
		info->write_input[1] = io_in;

	if (io_out != inherit)
		info->read_output[1] = io_out;

	if (io_err != inherit)
		info->error = io_err;

	info->fd = pseudofd;
	return info;
}

EVENTS_INLINE process_t exec(const char *command, const char *args, execinfo_t *info) {
	char *cmd_arg = str_cat((args == NULL ? 2 : 3), command, ",", args);
	if (info == NULL)
		info = exec_info(NULL, false, inherit, inherit, inherit);

	info->argv = str_has(cmd_arg, ",") ? str_swap(cmd_arg, ",", " ") : cmd_arg;
	events_free(cmd_arg);

	return os_exec_info(command, info);
}

int exec_wait(process_t ps, uint32_t timeout_ms, int *exit_code) {
	process_t pid = fdTable[(uintptr_t)ps].process->ps;
	if (fdTable[(uintptr_t)ps].process->detached)
		return 0;

	int r = WaitForSingleObject(pid, timeout_ms);
	if (r == WAIT_OBJECT_0) {
		if (exit_code != NULL)
			GetExitCodeProcess(pid, (DWORD *)exit_code);
		CloseHandle(pid);
		r = 0;
	} else if (r == WAIT_TIMEOUT) {
		SetLastError(WSAETIMEDOUT);
	}

	return r;
}

DWORD __stdcall spawn_io_thread(void *arg) {
	DWORD dwRead;
	execinfo_t *info = (execinfo_t *)arg;
	POVERLAPPED_REQUEST pOv = info->req;
	BOOL bSuccess = FALSE;

	for (;;) {
		bSuccess = ReadFile(info->read_output[0], pOv->buf, pOv->length, &dwRead, NULL);
		if (!bSuccess)
			break;

		if (dwRead == 0)
			continue;

		pOv->buf[dwRead] = '\0';
		info->buffer = pOv->buf;
		PostQueuedCompletionStatus(hIoCompPort, dwRead, (uintptr_t)info->fd, (LPOVERLAPPED)pOv);
	}

	return 0;
}

static void events_sig_handler(int sig) {
	events_signal_set();
	if (signal_running)
		exit(1);

	signal_running = true;
	int i;

	events_sigblock;
	events_got_signal++;
	/*
	 * Make signal handlers persistent.
	 */
	if (signal(sig, events_sig_handler) == SIG_ERR) {
		fprintf(stderr, "Cannot reinstall handler for signal (%d)\n", sig);
	}

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
		events_sig[i].data = NULL;
		events_sig[i].loop = NULL;
		events_sig[i].is_running = false;
		events_sig[i].sig = -1;
		if (signal(sig, SIG_DFL) == SIG_ERR)
			fprintf(stderr, "Cannot install handler for signal no %d\n", sig);
	}
}

EVENTS_INLINE sys_signal_t *events_signals(void) {
	return events_sig;
}

int events_add_signal(int sig, sig_cb proc, void *data) {
	int i;
	atomic_thread_fence(memory_order_seq_cst);
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
	if (signal(sig, events_sig_handler) == SIG_ERR) {
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

static int convert_wsa_error(int wsaerr) {
	switch (wsaerr) {
		case WSAEINTR:
			errno = EINTR;
			break;
		case WSAEBADF:
			errno = EBADF;
			break;
		case WSAEACCES:
			errno = EACCES;
			break;
		case WSAEFAULT:
			errno = EFAULT;
			break;
		case WSANOTINITIALISED:
			errno = EPERM;
			break;
		case WSAEMFILE:
			errno = EMFILE;
			break;
		case WSAEINPROGRESS:
			errno = EINPROGRESS;
			break;
		case WSAEALREADY:
			errno = EALREADY;
			break;
		case WSAENOTSOCK:
			errno = ENOTSOCK;
			break;
		case WSAEDESTADDRREQ:
			errno = EDESTADDRREQ;
			break;
		case WSAEMSGSIZE:
			errno = EMSGSIZE; //EFBIG;
			break;
		case WSAEPROTOTYPE:
			errno = EPROTOTYPE;
			break;
		case WSAENOPROTOOPT:
			errno = ENOPROTOOPT;
			break;
		case WSAEPROTONOSUPPORT:
			errno = EPROTONOSUPPORT;
			break;
		case WSAEOPNOTSUPP:
			errno = ENOTSUP;
			break;
		case WSAEAFNOSUPPORT:
			errno = EAFNOSUPPORT;
			break;
		case WSAEADDRINUSE:
			errno = EADDRINUSE;
			break;
		case WSAEADDRNOTAVAIL:
			errno = EADDRNOTAVAIL;
			break;
		case WSAENETDOWN:
			errno = ENETDOWN;
			break;
		case WSAENETUNREACH:
			errno = ENETUNREACH;
			break;
		case WSAENETRESET:
			errno = ENETRESET;
			break;
		case WSAECONNABORTED:
			errno = ECONNABORTED;
			break;
		case WSAECONNRESET:
			errno = ECONNRESET;
			break;
		case WSAENOBUFS:
			errno = ENOMEM;
			break;
		case WSAEISCONN:
			errno = EISCONN;
			break;
		case WSAENOTCONN:
			errno = ENOTCONN;
			break;
		case WSAESHUTDOWN:
			errno = ECONNRESET;
			break;
		case WSAETIMEDOUT:
			errno = ETIMEDOUT;
			break;
		case WSAECONNREFUSED:
			errno = ECONNREFUSED;
			break;
		case WSAELOOP:
			errno = ELOOP;
			break;
		case WSAENAMETOOLONG:
			errno = ENAMETOOLONG;
			break;
		case WSAEHOSTDOWN:
			errno = ENETDOWN;	/* EHOSTDOWN is not defined */
			break;
		case WSAEHOSTUNREACH:
			errno = EHOSTUNREACH; //EIO
			break;
		case WSAENOTEMPTY:
			errno = ENOTEMPTY;
			break;
		case WSAEPROCLIM:
		case WSAEUSERS:
		case WSAEDQUOT:
		case WSAEWOULDBLOCK:
			errno = EAGAIN;
			break;
		case WSAECANCELLED:
			errno = ECANCELED;
			break;
		case WSAEINVAL:
		default:
			errno = EINVAL;
			break;
	}

	return errno;
}

int socketpair(int domain, int type, int protocol, fds_t sockets[2]) {
	SOCKET listener = SOCKET_ERROR;
	struct sockaddr_in listener_addr;
	SOCKET connector = SOCKET_ERROR;
	struct sockaddr_in connector_addr;
	SOCKET acceptor = SOCKET_ERROR;
	int saved_errno;
	socklen_t addr_size;

	if (!sockets) {
		errno = EINVAL;
		return SOCKET_ERROR;
	}

	/* This must be WSASocket() and not socket(). The subtle difference is
	 * that only sockets created by WSASocket() can be used as standard
	 * file descriptors.
	 */
	listener = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listener < 0) {
		return SOCKET_ERROR;
	}

	memset(&listener_addr, 0, sizeof listener_addr);
	listener_addr.sin_family = AF_INET;
	listener_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listener_addr.sin_port = 0;  /* OS picks a random free port.  */

	errno = 0;
	if (bind(listener, (struct sockaddr *)&listener_addr,
		sizeof listener_addr) == -1) {
		goto fail_win32_socketpair;
	}

	if (listen(listener, 1) < 0) {
		goto fail_win32_socketpair;
	}

	connector = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (connector == -1) {
		goto fail_win32_socketpair;
	}

	/* Get the port number.  */
	addr_size = sizeof connector_addr;
	if (getsockname(listener, (struct sockaddr *)&connector_addr,
		&addr_size) < 0) {
		goto fail_win32_socketpair;
	}
	if (addr_size != sizeof connector_addr) {
		goto abort_win32_socketpair;
	}

	events_set_nonblocking(connector);
	if (connect(connector, (struct sockaddr *)&connector_addr,
		addr_size) < 0 && os_geterror() != EAGAIN) {
		goto fail_win32_socketpair;
	}

	acceptor = accept(listener, (struct sockaddr *)&listener_addr, &addr_size);
	if (acceptor < 0) {
		goto fail_win32_socketpair;
	}
	if (addr_size != sizeof listener_addr) {
		goto abort_win32_socketpair;
	}

	closesocket(listener);

	/* The port and host on the socket must be identical.  */
	if (getsockname(connector, (struct sockaddr *)&connector_addr,
		&addr_size) < 0) {
		goto fail_win32_socketpair;
	}

	if (addr_size != sizeof connector_addr
		|| listener_addr.sin_family != connector_addr.sin_family
		|| listener_addr.sin_addr.s_addr != connector_addr.sin_addr.s_addr
		|| listener_addr.sin_port != connector_addr.sin_port) {
		goto abort_win32_socketpair;
	}

	events_set_nonblocking(acceptor);
	sockets[0] = connector;
	sockets[1] = acceptor;

	return 0;

abort_win32_socketpair:
	errno = ECONNABORTED; /* This would be the standard thing to do. */

fail_win32_socketpair:
	if (!errno) {
		errno = os_geterror();
	}

	saved_errno = errno;
	if (listener >= 0) {
		closesocket(listener);
	}
	if (connector >= 0) {
		closesocket(connector);
	}
	if (acceptor >= 0) {
		closesocket(acceptor);
	}
	errno = saved_errno;

	return SOCKET_ERROR;
}

#if defined(__TINYC__)
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
#elif defined(_WIN32_PLATFORM_X86)
static struct impl_tls_dtor_entry {
	tls_emulate_t key;
	emulate_dtor dtor;
} impl_emulate_dtorbl[EMULATED_THREADS_TSS_DTOR_SLOTS];

static int impl_tls_dtor_register(tls_emulate_t key, emulate_dtor dtor) {
	int i;
	for (i = 0; i < EMULATED_THREADS_TSS_DTOR_SLOTS; i++) {
		if (!impl_emulate_dtorbl[i].dtor)
			break;
	}

	if (i == EMULATED_THREADS_TSS_DTOR_SLOTS)
		return 1;

	impl_emulate_dtorbl[i].key = key;
	impl_emulate_dtorbl[i].dtor = dtor;

	return 0;
}

static void impl_tls_dtor_invoke() {
	int i;
	for (i = 0; i < EMULATED_THREADS_TSS_DTOR_SLOTS; i++) {
		if (impl_emulate_dtorbl[i].dtor) {
			void *val = os_tls_get(impl_emulate_dtorbl[i].key);
			if (val) {
				(impl_emulate_dtorbl[i].dtor)(val);
			}
		}
	}
}

int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor) {
	if (!key) return -1;

	*key = TlsAlloc();
	if (dtor) {
		if (impl_tls_dtor_register(*key, dtor)) {
			TlsFree(*key);
			return -1;
		}
	}

	return (*key != 0xFFFFFFFF) ? 0 : -1;
}

EVENTS_INLINE void os_tls_free(tls_emulate_t key) {
	TlsFree(key);
}

EVENTS_INLINE void *os_tls_get(tls_emulate_t key) {
	return TlsGetValue(key);
}

EVENTS_INLINE int os_tls_set(tls_emulate_t key, void *val) {
	return TlsSetValue(key, val) ? 0 : -1;
}
#else
EVENTS_INLINE int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor) {
	if (!key) return -1;

	*key = FlsAlloc(dtor);
	return (*key != 0xFFFFFFFF) ? 0 : -1;
}

EVENTS_INLINE void os_tls_free(tls_emulate_t key) {
	tls_emulate_t temp = key;
	if (key != 0) {
		key = 0;
		FlsFree(temp);
	}
}

EVENTS_INLINE void *os_tls_get(tls_emulate_t key) {
	return FlsGetValue(key);
}

EVENTS_INLINE int os_tls_set(tls_emulate_t key, void *val) {
	return FlsSetValue(key, val) ? 0 : -1;
}
#endif

EVENTS_INLINE os_thread_t os_create(os_thread_proc proc, void *param) {
	uintptr_t thrd = _beginthreadex(NULL, 0, (_beginthreadex_proc_type)proc, param, 0, NULL);
	return thrd == 0 ? OS_NULL : (os_thread_t)thrd;
}

EVENTS_INLINE int os_join(os_thread_t t, uint32_t timeout_ms, int *exit_code) {
	int r = WaitForSingleObject(t, timeout_ms);

	if (r == WAIT_OBJECT_0) {
		if (exit_code != OS_NULL)
			GetExitCodeThread(t, (DWORD *)exit_code);

		CloseHandle(t);
		return 0;

	} else if (r == WAIT_TIMEOUT) {
		errno = ETIMEDOUT;
		SetLastError(WSAETIMEDOUT);
	}

	return -1;
}

EVENTS_INLINE void os_exit(uint32_t exit_code) {
	_endthreadex(exit_code);
}

EVENTS_INLINE int os_detach(os_thread_t t) {
	return 0 == CloseHandle(t);
}

EVENTS_INLINE void os_cpumask_set(os_cpumask *mask, uint32_t i) {
	mask->value |= ((size_t)1 << i);
}

EVENTS_INLINE int os_affinity(os_thread_t t, const os_cpumask *mask) {
	return (0 == SetThreadAffinityMask(t, mask->value));
}

EVENTS_INLINE int os_sleep(uint32_t msec) {
	Sleep(msec);
	return 0;
}

EVENTS_INLINE uintptr_t os_self(void) {
	return (uintptr_t)((void *)NtCurrentTeb());
}

EVENTS_INLINE int os_geterror(void) {
	return convert_wsa_error(WSAGetLastError());
}

void os_perror(const char *s) {
	fprintf(stderr, "%s: %s\n", s, strerror(errno));
}

int os_rename(const char *oldpath, const char *newpath) {
	return MoveFileEx(oldpath, newpath, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}

ssize_t pwrite(int d, const void *buf, size_t nbytes, off_t offset) {
	off_t cpos, opos, rpos;
	ssize_t bytes;
	if ((cpos = lseek(d, 0, SEEK_CUR)) == -1)
		return -1;
	if ((opos = lseek(d, offset, SEEK_SET)) == -1)
		return -1;
	if ((bytes = os_write(d, (char *)buf, nbytes)) == -1)
		return -1;
	if ((rpos = lseek(d, cpos, SEEK_SET)) == -1)
		return -1;
	return bytes;
}

ssize_t pread(int d, void *buf, size_t nbytes, off_t offset) {
	off_t cpos, opos, rpos;
	ssize_t bytes;
	if ((cpos = lseek(d, 0, SEEK_CUR)) == -1)
		return -1;
	if ((opos = lseek(d, offset, SEEK_SET)) == -1)
		return -1;
	if ((bytes = os_read(d, (char *)buf, nbytes)) == -1)
		return -1;
	if ((rpos = lseek(d, cpos, SEEK_SET)) == -1)
		return -1;
	return bytes;
}

ssize_t sendfile(int fd_out, int fd_in, off_t *offset, size_t length) {
	const size_t max_buf_size = 65536;
	size_t buf_size = length < max_buf_size ? length : max_buf_size;
	ssize_t result = 0;
	int n;
	off_t result_offset = 0;
	char *buf = (char *)events_malloc(buf_size);
	if (!buf) {
		errno = ENOMEM;
		result = -1;
	} else {
		if (*offset != -1)
			result_offset = _lseeki64(fd_in, *offset, SEEK_SET);

		if (result_offset == -1) {
			result = -1;
		} else {
			while (length > 0) {
				n = _read(fd_in, buf, length < buf_size ? length : buf_size);
				if (n == 0) {
					break;
				} else if (n == -1) {
					result = -1;
					break;
				}

				length -= n;

				n = _write(fd_out, buf, n);
				if (n == -1) {
					result = -1;
					break;
				}

				result += n;
			}
		}
		*offset = result_offset;
		events_free(buf);
	}

	return result;
}

static int setfd(int fd, int flag) {
	int rc = -1;
	if (flag & FD_CLOEXEC) {
		HANDLE h = (HANDLE)_get_osfhandle(fd);
		if (h != NULL)
			rc = SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) == 0 ? -1 : 0;
	}
	return rc;
}

static int setfl(int fd, int flag) {
	int rc = -1;
	if (flag & O_NONBLOCK) {
		long mode = 1;
		rc = ioctlsocket(fd, FIONBIO, &mode);
	}
	return rc;
}

int os_pipe(int fildes[2]) {
	return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC, _2socket(fildes));
}

int pipe2(int fildes[2], int flags) {
	int rc = os_pipe(fildes);
	if (rc == 0) {
		if (flags & O_NONBLOCK) {
			rc |= setfl(fildes[0], O_NONBLOCK);
			rc |= setfl(fildes[1], O_NONBLOCK);
		}
		if (flags & O_CLOEXEC) {
			rc |= setfd(fildes[0], FD_CLOEXEC);
			rc |= setfd(fildes[1], FD_CLOEXEC);
		}
		if (rc != 0) {
			int e = errno;
			os_close(fildes[0]);
			os_close(fildes[1]);
			errno = e;
		}
	}
	return rc;
}

int getcontext(ucontext_t *ucp) {
	int ret;

	/* Retrieve the full machine context */
	ucp->uc_mcontext.ContextFlags = CONTEXT_FULL;
	ret = GetThreadContext(GetCurrentThread(), &ucp->uc_mcontext);

	return (ret == 0) ? -1 : 0;
}

int setcontext(const ucontext_t *ucp) {
	int ret;

	/* Restore the full machine context (already set) */
	ret = SetThreadContext(GetCurrentThread(), &ucp->uc_mcontext);
	return (ret == 0) ? -1 : 0;
}

int makecontext(ucontext_t *ucp, void (*func)(), int argc, ...) {
	int i;
	va_list ap;
	char *sp;

	/* Stack grows down */
	sp = (char *)(size_t)ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size;

	/* Reserve stack space for the arguments (maximum possible: argc*(8 bytes per argument)) */
	sp -= argc * 8;

	if (sp < (char *)ucp->uc_stack.ss_sp) {
		/* errno = ENOMEM;*/
		return -1;
	}

	/* Set the instruction and the stack pointer */
#if defined(_X86_)
	ucp->uc_mcontext.Eip = (unsigned long long)func;
	ucp->uc_mcontext.Esp = (unsigned long long)(sp - 4);
#else
	ucp->uc_mcontext.Rip = (unsigned long long)func;
	ucp->uc_mcontext.Rsp = (unsigned long long)(sp - 40);
#endif
	/* Save/Restore the full machine context */
	ucp->uc_mcontext.ContextFlags = CONTEXT_FULL;

	/* Copy the arguments */
	va_start(ap, argc);
	for (i = 0; i < argc; i++) {
		memcpy(sp, ap, 8);
		ap += 8;
		sp += 8;
	}
	va_end(ap);

	return 0;
}

int swapcontext(ucontext_t *oucp, const ucontext_t *ucp) {
	int ret;

	if (oucp == NULL || (void *)ucp == NULL) {
		/*errno = EINVAL;*/
		return -1;
	}

	ret = getcontext(oucp);
	if (ret == 0) {
		ret = setcontext(ucp);
	}
	return ret;
}

EVENTS_INLINE int inotify_init(void) {
	events_init(256);
	return events_new_fd(FD_MONITOR_ASYNC, (intptr_t)hIoCompPort, -1);
}

EVENTS_INLINE int inotify_init1(int flags) {
	(void)flags;
	return inotify_init();
}

EVENTS_INLINE uint32_t inotify_mask(inotify_t *event) {
	return (uint32_t)event->Action;
}

EVENTS_INLINE bool inotify_added(inotify_t *event) {
	return event->Action == FILE_ACTION_ADDED || event->Action == FILE_ACTION_RENAMED_NEW_NAME;
}

EVENTS_INLINE bool inotify_removed(inotify_t *event) {
	return event->Action == FILE_ACTION_REMOVED || event->Action == FILE_ACTION_RENAMED_OLD_NAME;
}

EVENTS_INLINE bool inotify_modified(inotify_t *event) {
	return event->Action == FILE_ACTION_MODIFIED;
}

EVENTS_INLINE char *inotify_name(inotify_t *event) {
	char *filename = null;
	int i;

	for (i = 0; i < ioTableSize; ++i) {
		if (fdTable[i].type == FD_MONITOR_SYNC && fdTable[i].process->buffer == (char *)event) {
			WideCharToMultiByte(CP_ACP,
				0,
				event->FileName,
				(event->FileNameLength / 2),
				fdTable[i].path,
				fdTable[i].length,
				NULL,
				NULL);
			filename = fdTable[i].path;
			break;
		}
	}
	return filename;
}

EVENTS_INLINE uint32_t inotify_length(inotify_t *event) {
	return (event == null || !is_ptr_usable(event)) ? 0 : (uint32_t)event->FileNameLength / 2;
}

EVENTS_INLINE inotify_t *inotify_next(inotify_t *event) {
	if (event->NextEntryOffset)
		return (FILE_NOTIFY_INFORMATION *)event + event->NextEntryOffset;

	return null;
}

void inotify_handler(int fd, inotify_t *event, watch_cb handler) {
	char filename[(ARRAY_SIZE * 2) + 1] = nil;
	events_monitors action = WATCH_INVALID;
	int mask = (WATCH_MODIFIED | WATCH_REMOVED | WATCH_ADDED | WATCH_MOVED);
	switch (event->Action) {
		case FILE_ACTION_ADDED:
			action = WATCH_ADDED;
			break;
		case FILE_ACTION_REMOVED:
			action = WATCH_REMOVED;
			break;
		case FILE_ACTION_MODIFIED:
			action = WATCH_MODIFIED;
			break;
		case FILE_ACTION_RENAMED_NEW_NAME:
		case FILE_ACTION_RENAMED_OLD_NAME:
			action = WATCH_MOVED;
			break;
	}

	if (action) {
		WideCharToMultiByte(CP_ACP,
			0,
			event->FileName,
			(event->FileNameLength / 2),
			filename,
			(ARRAY_SIZE * 2),
			NULL,
			NULL);
		handler(fd, action | ~mask, (const char *)filename);
	}
}

EVENTS_INLINE int inotify_wd(int pseudo) {
	return events_valid_fd(pseudo) && fdTable[pseudo].type == FD_MONITOR_ASYNC ? fdTable[pseudo].offset : pseudo;
}

int inotify_del_monitor(int wd) {
	return fdTable[wd].type == FD_MONITOR_SYNC ? inotify_rm_watch(fdTable[wd].offset, wd) : TASK_ERRED;
}

EVENTS_INLINE bool events_is_watching(int fd) {
	return is_data(fdTable[fd].inotify) && $size(fdTable[fd].inotify) > 0;
}

int inotify_add_watch(int fd, const char *name, uint32_t mask) {
	struct stat st;
	if ((sys_event.num_loops > 0 ? !fs_stat(name, &st) : !stat(name, &st)) && (st.st_mode & S_IFMT) == S_IFDIR) {
		// create a handle for a directory to look for
		HANDLE hDir = CreateFileA(name, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
		if (hDir != INVALID && sys_event.num_loops > 0) {
			int newfd = events_new_fd(FD_MONITOR_SYNC, (intptr_t)hDir, -1);
			if (fdTable[fd].buffer == NULL) {
				fdTable[fd].length = 4096;
				fdTable[fd].buffer = (char *)events_calloc(1, fdTable[fd].length);
			}

			if (events_assign_fd(hDir, newfd)) {
				int r = ReadDirectoryChangesW(hDir, fdTable[fd].buffer, fdTable[fd].length, true, mask, NULL,
					&fdTable[newfd].ovList->overlapped, NULL);
				if (r == 1) {
					SetLastError(ERROR_IO_PENDING);
				} else if (GetLastError() != ERROR_IO_PENDING) {
					os_close(newfd);
					return TASK_ERRED;
				}

				fdTable[newfd].flags = mask;
				fdTable[newfd].offset = fd;
				$append_signed(fdTable[fd].inotify, newfd);
				fdTable[fd].flags = mask;
				fdTable[fd].offset = newfd;
				return newfd;
			}
		} else if (hDir != INVALID && !sys_event.num_loops) {
			int newfd = events_new_fd(FD_MONITOR_SYNC, (intptr_t)hDir, -1);
			fdTable[newfd].flags = mask;
			fdTable[fd].flags = mask;
			fdTable[fd].instance = (unsigned long)newfd;
			return newfd;
		} else {
			errno = GetLastError();
		}
	}

	return TASK_ERRED;
}

int inotify_close(int fd) {
	if (events_valid_fd(fd)) {
		foreach(watch in fdTable[fd].inotify) {
			os_close(watch.integer);
		}

		events_free_fd(fd);
		return 0;
	}

	return TASK_ERRED;
}

int inotify_rm_watch(int fd, int wd) {
	if (!sys_event.num_loops && events_valid_fd(wd))
		return os_close(wd);

	if (wd < 0)
		return inotify_close(fd);

	if (sys_event.num_loops > 0 && events_valid_fd(fd)) {
		foreach(watch in fdTable[fd].inotify) {
			if (watch.integer == wd) {
				$remove(fdTable[fd].inotify, iwatch);
				return os_close(wd);
			}
		}
	}

	return TASK_ERRED;
}
#endif /* WINDOWS ONLY */