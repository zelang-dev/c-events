#include "events_internal.h"

#undef read
#undef write
#undef close
#undef open

#define LOCALHOST "localhost"
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
	unsigned int value;
} DESCRIPTOR;

struct OVERLAPPED_REQUEST {
	OVERLAPPED overlapped;
	unsigned long instance;	/* file instance (won't match after a close) */
	os_cb proc;	/* callback routine */
	void *data;	/* callback argument */
	void *buf;	/* additional data */
};
typedef struct OVERLAPPED_REQUEST *POVERLAPPED_REQUEST;

/*
 * Structure used to map file handle and socket handle
 * values into values that can be used to create unix-like
 * select bitmaps, read/write for both sockets/files.
 */
struct FD_TABLE {
	DESCRIPTOR fid;
	FILE_TYPE type;
	char *path;
	DWORD Errno;
	unsigned long instance;
	int status;
	int offset;			/* only valid for async file writes */
	LPDWORD offsetHighPtr;	/* pointers to offset high and low words */
	LPDWORD offsetLowPtr;	/* only valid for async file writes (logs) */
	HANDLE  hMapMutex;		/* mutex handle for multi-proc offset update */
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
	sys_event.loop_signaled = true;
	events_sigunblock;
}

static EVENTS_INLINE void events_signal_clear(void) {
	events_sigblock;
	sys_event.loop_signaled = false;
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

static void os_error(const char *text) {
	LPVOID buf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		0,
		(LPTSTR)&buf,
		0,
		NULL
	);

	fprintf(stderr, "%s: %s\n", text, (LPCTSTR)buf);
	LocalFree(buf);
}

EVENTS_INLINE bool valid_fd(int fd) {
	return (fd >= 0) && (fd < ioTableSize) ? fdTable[fd].type != FD_UNUSED : false ;
}

bool assign_fd(HANDLE handle, int pseudo) {
	if (!CreateIoCompletionPort(handle, hIoCompPort, pseudo, 0)) {
		os_error("CreateIoCompletionPort");
		free_fd(pseudo);
		CloseHandle(handle);
		return false;
	}

	return true;
}

EVENTS_INLINE unsigned int get_fd(int pseudo) {
	return fdTable[pseudo].fid.value;
}

int new_fd(FILE_TYPE type, int fd, int desiredFd) {
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
		fdTable[index].Errno = NO_ERROR;
		fdTable[index].status = 0;
		fdTable[index].offset = -1;
		fdTable[index].offsetHighPtr = fdTable[index].offsetLowPtr = NULL;
		fdTable[index].hMapMutex = NULL;
		fdTable[index].ovList->overlapped.hEvent = CreateEvent(NULL, FALSE,	FALSE, NULL);
		fdTable[index].process->fd = -1;
		fdTable[index].process->env = NULL;
		fdTable[index].process->detached = false;
		fdTable[index].process->in = inherit;
		fdTable[index].process->out = inherit;
		fdTable[index].process->err = inherit;
		fdTable[index].process->ps = INVALID_HANDLE_VALUE;
	}

	LeaveCriticalSection(&fdTableCritical);
	return index;
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
		hIoCompPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
		if (hIoCompPort == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "CreateIoCompletionPort!  ERROR: %d\r\n\r\n", GetLastError());
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

void free_fd(int fd) {
	/* Catch it if fd is a bogus value */
	assert((fd >= 0) && (fd < ioTableSize));

	EnterCriticalSection(&fdTableCritical);
	if (fdTable[fd].type != FD_UNUSED) {
		switch (fdTable[fd].type) {
			case FD_FILE_SYNC:
			case FD_FILE_ASYNC:
				/* Free file path string */
				assert(fdTable[fd].path != NULL);
				free(fdTable[fd].path);
				fdTable[fd].path = NULL;
				break;
			default:
				break;
		}

		assert(fdTable[fd].path == NULL);
		fdTable[fd].type = FD_UNUSED;
		fdTable[fd].path = NULL;
		fdTable[fd].Errno = NO_ERROR;
		fdTable[fd].offsetHighPtr = fdTable[fd].offsetLowPtr = NULL;
		if (fdTable[fd].hMapMutex != NULL) {
			CloseHandle(fdTable[fd].hMapMutex);
			fdTable[fd].hMapMutex = NULL;
		}
	}

	LeaveCriticalSection(&fdTableCritical);
	return;
}

static short getPort(const char *bind_path) {
	short port = 0;
	char *p = strchr(bind_path, ':');

	if (p && *++p) {
		char buf[6];

		strncpy(buf, p, 6);
		buf[5] = '\0';

		port = (short)atoi(buf);
	}

	return port;
}

int os_connect(sockfd_t s, const struct sockaddr *name, int namelen) {
	int pseudoFd = -1;
	if (sys_event.num_loops == 0 || !valid_fd(s)) {
		return posix_connect(s, name, namelen);
	} else {
		return os_accept_pipe(s);
	}
}

int os_read(int fd, char *buf, size_t len) {
	if (sys_event.num_loops == 0 || fdTable[fd].type == FD_UNUSED)
		return posix_read(fd, buf, len);

	DWORD bytesRead;
	int ret = -1;

	assert((fd >= 0) && (fd < ioTableSize));
	switch (fdTable[fd].type) {
		case FD_FILE_SYNC:
		case FD_FILE_ASYNC:
		case FD_PIPE_SYNC:
		case FD_PIPE_ASYNC:
			if (ReadFile(fdTable[fd].fid.fileHandle, buf, len, &bytesRead, NULL)) {
				ret = bytesRead;
			} else {
				fdTable[fd].Errno = GetLastError();
			}
			break;
		default:
			assert(0);
	}

	return ret;
}

int os_write(int fd, char *buf, size_t len) {
	if (sys_event.num_loops == 0 || fdTable[fd].type == FD_UNUSED)
		return posix_write(fd, buf, len);

	DWORD bytesWritten;
	int ret = -1;

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

int os_asyncread(int fd, void *buf, int len, int offset, os_cb proc, void *data) {
	DWORD bytesRead;

	/*
	 * Catch any bogus fd values
	 */
	assert((fd >= 0) && (fd < ioTableSize));

	/*
	 * Confirm that this is an async fd
	 */
	assert(fdTable[fd].type != FD_UNUSED);
	assert(fdTable[fd].type != FD_FILE_SYNC);
	assert(fdTable[fd].type != FD_PIPE_SYNC);
	assert(fdTable[fd].type != FD_SOCKET_SYNC);
	/*
	 * Only file offsets should be non-zero, but make sure.
	 */
	if (fdTable[fd].type == FD_FILE_ASYNC)
		if (fdTable[fd].offset >= 0)
			fdTable[fd].ovList->overlapped.Offset = fdTable[fd].offset;
		else
			fdTable[fd].ovList->overlapped.Offset = offset;
	fdTable[fd].ovList->instance = fdTable[fd].instance;
	fdTable[fd].ovList->proc = proc;
	fdTable[fd].ovList->data = data;
	bytesRead = fd;
	/*
	 * ReadFile returns: true success, false failure
	 */
	if (!ReadFile(fdTable[fd].fid.fileHandle, buf, len, &bytesRead,
		(LPOVERLAPPED)fdTable[fd].ovList)) {
		fdTable[fd].Errno = GetLastError();
		if (fdTable[fd].Errno == ERROR_NO_DATA ||
			fdTable[fd].Errno == ERROR_PIPE_NOT_CONNECTED) {
			PostQueuedCompletionStatus(hIoCompPort, 0, fd, (LPOVERLAPPED)fdTable[fd].ovList);
			return 0;
		}
		if (fdTable[fd].Errno != ERROR_IO_PENDING) {
			PostQueuedCompletionStatus(hIoCompPort, 0, fd, (LPOVERLAPPED)fdTable[fd].ovList);
			return -1;
		}
		fdTable[fd].Errno = 0;
	}
	return 0;
}

int os_asyncwrite(int fd, void *buf, int len, int offset, os_cb proc, void *data) {
	DWORD bytesWritten;

	/*
	 * Catch any bogus fd values
	 */
	assert((fd >= 0) && (fd < ioTableSize));

	/*
	 * Confirm that this is an async fd
	 */
	assert(fdTable[fd].type != FD_UNUSED);
	assert(fdTable[fd].type != FD_FILE_SYNC);
	assert(fdTable[fd].type != FD_PIPE_SYNC);
	assert(fdTable[fd].type != FD_SOCKET_SYNC);

	/*
	 * Only file offsets should be non-zero, but make sure.
	 */
	if (fdTable[fd].type == FD_FILE_ASYNC)
	/*
	 * Only file opened via OS_AsyncWrite with
	 * O_APPEND will have an offset != -1.
	 */
		if (fdTable[fd].offset >= 0)
			/*
			 * If the descriptor has a memory mapped file
			 * handle, take the offsets from there.
			 */
			if (fdTable[fd].hMapMutex != NULL) {
			/*
			 * Wait infinitely; this *should* not cause problems.
			 */
				WaitForSingleObject(fdTable[fd].hMapMutex, INFINITE);

				/*
				 * Retrieve the shared offset values.
				 */
				fdTable[fd].ovList->overlapped.OffsetHigh = *(fdTable[fd].offsetHighPtr);
				fdTable[fd].ovList->overlapped.Offset = *(fdTable[fd].offsetLowPtr);

				/*
				 * Update the shared offset values for the next write
				 */
				*(fdTable[fd].offsetHighPtr) += 0;	/* TODO How do I handle overflow */
				*(fdTable[fd].offsetLowPtr) += len;

				ReleaseMutex(fdTable[fd].hMapMutex);
			} else
				fdTable[fd].ovList->overlapped.Offset = fdTable[fd].offset;
		else
			fdTable[fd].ovList->overlapped.Offset = offset;
	fdTable[fd].ovList->instance = fdTable[fd].instance;
	fdTable[fd].ovList->proc = proc;
	fdTable[fd].ovList->data = data;
	bytesWritten = fd;
	/*
	 * WriteFile returns: true success, false failure
	 */
	if (!WriteFile(fdTable[fd].fid.fileHandle, buf, len, &bytesWritten,
		(LPOVERLAPPED)fdTable[fd].ovList)) {
		fdTable[fd].Errno = GetLastError();
		if (fdTable[fd].Errno != ERROR_IO_PENDING) {
			PostQueuedCompletionStatus(hIoCompPort, 0, fd, (LPOVERLAPPED)fdTable[fd].ovList);
			return -1;
		}
		fdTable[fd].Errno = 0;
	}
	if (fdTable[fd].offset >= 0)
		fdTable[fd].offset += len;
	return 0;
}

int os_close(int fd) {
	if (fd == -1) return 0;

	if (sys_event.num_loops == 0 || !valid_fd(fd))
		return posix_close(fd);

	int ret = 0;

	/*
	 * Catch it if fd is a bogus value
	 */
	assert((fd >= 0) && (fd < ioTableSize));
	switch (fdTable[fd].type) {
		case FD_PIPE_SYNC:
		case FD_PIPE_ASYNC:
			/*
			* Make sure that the client (ie. a Web Server in this case) has
			* read all data from the pipe before we disconnect.
			*/
			if (!FlushFileBuffers(fdTable[fd].fid.fileHandle)) return -1;
			if (!DisconnectNamedPipe(fdTable[fd].fid.fileHandle)) return -1;
			break;
		case FD_FILE_SYNC:
		case FD_FILE_ASYNC:
		case FD_PROCESS_ASYNC:
			CloseHandle(fdTable[fd].fid.fileHandle);
			break;
		default:
			ret = -1;		/* fake failure */
	}

	free_fd(fd);
	return ret;
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

		/* call callback if descriptor still valid */
		if (pOv && pOv->instance == fdTable[fd].instance) {
			if (sys_event.loop_signaled) {
				events_signal_clear();
				return -1;
			}

			events_fd_t *target = events_target((fdTable[fd].type == FD_FILE_ASYNC ? fdTable[fd].fid.value : fd));
			int revents = (target->events & EVENTS_READ ? EVENTS_READ : 0)
				| (target->events & EVENTS_WRITE ? EVENTS_WRITE : 0)
				| (target->events & EVENTS_CLOSED ? EVENTS_CLOSED : 0);

			if (revents != 0 && target->is_iodispatch && target->loop_id != 0)
				(target->callback)((target->backend_used ? fdTable[fd].fid.value : fd), revents, target->cb_arg);
			else if (target->events & EVENTS_WATCH)
				(target->callback)(fd, EVENTS_WATCH, target->cb_arg);
			else if (fdTable[fd].type == FD_FILE_ASYNC)
				(pOv->proc)((intptr_t)fdTable[fd].fid.value, bytes, pOv->data);

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
				os_error("unexpected ConnectNamedPipe()");
				return -1;
		}
	}

	ipcFd = new_fd(FD_PIPE_ASYNC, (intptr_t)fdTable[fd].fid.fileHandle, -1);
	if (ipcFd == -1) {
		DisconnectNamedPipe(fdTable[fd].fid.fileHandle);
	}

	return ipcFd;
}

int os_mkfifo(const char *name, mode_t mode) {
	events_init(256);
	HANDLE pipeHandle;
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true}; // true: allow handles to be inherited
	const char *piped = "%s%s", *_piped = "%s%s-%zu";
	int err, count = 0;

	for (;;) {
		if (count)
			snprintf(sys_event.pNamed, sizeof(sys_event.pNamed), _piped, SYS_PIPE, name, (getpid() + count));
		else
			snprintf(sys_event.pNamed, sizeof(sys_event.pNamed), piped, SYS_PIPE, name);

		pipeHandle = CreateNamedPipe((LPCSTR)sys_event.pNamed,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			1, 65536, 65536, NMPWAIT_USE_DEFAULT_WAIT, &sa);

		if (pipeHandle != INVALID_HANDLE_VALUE) {
		  /* No name collisions.  We're done. */
			break;
		}

		err = GetLastError();
		if (err != ERROR_PIPE_BUSY && err != ERROR_ACCESS_DENIED) {
			goto error;
		}

		count++;
	}

	sys_event.listenType = FD_PIPE_ASYNC;
	sys_event.pHandle = pipeHandle;
	return 0;

error:
	if (pipeHandle != INVALID_HANDLE_VALUE)
		CloseHandle(pipeHandle);

	return err;
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

	HANDLE h = CreateFile(path, osmode, share_mode, &sec, creation_mode, file_mode, NULL);
	if (share_mode)
		type_mode = FD_PIPE_ASYNC;

	fd = new_fd((FILE_TYPE)type_mode, (intptr_t)h, -1);
	return assign_fd(h, fd) ? fd : -1;
}

int os_open(const char *path, ...) {
	va_list ap;
	int fake, pipe, flags, mode = 0, ipc = str_has(path, SYS_PIPE_PRE);

	if (str_has((const char *)sys_event.pNamed, (char *)path)) {
		fake = new_fd(FD_PIPE_ASYNC, (intptr_t)sys_event.pHandle, -1);
		pipe = os_accept_pipe(fake);
		return assign_fd(sys_event.pHandle, pipe) ? pipe : -1;
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
	STARTUPINFOA si = {0, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL};
	PROCESS_INFORMATION info = {NULL, NULL, 0, 0};
	BOOL inherit_handles = 0;

	si.cb = sizeof(STARTUPINFO);
	if (!i->detached) {
		if (i->in != INVALID_HANDLE_VALUE || i->out != INVALID_HANDLE_VALUE || i->err != INVALID_HANDLE_VALUE) {
			si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
			si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
			si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
			si.dwFlags |= STARTF_USESTDHANDLES;
			inherit_handles = 1;
		}

		if (i->in != inherit) {
			si.hStdInput = i->in;
			SetHandleInformation(i->in, HANDLE_FLAG_INHERIT, 1);
		}

		if (i->out != inherit) {
			si.hStdOutput = i->out;
			SetHandleInformation(i->out, HANDLE_FLAG_INHERIT, 1);
		}

		if (i->err != inherit) {
			si.hStdError = i->err;
			SetHandleInformation(i->err, HANDLE_FLAG_INHERIT, 1);
		}
	}

	BOOL b = CreateProcessA(filename, cmd, NULL, NULL, inherit_handles, i->detached ? DETACHED_PROCESS : 0,
		/*env*/ i->env,
		/*startup dir*/ NULL,
		&si,
		&info);

	if (!b)
		return INVALID_HANDLE_VALUE;

	CloseHandle(info.hThread);
	return info.hProcess;
}

static EVENTS_INLINE process_t os_exec_info(const char *filename, execinfo_t *info) {
	process_t ps = os_exec_child(filename, info->argv, info);
	if(info->argv != NULL)
		events_free(info->argv);
	if(info->env != NULL)
		events_free(info->env);

	info->ps = ps;
	fdTable[info->fd].fid.fileHandle = ps;
	return (process_t)info->fd;
}

EVENTS_INLINE execinfo_t *exec_info(const char *env, bool is_datached,
	filefd_t io_in, filefd_t io_out, filefd_t io_err) {
	int pseudofd = new_fd(FD_PROCESS_ASYNC, (intptr_t)hIoCompPort, -1);
	execinfo_t *info = fdTable[pseudofd].process;

	info->detached = is_datached;
	if (env != NULL && str_has(env, "=") && str_has(env, ";"))
		info->env = (const char **)str_slice(env, ";", NULL);

	if (io_in != inherit)
		info->in = io_in;

	if (io_out != inherit)
		info->out = io_out;

	if (io_err != inherit)
		info->err = io_err;

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

int exec_wait(process_t ps, unsigned int timeout_ms, int *exit_code) {
	process_t pid = fdTable[(intptr_t)ps].process->ps;
	if (fdTable[(intptr_t)ps].process->detached)
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
	for (i = 0; i < max_event_sig; i++) {
		if (!events_sig[i].proc || events_sig[i].sig == sig)
			break;
	}

	if (i == max_event_sig) {
		fprintf(stderr,
			"Cannot install exception handler for signal no (%d), "
			"too many signal exception handlers installed (max %d)\n",
			sig, max_event_sig);
		events_sigunblock;
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
			return EINTR;
		case WSAEBADF:
			return EBADF;
		case WSAEACCES:
			return EACCES;
		case WSAEFAULT:
			return EFAULT;
		case WSAEINVAL:
			return EINVAL;
		case WSAEMFILE:
			return EMFILE;
		case WSAEWOULDBLOCK:
			return EWOULDBLOCK;
		case WSAEINPROGRESS:
			return EINPROGRESS;
		case WSAEALREADY:
			return EALREADY;
		case WSAENOTSOCK:
			return ENOTSOCK;
		case WSAEDESTADDRREQ:
			return EDESTADDRREQ;
		case WSAEMSGSIZE:
			return EMSGSIZE;
		case WSAEPROTOTYPE:
			return EPROTOTYPE;
		case WSAENOPROTOOPT:
			return ENOPROTOOPT;
		case WSAEPROTONOSUPPORT:
			return EPROTONOSUPPORT;
		case WSAEOPNOTSUPP:
			return EOPNOTSUPP;
		case WSAEAFNOSUPPORT:
			return EAFNOSUPPORT;
		case WSAEADDRINUSE:
			return EADDRINUSE;
		case WSAEADDRNOTAVAIL:
			return EADDRNOTAVAIL;
		case WSAENETDOWN:
			return ENETDOWN;
		case WSAENETUNREACH:
			return ENETUNREACH;
		case WSAENETRESET:
			return ENETRESET;
		case WSAECONNABORTED:
			return ECONNABORTED;
		case WSAECONNRESET:
			return ECONNRESET;
		case WSAENOBUFS:
			return ENOBUFS;
		case WSAEISCONN:
			return EISCONN;
		case WSAENOTCONN:
			return ENOTCONN;
		case WSAESHUTDOWN:
			return ECONNRESET;
		case WSAETIMEDOUT:
			return ETIMEDOUT;
		case WSAECONNREFUSED:
			return ECONNREFUSED;
		case WSAELOOP:
			return ELOOP;
		case WSAENAMETOOLONG:
			return ENAMETOOLONG;
		case WSAEHOSTDOWN:
			return ENETDOWN;		/* EHOSTDOWN is not defined */
		case WSAEHOSTUNREACH:
			return EHOSTUNREACH;
		case WSAENOTEMPTY:
			return ENOTEMPTY;
		case WSAEPROCLIM:
			return EAGAIN;
		case WSAEUSERS:
			return EAGAIN;
		case WSAEDQUOT:
			return EAGAIN;
#ifdef WSAECANCELLED
		case WSAECANCELLED:		 /* New in WinSock2 */
			return ECANCELED;
#endif
	}

	return EINVAL;
}

int socketpair(int domain, int type, int protocol, sockfd_t sockets[2]) {
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
	listener = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);
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

	connector = socket(AF_INET, SOCK_STREAM, 0);
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

	if (connect(connector, (struct sockaddr *)&connector_addr,
		addr_size) < 0) {
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

	events_set_nonblocking(connector);
	events_set_nonblocking(acceptor);
	sockets[0] = connector;
	sockets[1] = acceptor;

	return 0;

abort_win32_socketpair:
	errno = ECONNABORTED; /* This would be the standard thing to do. */

fail_win32_socketpair:
	if (!errno) {
		errno = convert_wsa_error(WSAGetLastError());
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