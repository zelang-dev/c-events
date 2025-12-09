#include "events_internal.h"

fds_t async_listener(char *server, int port, bool proto_tcp) {
	fds_t fd;
	int proto, n;
	char *ip;
	struct sockaddr_in sa;
	socklen_t sn;
	struct hostent *he = {0};

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	if (server != OS_NULL && strcmp(server, "*") != 0) {
		he = async_gethostbyname(server);
		if (he == NULL) {
			return -1;
		}

		ip = (char *)he->h_addr;
		memmove(&sa.sin_addr, ip, 4);
	}

	sa.sin_port = htons(port);
	proto = proto_tcp ? SOCK_STREAM : SOCK_DGRAM;
	if ((fd = socket(AF_INET, proto, IPPROTO_IP)) < 0) {
		errno = os_geterror();
		return -1;
	}

	// set reuse flag for tcp
	if (proto_tcp && getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)&n, &sn) >= 0) {
		n = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof n);
	}

	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		errno = os_geterror();
		close(fd);
		return -1;
	}

	if (proto == SOCK_STREAM)
		listen(fd, 128);

	events_set_nonblocking(fd);
	return fd;
}

fds_t async_accept(fds_t fd, char *server, int *port) {
	fds_t cfd;
	int one;
	struct sockaddr_in sa;
	uchar *ip;
	socklen_t len;

	async_wait(fd, 'r');
	len = sizeof sa;
	if ((cfd = accept(fd, (void *)&sa, &len)) < 0) {
		errno = os_geterror();
		return -1;
	}

	if (server) {
		ip = (uchar *)&sa.sin_addr;
		snprintf(server, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	}

	if (port)
		*port = ntohs(sa.sin_port);
	events_set_nonblocking(cfd);
	one = 1;
	setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof one);
	return cfd;
}

fds_t async_connect(char *hostname, int port, bool proto_tcp) {
	fds_t fd;
	int proto, n = 0;
	char *ip;
	struct sockaddr_in sa;
	socklen_t sn;
	struct hostent *he = {0};

	if ((he = async_gethostbyname(hostname)) == NULL) {
		return -1;
	}

	ip = (char *)he->h_addr;
	proto = proto_tcp ? SOCK_STREAM : SOCK_DGRAM;
	if ((fd = socket(AF_INET, proto, IPPROTO_IP)) < 0) {
		errno = os_geterror();
		return -1;
	}
	events_set_nonblocking(fd);

	// for udp
	if (!proto_tcp) {
		n = 1;
		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const char *)&n, sizeof n);
	}

	// start connecting
	memset(&sa, 0, sizeof sa);
	memmove(&sa.sin_addr, ip, 4);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0
		&& (os_geterror() != EINPROGRESS && os_geterror() != EAGAIN)) {
		close(fd);
		return -1;
	}

	// wait for finish
	async_wait(fd, 'w');

	sn = sizeof sa;
	if (getpeername(fd, (struct sockaddr *)&sa, &sn) >= 0)
		return fd;

	// report error
	sn = sizeof n;
	getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&n, &sn);
	if (n == 0)
		errno = os_geterror();

	close(fd);
	return -1;
}

int async_read2(int fd, void *buf, int n) {
	int m;

	do
		async_wait(fd, 'r');
	while ((m = read(fd, buf, n)) < 0 && os_geterror() == EAGAIN);
	return m;
}

int async_read(int fd, void *buf, int n) {
	int m;

	while ((m = read(fd, buf, n)) < 0 && os_geterror() == EAGAIN)
		async_wait(fd, 'r');
	return m;
}

int async_write(int fd, void *buf, int n) {
	int m, tot;

	for (tot = 0; tot < n; tot += m) {
		while ((m = write(fd, (char *)buf + tot, n - tot)) < 0 && os_geterror() == EAGAIN)
			async_wait(fd, 'w');
		if (m < 0)
			return m;
		if (m == 0)
			break;
	}
	return tot;
}

EVENTS_INLINE void enqueue_pool_request(os_worker_t *j, os_request_t *r) {
	atomic_lock(&j->mutex);
	events_deque_t *queue = sys_event.local[j->id];
	$append(queue->jobs, r);
	atomic_unlock(&j->mutex);
	atomic_fetch_add(&queue->available, 1);
}

static unsigned int async_loop(events_t *loop, size_t heapsize, param_func_t fn, unsigned int num_of_args, ...) {
	va_list ap;

	va_start(ap, num_of_args);
	param_t params = data_ex(num_of_args, ap);
	va_end(ap);

	tasks_t *t = create_task(heapsize, (data_func_t)fn, params);
	t->tid = loop->loop_id - 1;
	return task_push(t, true);
}

static int __threads_wrapper(void *arg) {
	os_worker_t *work = (os_worker_t *)arg;
	events_deque_t *queue = work->queue;
	values_t res[1] = {0};
	int status = 0, tid = work->id;

	while (!atomic_flag_load(&queue->started))
		;

	do {
		if ((int)atomic_load(&queue->available) > 0) {
			atomic_fetch_sub(&queue->available, 1);
			atomic_lock(&work->mutex);
			os_request_t *worker = (os_request_t *)$shift(queue->jobs).object;
			atomic_unlock(&work->mutex);
			res->object = worker->func(worker->args);
			thread_result_set(worker, res->object);
			$delete(worker->args);
		} else {
			os_sleep(1);
		}
	} while (!atomic_flag_load_explicit(&queue->shutdown, memory_order_relaxed));
	$delete(queue->jobs);
	events_free(arg);
	os_exit(status);
	return status;
}

os_worker_t *events_add_pool(events_t *loop) {
	events_deque_t **local = sys_event.local;
	os_worker_t *f_work = NULL;
	int index = loop->loop_id - 1;
	if (index <= sys_event.cpu_count) {
		local[index] = (events_deque_t *)events_malloc(sizeof(events_deque_t));
		if (local[index] == NULL)
			abort();

		deque_init(local[index], sys_event.queue_size);
		f_work = events_calloc(1, sizeof(os_worker_t));
		if (f_work == NULL)
			abort();

		atomic_unlock(&f_work->mutex);
		f_work->id = (int)index;
		f_work->queue = local[index];
		f_work->queue->jobs = array();
		f_work->queue->loop = loop;
		f_work->loop = loop;
		f_work->type = DATA_PTR;
		local[index]->thread = os_create(__threads_wrapper, (void *)f_work);
		if (local[index]->thread == OS_NULL)
			abort();
	}

	return f_work;
}

static void *queue_work_handler(param_t args) {
	os_worker_t *thrd = args[0].object;
	os_request_t *job = args[1].object;
	job->id = task_id();

	task_name("queue_work #%d", job->id);
	atomic_flag_test_and_set(&thrd->queue->started);

	enqueue_pool_request(thrd, job);
	yield_task();
	while (!atomic_flag_load(&job->done)) {
		task_info(active_task(), 1);
		yield_task();
	}

	defer_free(job);
	return job->result->value.object;
}

unsigned int queue_work(os_worker_t *thrd, param_func_t fn, size_t num_args, ...) {
	va_list ap;

	va_start(ap, num_args);
	array_t args = data_ex(num_args, ap);
	va_end(ap);

	os_request_t *f = (os_request_t*)events_calloc(1, sizeof(os_request_t));
	f->args = args;
	f->func = fn;
	atomic_unlock(&f->mutex);
	atomic_flag_clear(&f->done);
	unsigned int id = async_loop(thrd->loop, Kb(9), queue_work_handler, 2, thrd, f);
	yield_task();
	return id;
}

static EVENTS_INLINE void *os_gethostbyname(param_t name) {
	struct hostent *he = {0};
	if ((he = gethostbyname(name->char_ptr)) != NULL)
		return (void *)he;

	return NULL;
}

EVENTS_INLINE char *gethostbyname_ip(struct hostent *host) {
	struct in_addr **p1 = (struct in_addr **)host->h_addr_list;
	return (char *)inet_ntop(AF_INET, p1[0], events_pool()->buffer, INET_ADDRSTRLEN);
}

EVENTS_INLINE struct hostent *async_get_hostbyname(os_worker_t *thrd, char *hostname) {
	return (struct hostent *)await_for(queue_work(thrd, os_gethostbyname, 2, hostname, thrd->buffer)).object;
}

EVENTS_INLINE struct hostent *async_gethostbyname(char *hostname) {
	return async_get_hostbyname(events_pool(), hostname);
}

static EVENTS_INLINE void *os_getaddrinfo(param_t args) {
	return casting(getaddrinfo(args[0].const_char_ptr, args[1].const_char_ptr,
		(const struct addrinfo *)args[2].object, (addrinfo_t)args[3].object));
}

EVENTS_INLINE int async_get_addrinfo(os_worker_t *thrd, const char *name,
	const char *service, const struct addrinfo *hints, addrinfo_t result) {
	return await_for(queue_work(thrd, os_getaddrinfo, 4, name, service, hints, result)).integer;
}

EVENTS_INLINE int async_getaddrinfo(const char *name,
	const char *service, const struct addrinfo *hints, addrinfo_t result) {
	return async_get_addrinfo(events_pool(), name, service, hints, result);
}

static EVENTS_INLINE void *_os_open(param_t args) {
#ifdef _WIN32
	int r, flags = args[1].integer, mode = args[2].integer;
	flags |= O_BINARY;
	if (flags & O_CLOEXEC) {
		flags &= ~O_CLOEXEC;
		flags |= O_NOINHERIT;
	}

	flags &= ~O_NONBLOCK;
	r = _open(args[0].char_ptr, flags, mode);
#else
	int r = open(args[0].char_ptr, args[1].integer, args[2].integer);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_read(param_t args) {
#ifdef _WIN32
	int r = _read(args[0].integer, args[1].object, args[2].u_int);
#else
	int r = read(args[0].integer, args[1].object, args[2].u_int);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_write(param_t args) {
#ifdef _WIN32
	int r = _write(args[0].integer, args[1].const_char_ptr, args[2].u_int);
#else
	int r = write(args[0].integer, args[1].const_char_ptr, args[2].u_int);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_sendfile(param_t args) {
	return casting(sendfile(args[0].integer, args[1].integer, (off_t *)args[2].long_long_ptr, args[3].max_size));
}

static EVENTS_INLINE void *_os_close(param_t args) {
#ifdef _WIN32
	int r = _close(args[0].integer);
#else
	int r = close(args[0].integer);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_stat(param_t args) {
	return casting(stat(args[0].const_char_ptr, args[1].object));
}

static EVENTS_INLINE void *_os_access(param_t args) {
	return casting(access(args[0].const_char_ptr, args[1].integer));
}

static EVENTS_INLINE void *_os_unlink(param_t args) {
	return casting(unlink(args[0].const_char_ptr));
}

EVENTS_INLINE int async_fs_open(os_worker_t *thrd, const char *path, int flag, int mode) {
	return await_for(queue_work(thrd, _os_open, 3, path, casting(flag), casting(mode))).integer;
}

EVENTS_INLINE int fs_open(const char *path, int flag, int mode) {
	return async_fs_open(events_pool(), path, flag, mode);
}

EVENTS_INLINE int async_fs_read(os_worker_t *thrd, int fd, void *buf, unsigned int count) {
	return await_for(queue_work(thrd, _os_read, 3, casting(fd), buf, casting(count))).integer;
}

EVENTS_INLINE int fs_read(int fd, void *buf, unsigned int count) {
	return async_fs_read(events_pool(), fd, buf, count);
}

EVENTS_INLINE int async_fs_write(os_worker_t *thrd, int fd, const void *buf, unsigned int count) {
	return await_for(queue_work(thrd, _os_write, 3, casting(fd), buf, casting(count))).integer;
}

EVENTS_INLINE int fs_write(int fd, const void *buf, unsigned int count) {
	return async_fs_write(events_pool(), fd, buf, count);
}

EVENTS_INLINE ssize_t async_fs_sendfile(os_worker_t *thrd, int fd_out, int fd_in, off_t *offset, size_t length) {
	return await_for(queue_work(thrd, _os_sendfile, 4,
		casting(fd_out), casting(fd_in), offset, casting(length))).long_long;
}

EVENTS_INLINE ssize_t fs_sendfile(int fd_out, int fd_in, off_t *offset, size_t length) {
	return async_fs_sendfile(events_pool(), fd_out, fd_in, offset, length);
}

EVENTS_INLINE int async_fs_close(os_worker_t *thrd, int fd) {
	return await_for(queue_work(thrd, _os_close, 1, casting(fd))).integer;
}

EVENTS_INLINE int fs_close(int fd) {
	return async_fs_close(events_pool(), fd);
}

EVENTS_INLINE int async_fs_unlink(os_worker_t *thrd, const char *path) {
	return await_for(queue_work(thrd, _os_unlink, 1, path)).integer;
}

EVENTS_INLINE int fs_unlink(const char *path) {
	return async_fs_unlink(events_pool(), path);
}

EVENTS_INLINE int async_fs_stat(os_worker_t *thrd, const char *path, struct stat *st) {
	return await_for(queue_work(thrd, _os_stat, 2, path, st)).integer;
}

EVENTS_INLINE int fs_stat(const char *path, struct stat *st) {
	return async_fs_stat(events_pool(), path, st);
}

EVENTS_INLINE int async_fs_access(os_worker_t *thrd, const char *path, int mode) {
	return await_for(queue_work(thrd, _os_access, 2, path, casting(mode))).integer;
}

EVENTS_INLINE int fs_access(const char *path, int mode) {
	return async_fs_access(events_pool(), path, mode);
}

EVENTS_INLINE bool fs_exists(const char *path) {
	return fs_access(path, F_OK) == 0;
}

EVENTS_INLINE size_t fs_filesize(const char *path) {
	struct stat st;
	if (!fs_stat(path, &st))
		return (size_t)st.st_size;

	return 0;
}

static void spawn_io(fds_t fd, int events, void *arg) {
	char data[1024] = {0};
	int len;
	execinfo_t *info = (execinfo_t *)arg;
	spawn_cb func = (spawn_cb)info->io_func;
	if (events & EVENTS_CLOSED) {
		events_del(fd);
		events_destroy(events_loop(fd));
	} else if ((len = recv(fd, data, sizeof(data), 0))) {
		func((fds_t)info->write_input[0], data);
	} else {
		perror("spawn_io");
	}
}

static void *spawning(param_t args) {
	process_t pid;
	execinfo_t *info = (execinfo_t *)args[2].object;
	tasks_t *t = active_task();
	char *command = args[0].char_ptr;
	int status = 0;
#ifdef _WIN32
	if (!str_has(command, ".bat") && !str_has(command, ".exe")) {
		command = str_cat(2, command, ".exe");
		defer_free(command);
	}
#endif
	task_name("spawn #%d", task_id());
	//status = events_add(events_pool()->loop, (fds_t)info->read_output[0], EVENTS_READ | EVENTS_CLOSED, 0, spawn_io, info);
	pid = exec((const char *)command, args[1].const_char_ptr, info);
	if (pid > 0) {
		info->context = t;
		yield_task();
		while (exec_wait(pid, 0, &status) && os_geterror() == ETIMEDOUT) {
			task_info(t, 1);
			yield_task();
		}

		info->context = NULL;
		if (info->exit_func)
			info->exit_func(status, status);
	} else {
		fprintf(stderr, "Process launch failed with: %s"CLR_LN, strerror(os_geterror()));
	}

	return 0;
}

execinfo_t *spawn(const char *command, const char *args, spawn_cb io_func, exit_cb exit_func) {
	/*if (mkfifo("spawn", 0600) == -1) {
		perror("mkfifo");
		return NULL;
	}

	fds_t socket = open("spawn", O_RDONLY | O_NONBLOCK, 0);
	if (socket == -1) {
		perror("open");
		unlink(mkfifo_name());
		return NULL;
	}
	info->read_output[0] = (filefd_t)socket;*/
	execinfo_t *info = exec_info(NULL, false, inherit, inherit, inherit);
	/*
#ifdef _WIN32
	if (pipe(_2fd(info->write_input))
		|| pipe(_2fd(info->read_output))) {
		perror("pipe");
		return NULL;
	}
#else
	if (pipe2(_2fd(info->write_input), O_NONBLOCK)
		|| pipe2(_2fd(info->read_output), O_NONBLOCK)) {
		perror("pipe2");
		return NULL;
	}
#endif
*/
	//assign_fd(info->read_output[0], (intptr_t)info->fd);
	info->io_func = (exec_io_cb)io_func;
	info->exit_func = exit_func;
	info->rid = async_task(spawning, 3, command, args, info);
	yield_task();
	return info->context == NULL ? NULL : info;
}

EVENTS_INLINE uintptr_t spawn_pid(execinfo_t *child) {
#ifdef _WIN32
	return (uintptr_t)GetProcessId(child->ps);
#else
	return (uintptr_t)child->ps;
#endif

}

EVENTS_INLINE bool spawn_is_finish(execinfo_t *child) {
	return !is_ptr_usable(child) || !is_ptr_usable(child->context) || task_is_terminated(child->context);
}
