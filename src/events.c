#include "events_internal.h"

#define dequeue(l, t) 				\
	 do { 							\
		if (t->prev)				\
			t->prev->next = t->next;\
		else						\
			l->head = t->next;		\
		if (t->next)				\
			t->next->prev = t->prev;\
		else						\
			l->tail = t->prev;		\
	 } while(0)

#define enqueue(l, t) 				\
	do {							\
		if (l->tail) {				\
			l->tail->next = t;		\
			t->prev = l->tail;		\
		} else {					\
			l->head = t;			\
			t->prev = NULL;			\
		}							\
		l->tail = t;				\
		t->next = NULL; 			\
	} while(0)

static volatile bool events_startup_set = false;
static volatile bool events_shutdown_set = false;
static volatile bool events_tasks_started = false;
static array_t events_fsevents_tasks = null;
static int events_execute(events_t * loop, int max_wait);
sys_events_t sys_event = {0};

typedef struct {
	malloc_func local_malloc;
	realloc_func local_realloc;
	calloc_func local_calloc;
	free_func local_free;
} events_allocator_t;

static events_allocator_t events_allocators = {
  malloc,
  realloc,
  calloc,
  free,
};

typedef struct {
	bool is_main;
	bool started;
	/* has the task sleep/wait system started. */
	bool sleep_activated;
	int active_timer;
	int in_callback;
	/* number of tasks waiting in sleep mode. */
	int sleep_count;
	/* track the number of tasks used */
	int task_count;
	/* indicator for thread termination. */
	uint32_t exiting;
	/* thread id assigned */
	uint32_t thrd_id;
	/* number of other task that ran while the current task was waiting.*/
	uint32_t num_others_ran;
	/* per thread event loop */
	events_t *loop;
	os_worker_t *pool;
	tasks_t *sleep_handle;
	/* record which task is executing for scheduler */
	tasks_t *running;
	/* Variable holding the current running task per thread. */
	tasks_t *active_handle;
#if defined(USE_SJLJ)
	tasks_t *active_sig_handle;
#endif
	/* Variable holding the main target `scheduler` that gets called once an task
	function fully completes and return. */
	tasks_t *main_handle;
	/* Variable holding the previous running task per thread. */
	tasks_t *current_handle;
	/* Store/hold the registers of the default task thread state,
	allows the ability to switch from any function, non task/coroutine context. */
	tasks_t active_buffer[1];
	/* record which task sleeping in scheduler */
	tasklist_t sleep_queue[1];
	/* task's FIFO scheduler queue */
	tasklist_t run_queue[1];
} events_thread_t;
thrd_static(events_thread_t, __thrd, NULL)

struct task_group_s {
	data_types type;
	bool threaded;
	bool taken;
	size_t capacity;
	size_t count;
	array_t results;
	array_t group;
};

static void __thrd_init(bool is_main, uint32_t thread_id);
static int __thrd_wrapper(void *arg);
static int __main_wrapper(void *arg);
static void task_switch(tasks_t *co);
static void task_scheduler_switch(void);
static void task_sleep_switch(void);
static int tasks_schedulering(bool do_io);
static void *task_wait_system(void *v);
static void defer_cleanup(tasks_t *t);
static void enqueue_tasks(tasks_t *t);

#include "deque.c"

EVENTS_INLINE bool events_is_shutdown(void) {
	return events_shutdown_set;
}

void events_set_destroy(void) {
	__thrd()->loop = NULL;
}

EVENTS_INLINE bool events_is_destroy(void) {
	return __thrd()->loop == NULL;
}

EVENTS_INLINE os_worker_t *events_pool(void) {
	return __thrd()->pool;
}

EVENTS_INLINE int events_set_allocator(malloc_func malloc_cb, realloc_func realloc_cb, calloc_func calloc_cb,
	free_func free_cb) {
	if (malloc_cb == NULL || realloc_cb == NULL ||
		calloc_cb == NULL || free_cb == NULL) {
		return -4072;
	}

	events_allocators.local_malloc = malloc_cb;
	events_allocators.local_realloc = realloc_cb;
	events_allocators.local_calloc = calloc_cb;
	events_allocators.local_free = free_cb;

	return 0;
}

void *events_realloc(void *ptr, size_t size) {
	if (size > 0)
		return events_allocators.local_realloc(ptr, size);
	events_free(ptr);
	return NULL;
}

void *events_malloc(size_t size) {
	if (size > 0)
		return events_allocators.local_malloc(size);
	return NULL;
}

void events_free(void *ptr) {
	int saved_errno;
	saved_errno = errno;
	events_allocators.local_free(ptr);
	errno = saved_errno;
}

void *events_calloc(size_t count, size_t size) {
	return events_allocators.local_calloc(count, size);
}

EVENTS_INLINE void events_update_polling(events_t *loop, int fd, int events) {
	events_target(fd)->events = events & EVENTS_READWRITE;
}

EVENTS_INLINE int events_init(int max_fd) {
	atomic_thread_fence(memory_order_seq_cst);
	if (events_shutdown_set || events_startup_set)
		return 0;

	int i;
	events_startup_set = true;
#ifdef _WIN32
	_setmaxstdio(8192);
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif
	assert(!EVENTS_IS_INITD);
	assert(max_fd > 0);

	if (os_init() == -1) {
		return -1;
	}

	atomic_init(&sys_event.fds, NULL);
	atomic_init(&sys_event.results, NULL);
	atomic_init(&sys_event.result_id_generate, 0);
	atomic_init(&sys_event.thrd_id_count, 0);
	atomic_init(&sys_event.id_generate, 0);
	atomic_init(&sys_event.num_loops, 0);
	atomic_flag_clear(&sys_event.loop_signaled);
	atomic_unlock(&sys_event.lock);
	events_fd_t *fds = (events_fd_t *)events_memalign(sizeof(events_fd_t) * max_fd, &sys_event._fds_free_addr, 1);
	if (fds == NULL) {
		os_shutdown();
		return -1;
	}

	atomic_init(&sys_event.fds, fds);
	atexit(events_deinit);
	sys_event.max_fd = max_fd;
	sys_event.cpu_index = NULL;
	sys_event.gc = NULL;
	sys_event.cpu_count = tasks_cpu_count();
	sys_event.queue_size = data_queue_size();
	sys_event.local = NULL;
	sys_event.timeout_vec_size = EVENTS_RND_UP(sys_event.max_fd, EVENTS_SIMD_BITS) / EVENTS_SHORT_BITS;
	sys_event.timeout_vec_of_vec_size = EVENTS_RND_UP(sys_event.timeout_vec_size, EVENTS_SIMD_BITS)
		/ EVENTS_SHORT_BITS;

#if defined(_WIN32)
	sys_event.listenType = FD_UNUSED;
	QueryPerformanceFrequency(&sys_event.timer);
#elif defined(__APPLE__) || defined(__MACH__)
	mach_timebase_info(&sys_event.timer);
#endif

	__thrd_init(true, 0);
	sys_event.local = (events_deque_t **)events_realloc(sys_event.local,
		(sys_event.cpu_count + 1) * sizeof(sys_event.local[0]));

	for (i = 0; i <= sys_event.cpu_count; i++)
		sys_event.local[i] = NULL;

	sys_event.local[0] = (events_deque_t *)events_malloc(sizeof(events_deque_t));
	if (sys_event.local[0] == NULL)
		abort();

	deque_init(sys_event.local[0], sys_event.queue_size);
	return 0;
}

EVENTS_INLINE void events_deinit(void) {
	atomic_thread_fence(memory_order_seq_cst);
	if (events_shutdown_set)
		return;

	events_shutdown_set = true;
	deque_destroy();
	if (sys_event.gc != NULL) {
		foreach(t in sys_event.gc) {
			if (((tasks_t *)t.object)->magic_number == TASK_MAGIC_NUMBER) {
#if defined(_WIN32) && defined(USE_FIBER)
				DeleteFiber(((tasks_t *)t.object)->type->fiber);
#endif
				events_free((tasks_t *)t.object);
			}
		}

		$delete(sys_event.gc);
		sys_event.gc = NULL;
	}

	if (sys_event.cpu_index != NULL) {
		$delete(sys_event.cpu_index);
		sys_event.cpu_index = NULL;
	}

	if (__thrd()->sleep_handle != NULL
		&& __thrd()->sleep_handle->magic_number == TASK_MAGIC_NUMBER) {
#if defined(_WIN32) && defined(USE_FIBER)
		DeleteFiber(__thrd()->sleep_handle->type->fiber);
#endif
		events_free(__thrd()->sleep_handle);
		__thrd()->sleep_handle = NULL;
	}

	events_free(sys_event._fds_free_addr);
	sys_event._fds_free_addr = NULL;
	sys_event.max_fd = 0;
	atomic_init(&sys_event.fds, NULL);
	atomic_init(&sys_event.num_loops, 0);
	results_data_t *r = atomic_get(results_data_t *, &sys_event.results);
	if (r != NULL) {
		size_t i, count = atomic_load(&sys_event.result_id_generate);
		for (i = 0; i < count; i++)
			events_free(r[i]);

		atomic_init(&sys_event.results, NULL);
		events_free((void *)r);
	}

	if (events_fsevents_tasks != null) {
		$delete(events_fsevents_tasks);
		events_fsevents_tasks = null;
	}

	os_shutdown();
#ifdef _WIN32
	WSACleanup();
#endif
}

EVENTS_INLINE int events_set_nonblocking(fds_t fd) {
#ifdef _WIN32
	unsigned long flag = 1;
	return ioctlsocket(fd, FIONBIO, &flag);
#else
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
}

EVENTS_INLINE void events_set_timeout(fds_t sfd, int secs) {
	events_t *loop;
	events_fd_t *target;
	short *vec, *vec_of_vec;
	int fd = socket2fd(sfd);
	size_t vi = fd / EVENTS_SHORT_BITS, delta;
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(fd));
	target = events_target(sfd);
	loop = target->loop;
	if (!EVENTS_FD_BELONGS_TO_LOOP(loop, fd))
		return;

	/* clear timeout */
	if (target->timeout_idx != EVENTS_TIMEOUT_IDX_UNUSED) {
		vec = EVENTS_TIMEOUT_VEC_OF(loop, target->timeout_idx);
		if ((vec[vi] &= ~((unsigned short)SHRT_MIN >> (fd % EVENTS_SHORT_BITS)))
			== 0) {
			vec_of_vec = EVENTS_TIMEOUT_VEC_OF_VEC_OF(loop, target->timeout_idx);
			vec_of_vec[vi / EVENTS_SHORT_BITS]
				&= ~((unsigned short)SHRT_MIN >> (vi % EVENTS_SHORT_BITS));
		}
		target->timeout_idx = EVENTS_TIMEOUT_IDX_UNUSED;
	}
	if (secs != 0) {
		delta = (loop->now + secs - loop->timeout.base_time)
			/ loop->timeout.resolution;
		if (delta >= EVENTS_TIMEOUT_VEC_SIZE) {
			delta = EVENTS_TIMEOUT_VEC_SIZE - 1;
		}
		target->timeout_idx = (loop->timeout.base_idx + delta) % EVENTS_TIMEOUT_VEC_SIZE;
		vec = EVENTS_TIMEOUT_VEC_OF(loop, target->timeout_idx);
		vec[vi] |= (unsigned short)SHRT_MIN >> (fd % EVENTS_SHORT_BITS);
		vec_of_vec = EVENTS_TIMEOUT_VEC_OF_VEC_OF(loop, target->timeout_idx);
		vec_of_vec[vi / EVENTS_SHORT_BITS]
			|= (unsigned short)SHRT_MIN >> (vi % EVENTS_SHORT_BITS);
	}
}

EVENTS_INLINE events_fd_t *events_target(int fd) {
	return (events_fd_t *)atomic_load_explicit(&sys_event.fds, memory_order_relaxed) + fd;
}

EVENTS_INLINE int events_remove(int wd) {
	return inotify_del_monitor(wd);
}

EVENTS_INLINE int events_del_watch(events_t *loop) {
	int fd = loop->inotify_fd;
	loop->inotify_fd = DATA_INVALID;

	return inotify_close(fd);
}

EVENTS_INLINE bool events_is_watching(int inotify) {
	return events_watch_count(inotify) > 0;
}

static void *fsevents_task(param_t args) {
	events_t *loop = tasks_loop();
	int fd = events_watch(loop, args[0].const_char_ptr, (watch_cb)args[1].func, args[2].object);
	while (events_is_watching(fd) && !task_is_canceled()) {
		tasks_info(active_task(), 1);
		yield_task();
	}

	(void)events_del_watch(loop);
	return 0;
}

int fsevents_init(const char *name, watch_cb handler, void *filter) {
	int rid = go(fsevents_task, 3, name, handler, filter);
	if (rid > 0) {
		if (events_fsevents_tasks == null)
			events_fsevents_tasks = array();

		atomic_lock($lock(events_fsevents_tasks));
		$append_signed(events_fsevents_tasks, rid);
		atomic_unlock($lock(events_fsevents_tasks));
		__thrd()->task_count++;
	}

	return rid;
}

int fsevents_stop(uint32_t rid) {
	int found = TASK_ERRED;
	if (rid > 0 && is_data(events_fsevents_tasks) && $size(events_fsevents_tasks) > 0) {
		atomic_lock($lock(events_fsevents_tasks));
		foreach(watch in events_fsevents_tasks) {
			if (watch.integer == rid) {
				$remove(events_fsevents_tasks, iwatch);
				results_data_t *results = (results_data_t *)atomic_load_explicit(&sys_event.results, memory_order_acquire);
				results[rid]->is_canceled = true;
				atomic_store_explicit(&sys_event.results, results, memory_order_release);
				__thrd()->task_count--;
				found = 0;
				break;
			}
		}
		atomic_unlock($lock(events_fsevents_tasks));
	}

	return found;
}

EVENTS_INLINE int events_watch(events_t *loop, const char *name, watch_cb handler, void *filter) {
	if (loop->inotify_fd == DATA_INVALID)
		if ((loop->inotify_fd = inotify_init1(IN_NONBLOCK)) < 0)
			return -1;

#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
	kqueue_watch_init(loop, handler, filter);
	if (inotify_add_watch(loop->inotify_fd, name, IN_ALL_EVENTS) < 0)
		return -1;
#else
	if ((inotify_add_watch(loop->inotify_fd, name, IN_ALL_EVENTS) < 0)
		|| (events_add(loop, loop->inotify_fd, EVENTS_PATHWATCH, 0, (events_cb)handler, filter) < 0))
		return -1;
#endif

	return loop->inotify_fd;
}

int events_add(events_t *loop, fds_t sfd, int event, int timeout_in_secs,
	events_cb callback, void *cb_arg) {
	events_fd_t *target;
	fd_types type = FD_UNKNOWN;
	int sig_idx, fd = socket2fd(sfd);
	bool is_io = false;

	if (!EVENTS_IS_INITD_AND_FD_IN_RANGE(fd)) { return -1; }

#if _WIN32 || __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
	fd = (event == EVENTS_PATHWATCH) ? inotify_wd(fd) : fd;
#else
	fd = (event == EVENTS_PATHWATCH) ? events_get_fd(fd) : fd;
#endif
	target = events_target(fd);
	if (event == EVENTS_SIGNAL) {
		if ((sig_idx = events_add_signal(fd, callback, cb_arg)) >= 0) {
			loop->signal_handlers = events_signals();
			loop->active_signals++;
			loop->signal_handlers[sig_idx].loop = loop;
			target->loop = loop;
			target->signal_idx = sig_idx;
			target->signal_set = true;
			return 0;
		}

		return -1;
	}

	target->is_pathwatcher = event == EVENTS_PATHWATCH;
	target->is_iodispatch = false;
	target->backend_used = false;
#ifdef _WIN32
	if (events_valid_fd(fd) || !is_socket(fd)) {
		is_io = true;
		if (events_valid_fd(fd)) {
			target->_backend = (intptr_t)events_get_fd(fd);
		} else {
			target->backend_used = true;
			target->_backend = (intptr_t)events_new_fd(FD_FILE_ASYNC, fd, -1);
		}

		loop->active_io++;
		target->is_iodispatch = true;
	}
#endif
	//assert(target->loop_id == 0);
	target->callback = callback;
	target->cb_arg = cb_arg;
	target->loop = loop;
	target->loop_id = loop->loop_id;
	target->events = 0;
	target->timeout_idx = EVENTS_TIMEOUT_IDX_UNUSED;
	if (is_io) {
		events_update_polling(loop, fd, event | EVENTS_ADD);
	} else {
		if (events_update_internal(loop, fd, event | EVENTS_ADD) != 0) {
			target->loop = NULL;
			target->loop_id = 0;
			return -1;
		}
	}

	events_set_timeout(fd, timeout_in_secs);
	loop->active_descriptors++;
	return 0;
}

int events_del(fds_t sfd) {
	events_fd_t *target = NULL;
	events_t *loop = NULL;
	sys_signal_t *signal_handlers = NULL;
	int fd = socket2fd(sfd);

	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(fd));
	target = events_target(fd);
	if (target->signal_set) {
		signal_handlers = events_signals();
		if (signal_handlers[target->signal_idx].sig == fd
			&& signal_handlers[target->signal_idx].is_running) {
			events_del_signal(fd, target->signal_idx);
			target->signal_set = false;
			target->loop->active_signals--;
			return 0;
		}
	}

	loop = target->loop;
	if (target->is_iodispatch) {
		loop->active_io--;
	}

	if (loop == NULL || !target->is_iodispatch && events_update_internal(loop, fd, EVENTS_DEL) != 0)
		return -1;

	events_set_timeout(fd, 0);
	loop->active_descriptors--;
	target->loop_id = 0;
	target->loop = NULL;
	return 0;
}

EVENTS_INLINE bool events_is_registered(events_t *loop, fds_t sfd) {
	return loop != NULL
		? events_target(socket2fd(sfd))->loop_id == loop->loop_id
		: events_target(socket2fd(sfd))->loop_id != 0;
}

EVENTS_INLINE bool events_is_running(events_t *loop) {
	return (events_shutdown_set || events_is_destroy() || events_got_signal)
		? false
		: (int)loop->active_descriptors > 0
		|| (int)loop->active_timers > 0
		|| (int)loop->active_io > 0
		|| (int)loop->active_signals > 0
		|| __thrd()->task_count > 0;
}

EVENTS_INLINE int events_get_event(events_t *loop __attribute__((unused)), fds_t sfd) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	return events_target(socket2fd(sfd))->events & EVENTS_READWRITE;
}

int events_set_event(fds_t sfd, int event) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	events_t *loop = events_loop(sfd);
	bool is_io = false;
#ifdef _WIN32
	if ((is_io = (events_valid_fd(sfd) || !is_socket(sfd)))) {
		if (events_target(socket2fd(sfd))->events != event)
			return -1;

		events_update_polling(loop, socket2fd(sfd), event);
		return 0;
	}
#endif
	if (!is_io && events_target(socket2fd(sfd))->events != event
		&& events_update_internal(loop, socket2fd(sfd), event) != 0) {
		return -1;
	}

	return 0;
}

EVENTS_INLINE events_cb events_get_callback(events_t *loop __attribute__((unused)),
	fds_t sfd, void **cb_arg) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	if (cb_arg != NULL) {
		*cb_arg = events_target(socket2fd(sfd))->cb_arg;
	}

	return events_target(socket2fd(sfd))->callback;
}

EVENTS_INLINE void events_set_callback(events_t *loop __attribute__((unused)),
	fds_t sfd, events_cb callback, void **cb_arg) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	if (cb_arg != NULL) {
		events_target(socket2fd(sfd))->cb_arg = *cb_arg;
	}

	events_target(socket2fd(sfd))->callback = callback;
}

EVENTS_INLINE int events_once(events_t *loop, int max_wait) {
	if (max_wait > loop->timeout.resolution) {
		max_wait = loop->timeout.resolution;
	}

	loop->now = time(NULL);
	if (events_execute(loop, max_wait) != 0) {
		return -1;
	}

	if (!__thrd()->in_callback && __thrd()->task_count) {
		tasks_schedulering(false);
	}

	if (max_wait != 0) {
		loop->now = time(NULL);
	}

	events_handle_timeout_internal(loop);
	return (int)(loop->active_descriptors + loop->active_timers + loop->active_io);
}

EVENTS_INLINE void *events_memalign(size_t sz, void **orig_addr, int clear) {
	sz = sz + EVENTS_PAGE_SIZE + EVENTS_CACHE_LINE_SIZE;
	if ((*orig_addr = events_malloc(sz)) == NULL)
		return NULL;

	if (clear != 0)
		memset(*orig_addr, 0, sz);

	return (void *)EVENTS_RND_UP((uintptr_t)*orig_addr + (rand() % EVENTS_PAGE_SIZE), EVENTS_CACHE_LINE_SIZE);
}

EVENTS_INLINE int events_id(events_t *loop) {
	return loop->loop_id;
}

int events_init_loop_internal(events_t *loop, int max_timeout) {
	loop->loop_id = atomic_fetch_add(&sys_event.num_loops, 1) + 1;
	loop->inotify_fd = DATA_INVALID;
	loop->active_descriptors = 0;
	loop->active_io = 0;
	loop->active_timers = 0;
	loop->active_signals = 0;
	loop->signal_handlers = NULL;
	memset(loop->timers, 0, sizeof(loop->timers));
	assert(EVENTS_TOO_MANY_LOOPS);
	if ((loop->timeout.vec_of_vec = (short *)events_memalign(
		(sys_event.timeout_vec_of_vec_size + sys_event.timeout_vec_size) * sizeof(short) * EVENTS_TIMEOUT_VEC_SIZE,
		&loop->timeout._free_addr, 1)) == NULL) {
		atomic_fetch_sub(&sys_event.num_loops, 1);
		return -1;
	}

	loop->timeout.vec = loop->timeout.vec_of_vec + sys_event.timeout_vec_of_vec_size * EVENTS_TIMEOUT_VEC_SIZE;
	loop->timeout.base_idx = 0;
	loop->timeout.base_time = time(NULL);
	loop->timeout.resolution = EVENTS_RND_UP(max_timeout, EVENTS_TIMEOUT_VEC_SIZE) / EVENTS_TIMEOUT_VEC_SIZE;
	if (events_is_destroy())
		__thrd()->loop = loop;

	if (__thrd()->is_main && __thrd()->pool == NULL) {
		__thrd()->pool = events_add_pool(loop);
	}

	return 0;
}

void events_deinit_loop_internal(events_t *loop) {
	events_free(loop->timeout._free_addr);
}

EVENTS_INLINE void events_handle_timeout_internal(events_t *loop) {
	size_t i, j, k;
	for (
		;loop->timeout.base_time <= loop->now - loop->timeout.resolution
		;loop->timeout.base_idx = (loop->timeout.base_idx + 1) % EVENTS_TIMEOUT_VEC_SIZE,
		loop->timeout.base_time += loop->timeout.resolution) {
	   /* TODO use SIMD instructions */
		short *vec = EVENTS_TIMEOUT_VEC_OF(loop, loop->timeout.base_idx);
		short *vec_of_vec = EVENTS_TIMEOUT_VEC_OF_VEC_OF(loop, loop->timeout.base_idx);
		for (i = 0; i < sys_event.timeout_vec_of_vec_size; ++i) {
			if (events_shutdown_set)
				return;
			short vv = vec_of_vec[i];
			if (vv != 0) {
				for (j = i * EVENTS_SHORT_BITS; vv != 0; j++, vv <<= 1) {
					if (vv < 0) {
						short v = vec[j];
						assert(v != 0);
						for (k = j * EVENTS_SHORT_BITS; v != 0; k++, v <<= 1) {
							if (v < 0) {
								events_fd_t *fd = events_target(k);
								assert(fd->loop_id == loop->loop_id);
								fd->timeout_idx = EVENTS_TIMEOUT_IDX_UNUSED;
								events_id_t loop_id = loop->loop_id;
								(*fd->callback)(k, EVENTS_TIMEOUT, fd->cb_arg);
								if (loop_id != loop->loop_id)
									return;
							}
						}
						vec[j] = 0;
					}
				}
				vec_of_vec[i] = 0;
			}
		}
	}
}

static EVENTS_INLINE uint64_t events_nsec(void) {
	struct timeval tv;

	if (events_timeofday(&tv, 0) < 0)
		return -1;

	return (uint64_t)tv.tv_sec * 1000 * 1000 * 1000 + tv.tv_usec * 1000;
}

#	if defined(__APPLE__) || defined(__MACH__)
EVENTS_INLINE int events_timeofday(struct timeval *tp, void *tz)
#else
EVENTS_INLINE int events_timeofday(struct timeval *tp, struct timezone *tz)
#endif
{
#ifdef _WIN32
	/*
	 * Note: some broken versions only have 8 trailing zero's, the correct
	 * epoch has 9 trailing zero's
	 */
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
#else
	return gettimeofday(tp, tz);
#endif
}

EVENTS_INLINE uint64_t events_now(void) {
	uint64_t lapse = 0;
	struct timeval tv;

#if defined(__APPLE__) || defined(__MACH__)
	uint64_t t = mach_absolute_time();

	if (&sys_event.timer)
		lapse = t * ((double)sys_event.timer.numer / (double)sys_event.timer.denom);
#elif defined(_WIN32)
	LARGE_INTEGER count;

	if (QueryPerformanceCounter(&count) && &sys_event.timer)
		lapse = (count.QuadPart * 1000000000) / sys_event.timer.QuadPart;
#else
	struct timespec ts;

	/* Has 2038 issue if time_t: tv.tv_sec is 32-bit. */
	if (!clock_gettime(CLOCK_MONOTONIC, &ts))
		lapse = ts.tv_sec * 1000000000 + ts.tv_nsec;
#endif

	if (!lapse) {
		/* macOS , mingw.org, used on mingw-w64.
		   Has 2038 issue if time_t: tv.tv_sec is 32-bit.
		 */
		if (!events_timeofday(&tv, NULL))
			lapse = tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
	}

	return lapse;
}

static actor_t *events_actor_timeout(events_t *loop, int ms, actor_cb timer, void *args, actor_t *timeout) {
	size_t when;
	actor_t *t = NULL, *actor_running = (timeout == NULL)
		? events_calloc(1, sizeof(actor_t))
		: timeout;

	if (actor_running != NULL) {
		when = (size_t)(events_nsec() + ms * 1000000);
		for (t = loop->timers->head; t != NULL && t->alarmtime < when; t = t->next)
			;

		if (t) {
			actor_running->prev = t->prev;
			actor_running->next = t;
		} else {
			actor_running->prev = loop->timers->tail;
			actor_running->next = NULL;
		}

		actor_running->actor = timer;
		actor_running->args = args;
		actor_running->loop = loop;
		t = actor_running;
		t->alarmtime = when;
		if (t->prev)
			t->prev->next = t;
		else
			loop->timers->head = t;

		if (t->next)
			t->next->prev = t;
		else
			loop->timers->tail = t;

		loop->active_timers++;
	}

	return t;
}

EVENTS_INLINE actor_t *events_repeat_actor(actor_t *actor, int ms) {
	actor->repeating = 1;
	actor->loop->active_timers--;
	return events_actor_timeout(actor->loop, ms, actor->actor, actor->args, actor);
}

EVENTS_INLINE void events_clear_actor(actor_t *actor) {
	actor->repeating = 0;
}

EVENTS_INLINE actor_t *events_actor(events_t *loop, int ms, actor_cb timer, void *args) {
	return events_actor_timeout(loop, ms, timer, args, NULL);
}

EVENTS_INLINE events_t *events_loop(fds_t sfd) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	events_fd_t *target = events_target(socket2fd(sfd));
	return (target->signal_set)
		? events_signals()[target->signal_idx].loop : target->loop;
}

EVENTS_INLINE events_t *events_actor_loop(actor_t *actor) {
	return actor->loop;
}

static int events_execute(events_t *loop, int max_wait) {
	actor_t *t;
	size_t now;
	timerlist_t *l;

	if (loop->active_io)
		os_iodispatch((__thrd()->task_count ? 0 : max_wait));

	if (events_poll_once_internal(loop, (__thrd()->task_count || loop->active_io ? 0 : max_wait)) != 0) {
		return -1;
	}

	now = events_nsec();
	l = loop->timers;
	while ((t = l->head) && now >= t->alarmtime) {
		dequeue(l, t);
		t->actor(t, t->args);
		if (!t->repeating) {
			events_free(t);
			loop->active_timers--;
		}
		break;
	}

	return 0;
}

EVENTS_INLINE char *mkfifo_name(void) {
	return sys_event.pNamed;
}

EVENTS_INLINE filefd_t mkfifo_fd(void) {
	return sys_event.pHandle;
}

fd_types events_fd_type(int fd) {
#ifndef _WIN32
	struct stat sb;
	if (fstat(fd, &sb) == -1)
		return -1;

	switch (sb.st_mode & S_IFMT) {
		case S_IFBLK:
			return FD_BLK;
		case S_IFCHR:
			return FD_CHR;
		case S_IFDIR:
			return FD_DIR;
		case S_IFIFO:
			return FD_FIFO;
		case S_IFLNK:
			return FD_LNK;
		case S_IFREG:
			return FD_REG;
		case S_IFSOCK:
			return FD_SOCK;
		default:
			return FD_UNKNOWN;
	}
#else
	HANDLE handle = (HANDLE)&fd;
	BY_HANDLE_FILE_INFORMATION info;
	DWORD dw;

	/* GetFileType vaguely tells us what kind of file it is */
	dw = GetFileType(handle);
	if (dw == FILE_TYPE_UNKNOWN) return FD_UNKNOWN;

	switch (dw) {
		/* Character device */
		case FILE_TYPE_CHAR:
			return FD_CHR;
		/* Regular file, Directory, Symbolic link, or block device */
		case FILE_TYPE_DISK:

			/* Block device if file attributes are undefined */
			if (GetFileInformationByHandle(handle, &info) == false)
				return FD_BLK;

			/* File attributes can tell us what type of physical file it is */
			switch (info.dwFileAttributes) {
				case FILE_ATTRIBUTE_NORMAL: return FD_REG;
				case FILE_ATTRIBUTE_DIRECTORY: return FD_DIR;
				case FILE_ATTRIBUTE_REPARSE_POINT: return FD_LNK;
			}
			break;
		/* Socket or FIFO */
		case FILE_TYPE_PIPE:
			/* If we cannot query pipe info, it must be a socket */
			return GetNamedPipeInfo(handle, 0, 0, 0, 0) ?
				FD_FIFO : FD_SOCK;
	}

	/* Should never reach here */
	return FD_UNKNOWN;
#endif
}

static void __thrd_init(bool is_main, uint32_t thread_id) {
	__thrd()->is_main = is_main;
	__thrd()->thrd_id = thread_id;
	__thrd()->started = false;
	__thrd()->exiting = 0;
	__thrd()->in_callback = 0;
	__thrd()->active_timer = 0;
	__thrd()->sleep_count = 0;
	__thrd()->task_count = 0;
	__thrd()->sleep_handle = NULL;
	__thrd()->active_handle = NULL;
	__thrd()->current_handle = NULL;
	__thrd()->main_handle = NULL;
	__thrd()->loop = NULL;
	__thrd()->pool = NULL;
	__thrd()->sleep_activated = (int)task_push(create_task(Kb(18), task_wait_system, NULL, false)) >= 0;
}

static EVENTS_INLINE void task_scheduler_switch(void) {
	task_switch(__thrd()->main_handle);
}

static EVENTS_INLINE tasks_t *task_dequeue(tasklist_t *l) {
	tasks_t *t = NULL;
	if (l->head != NULL) {
		t = l->head;
		dequeue(l, t);
	}

	return t;
}

/* Delete specified coroutine. */
static void task_delete(tasks_t *co) {
	if (!co) {
		fprintf(stderr, "attempt to delete an invalid task");
	} else if (!(co->status == TASK_NORMAL
		|| co->status == TASK_DEAD
		|| co->status == TASK_ERRED
		|| co->status == TASK_FINISH)) {
		co->err_code = TASK_ERRED;
	} else {
		if (co->magic_number == TASK_MAGIC_NUMBER) {
			co->magic_number = TASK_ERRED;
			co->garbage = NULL;
#if defined(_WIN32) && defined(USE_FIBER)
			DeleteFiber(co->type->fiber);
#endif
			events_free(co);
		}
	}
}

static EVENTS_INLINE void defer_cleanup(tasks_t *t) {
	if (t->garbage != NULL) {
		foreach_back(arr in t->garbage) {
			if (is_ptr_usable(arr.object)) {
				if (is_data(arr.object))
					$delete(arr.object);
				else if (data_type(arr.object) == DATA_OBJ)
					((data_object_t *)arr.object)->dtor(arr.object);
				else if (arr.object != NULL)
					events_free(arr.object);
			}
		}

		$delete(t->garbage);
		t->garbage = NULL;
	}
}

static EVENTS_INLINE void tasks_result_set(tasks_t *co, void *data) {
	results_data_t *results = (results_data_t *)atomic_load_explicit(&sys_event.results, memory_order_acquire);
	if (data != NULL && is_ptr_usable(co)) {
		atomic_thread_fence(memory_order_seq_cst);
		results[co->rid]->result.object = data;
		results[co->rid]->is_ready = true;
		co->results = &results[co->rid]->result;
	}

	if (is_ptr_usable(co)) {
		results[co->rid]->is_terminated = true;
		co->status = TASK_FINISH;
	}
	atomic_store_explicit(&sys_event.results, results, memory_order_release);
}

/* called only if tasks_t func returns */
static EVENTS_INLINE void task_done(void) {
	active_task()->halt = true;
	active_task()->status = TASK_DEAD;
	task_scheduler_switch();
}

static void task_awaitable(void) {
	tasks_t *co = active_task();
	param_t args = (param_t)co->args;
	tasks_result_set(co, co->func(args));
	data_delete(args);
	defer_cleanup(co);
}

static EVENTS_INLINE void task_func(void) {
	task_awaitable();
	task_done(); /* called only if coroutine function returns */
}

static EVENTS_INLINE void task_sleep_switch(void) {
	task_switch(__thrd()->sleep_handle);
	task_scheduler_switch();
}

/* Returns task status state string. */
static EVENTS_INLINE const char *task_state(int status) {
	switch (status) {
		case TASK_DEAD:
			return "Dead/Not initialized";
		case TASK_NORMAL:
			return "Active/Not running";
		case TASK_RUNNING:
			return "Active/Running";
		case TASK_SUSPENDED:
			return "Suspended/Not started";
		case TASK_SLEEPING:
			return "Sleeping/Waiting";
		case TASK_EVENT:
			return "Events running";
		case TASK_ERRED:
			return "Erred/Exception generated";
		default:
			return "Unknown";
	}
}

EVENTS_INLINE int task_err_code(void) {
	return active_task()->err_code;
}

EVENTS_INLINE ptrdiff_t task_code(void) {
	return (ptrdiff_t)active_task()->err_code;
}

EVENTS_INLINE void *task_data(void) {
	return active_task()->user_data;
}

EVENTS_INLINE void task_data_set(tasks_t *t, void *data) {
	t->user_data = data;
}

EVENTS_INLINE void *task_data_get(tasks_t *t) {
	return t->user_data;
}

EVENTS_INLINE void tasks_info(tasks_t *t, int pos) {
#ifdef USE_DEBUG
	bool line_end = false;
	if (t == NULL) {
		line_end = true;
		t = active_task();
	}

	char line[256];
	snprintf(line, 256, CLR_LN"\r\033[%dA", pos);
	fprintf(stderr, "\t\t - Thrd #%zx, id: %u cid: %u (%s) %s cycles: %zu%s",
		os_self(),
		t->tid,
		t->cid,
		t->name,
		task_state(t->status),
		t->cycles,
		(line_end ? CLR_LN : line)
	);
#endif
}

/* Mark the current task as a ``system`` coroutine. These are ignored for the
purposes of deciding the program is done running */
static EVENTS_INLINE void task_system(void) {
	if (!__thrd()->running->system) {
		__thrd()->running->system = true;
		--__thrd()->task_count;
		__thrd()->running->tid = __thrd()->thrd_id;
		__thrd()->sleep_handle = __thrd()->running;
	}
}

/* The current task will be scheduled again once all the
other currently-ready tasks have a chance to run. Returns
the number of other tasks that ran while the current task was waiting. */
static EVENTS_INLINE int task_yielding_active(void) {
	int n = __thrd()->num_others_ran;
	yield_task();
	return __thrd()->num_others_ran - n - 1;
}

static void *task_wait_system(void *v) {
	tasks_t *t;
	tasklist_t *l;
	size_t now;
	(void)v;

	task_system();
	if (__thrd()->is_main)
		task_name("task_wait_system");
	else
		task_name("task_wait_system #%d", (int)__thrd()->thrd_id);

	while (!__thrd()->exiting) {
#ifdef _WIN32
		__thrd()->active_timer++;
#endif
		/* let everyone else run */
		while (task_yielding_active() > 0)
			;
#ifdef _WIN32
		__thrd()->active_timer--;
#endif

		now = events_nsec();
		tasks_info(active_task(), 1);
		while ((t = __thrd()->sleep_queue->head) && now >= t->alarm_time || (t && t->halt)) {
			l = __thrd()->sleep_queue;
			dequeue(l, t);
			if (!t->system && --__thrd()->sleep_count == 0)
				__thrd()->task_count--;

			if (!t->halt) {
				t->status = TASK_NORMAL;
				l = __thrd()->run_queue;
				t->ready = true;
				enqueue(l, t);
				if (t->sleeping != NULL) {
					t = t->sleeping;
					t->ready = true;
					t->sleeping = NULL;
					enqueue(l, t);
				}
			}
		}
	}

	return 0;
}

static EVENTS_INLINE void add_timeout(tasks_t *running, tasks_t *context, uint32_t ms, size_t now) {
	size_t when = now + (size_t)ms * 1000000;
	tasks_t *t = NULL;

	for (t = __thrd()->sleep_queue->head; t != NULL && t->alarm_time < when; t = t->next)
		;

	if (t) {
		context->prev = t->prev;
		context->next = t;
	} else {
		context->prev = __thrd()->sleep_queue->tail;
		context->next = NULL;
	}

	t = context;
	t->alarm_time = when;
	t->status = TASK_SLEEPING;
	if (t->prev)
		t->prev->next = t;
	else
		__thrd()->sleep_queue->head = t;

	if (t->next)
		t->next->prev = t;
	else
		__thrd()->sleep_queue->tail = t;

	if (!running->system && __thrd()->sleep_count++ == 0)
		__thrd()->task_count++;
}

EVENTS_INLINE uint32_t sleep_task(uint32_t ms) {
	size_t now = events_nsec();

	add_timeout(__thrd()->running, __thrd()->running, ms, now);
	task_switch(__thrd()->current_handle);

	return (uint32_t)(events_nsec() - now) / 1000000;
}

static void wait_cb(fds_t fd, int event, void *arg) {
	tasks_t *t = (tasks_t *)arg;
	tasklist_t *l = __thrd()->run_queue;
	t->ready = true;
	enqueue(l, t);
	events_del(fd);
}

void async_wait(int fd, int rw) {
	int bits = 0;
	switch (rw) {
		case 'r':
			bits |= EVENTS_READ;
			break;
		case 'w':
			bits |= EVENTS_WRITE;
			break;
	}

	events_add(__thrd()->loop, fd, bits, 0, wait_cb, (void *)__thrd()->running);
	task_switch(__thrd()->current_handle);
}

#if defined(_WIN32) && defined(USE_FIBER)
static EVENTS_INLINE void __stdcall fiber_thunk(void *func) {
	((void (*)(void))func)();
}

/* Windows fibers do not allow users to supply their own memory */
static EVENTS_INLINE tasks_t *task_derive(void *memory, uint32_t heapsize, bool is_thread) {
	active_task();
	coroutine_t *co = (coroutine_t *)memory;
	if (!is_thread)
		co->fiber = CreateFiber(heapsize, fiber_thunk, (void *)task_func);

	return (tasks_t *)co;
}

EVENTS_INLINE void task_switch(tasks_t *handle) {
	tasks_t *coro_previous_handle = __thrd()->active_handle;
	__thrd()->active_handle = handle;
	__thrd()->active_handle->status = TASK_RUNNING;
	__thrd()->current_handle = coro_previous_handle;
	if (__thrd()->current_handle->status != TASK_SLEEPING)
		__thrd()->current_handle->status = TASK_NORMAL;

	SwitchToFiber(handle->type->fiber);
}

#elif defined(USE_SJLJ)
static void _spring_board(int ignored) {
	if (sigsetjmp(((coroutine_t *)__thrd()->active_sig_handle)->sig_ctx, 0)) {
		((coroutine_t *)__thrd()->active_handle)->sig_func();
	}
}

/* Switch to specified coroutine. */
static void task_switch(tasks_t *co) {
	if (!sigsetjmp(((coroutine_t *)active_task())->sig_ctx, 0)) {
		tasks_t *task_previous_handle = __thrd()->active_handle;
		__thrd()->active_handle = co;
		__thrd()->active_handle->status = TASK_RUNNING;
		__thrd()->current_handle = task_previous_handle;
		__thrd()->active_sig_handle = __thrd()->current_handle;
		if (__thrd()->current_handle->status != TASK_SLEEPING)
			__thrd()->current_handle->status = TASK_NORMAL;

		siglongjmp(((coroutine_t *)__thrd()->active_handle)->sig_ctx, 1);
	}
}

static tasks_t *task_derive(void *co, size_t stack_size, bool is_thread) {
	(void)is_thread;
	coroutine_t *contxt = (coroutine_t *)co;
	void *memory = (unsigned char *)co + sizeof(_results_data_t);
	stack_size -= sizeof(tasks_t);
	if (contxt) {
		struct sigaction handler;
		struct sigaction old_handler;

		stack_t stack;
		stack_t old_stack;

		contxt->sig_func = contxt->stack = NULL;

		stack.ss_flags = 0;
		stack.ss_size = stack_size;
		contxt->stack = stack.ss_sp = memory;
		if (stack.ss_sp && !sigaltstack(&stack, &old_stack)) {
			handler.sa_handler = _spring_board;
			handler.sa_flags = SA_ONSTACK;
			sigemptyset(&handler.sa_mask);
			__thrd()->active_sig_handle = (tasks_t *)co;

			if (!sigaction(SIGUSR1, &handler, &old_handler)) {
				if (!raise(SIGUSR1)) {
					contxt->sig_func = task_func;
				}

				sigaltstack(&old_stack, 0);
				sigaction(SIGUSR1, &old_handler, 0);
			}
		}

		if (contxt->sig_func != task_func) {
			task_delete((tasks_t *)contxt);
			contxt = NULL;
		}
	}

	return (tasks_t *)contxt;
}

#else
static tasks_t *task_derive(void *co, size_t stack_size, bool is_thread) {
	(void)is_thread;
	ucontext_t *ctx = (ucontext_t *)co;
	size_t size = stack_size + sizeof(_results_data_t);
	size -= sizeof(ucontext_t);

	/* Initialize ucontext. */
	if (getcontext(ctx)) {
		perror("getcontext failed!");
		return NULL;
	}

	ctx->uc_link = (ucontext_t *)__thrd()->main_handle;
	ctx->uc_stack.ss_sp = (unsigned char *)co + 8;
	ctx->uc_stack.ss_size = size - 64;
	makecontext(ctx, (void (*)(void))task_func, 0);

	return (tasks_t *)co;
}

/* Switch to specified coroutine. */
static EVENTS_INLINE void task_switch(tasks_t *co) {
	tasks_t *task_previous_handle = __thrd()->active_handle;
	__thrd()->active_handle = co;
	__thrd()->active_handle->status = TASK_RUNNING;
	__thrd()->current_handle = task_previous_handle;
	if (__thrd()->current_handle->status != TASK_SLEEPING)
		__thrd()->current_handle->status = TASK_NORMAL;

	if (swapcontext((ucontext_t *)__thrd()->current_handle, (ucontext_t *)__thrd()->active_handle))
		perror("Error! `swapcontext`");
}

#endif

void events_abort(const char *message, const char *file, int line, const char *function) {
	fflush(stdout);
#ifndef USE_DEBUG
	fprintf(stderr, "\nFatal Error: %s in function(%s)\n\n", message, function);
#else
	fprintf(stderr, "\n%s: %s\n", "Runtime Error", message);
	if (file != NULL) {
		if (function != NULL) {
			fprintf(stderr, "    thrown in %s at (%s:%d)\n\n", function, file, line);
		} else {
			fprintf(stderr, "    thrown at %s:%d\n\n", file, line);
		}
	}
#endif
	fflush(stderr);
	abort();
}

EVENTS_INLINE uint32_t gen_id(void) {
	return active_task()->gen_id;
}

generator_t generator(param_func_t fn, size_t num_of, ...) {
	generator_t gen = NULL;
	va_list ap;

	va_start(ap, num_of);
	param_t params = data_ex(num_of, ap);
	va_end(ap);

	tasks_t *t = create_task(Kb(32), (data_func_t)fn, params, false);
	uint32_t rid = task_push(t);
	if (rid != TASK_ERRED && snprintf(t->name, sizeof(t->name), "Generator #%d", (int)rid)) {
		gen = events_calloc(1, sizeof(struct generator_s));
		if (gen != NULL) {
			gen->rid = rid;
			gen->is_ready = false;
			gen->context = t;
			gen->type = DATA_GENERATOR;
			t->generator = gen;
			t->is_generator = true;
			t->garbage = array();
			$append(t->garbage, gen);
		}
	}

	return gen;
}

void yielding(void *data) {
	tasks_t *co = active_task();
	if (!co->is_generator)
		panic("Current `task` not a generator!\n");

	while (co->generator->is_ready) {
		yield_task();
	}

	co->generator->values->object = data;
	co->generator->is_ready = true;
	yield_task();
}

values_t yielded(generator_t gen) {
	if (data_type(gen) != DATA_GENERATOR)
		return data_values_empty->value;

	while (!gen->is_ready && !gen->context->halt) {
		if (gen->context->status == TASK_SUSPENDED) {
			tasklist_t *l = __thrd()->run_queue;
			enqueue(l, gen->context);
		}

		tasks_info(active_task(), 1);
		yield_task();
	}

	if (data_type(gen) != DATA_GENERATOR || (gen->context->halt && !gen->is_ready))
		return data_values_empty->value;

	active_task()->gen_id = gen->rid;
	gen->is_ready = false;
	return *gen->values;
}

static EVENTS_INLINE void task_yielding(tasks_t *co) {
	if (!__thrd()->in_callback && !__thrd()->active_timer)
		tasks_stack_check(0);

	task_switch(co);
}

static results_data_t tasks_create_result(void) {
	results_data_t result, *results;
	size_t id = atomic_fetch_add(&sys_event.result_id_generate, 1);
	result = (results_data_t)events_malloc(sizeof(_results_data_t));
	results = (results_data_t *)atomic_load_explicit(&sys_event.results, memory_order_acquire);
	if (id % sys_event.queue_size == 0 || results == NULL)
		results = events_realloc(results, (id + sys_event.queue_size) * sizeof(results[0]));

	result->is_ready = false;
	result->is_terminated = false;
	result->is_canceled = false;
	result->id = id;
	result->result.object = NULL;
	result->type = DATA_PTR;
	results[id] = result;
	atomic_store_explicit(&sys_event.results, results, memory_order_release);
	return result;
}

/* Utility for aligning addresses. */
static EVENTS_INLINE size_t _tasks_align_forward(size_t addr, size_t align) {
	return (addr + (align - 1)) & ~(align - 1);
}

/* Create new task. */
tasks_t *create_task(size_t heapsize, data_func_t func, void *args, bool is_thread) {
	void *memory = NULL;
	tasks_t *co = NULL;
	/* Stack size should be at least `TASK_STACK_SIZE`. */
	if ((heapsize != 0 && heapsize < TASK_STACK_SIZE) || heapsize == 0)
		heapsize = TASK_STACK_SIZE;

#if __APPLE__ && __MACH__
	if (heapsize <= MINSIGSTKSZ)
		heapsize = MINSIGSTKSZ + heapsize;
#endif

	if (atomic_load(&sys_event.id_generate) == 1)
		heapsize = heapsize * 4;
#if !defined(_WIN32) && !defined(USE_FIBER)
	else if (is_thread && heapsize <= Kb(32))
		heapsize = Kb(32) + heapsize;
#endif

	heapsize = _tasks_align_forward(heapsize + sizeof(tasks_t), 16); /* Stack size should be aligned to 16 bytes. */
	if ((memory = events_calloc(1, heapsize + sizeof(_results_data_t))) == NULL
		|| (co = task_derive(memory, heapsize, is_thread))== NULL) {
		perror("Error! calloc/task_derive");
		return NULL;
	}

	if (!__thrd()->current_handle)
		__thrd()->current_handle = active_task();

	if (!__thrd()->main_handle)
		__thrd()->main_handle = __thrd()->active_handle;

	co->func = func;
	co->args = args;
	co->status = TASK_SUSPENDED;
	co->halt = false;
	co->ready = false;
	co->waiting = false;
	co->taken = false;
	co->is_threaded = is_thread;
	co->is_generator = false;
	co->group_active = false;
	co->group_finish = true;
	co->system = false;
	co->referenced = false;
	co->err_code = 0;
	co->cycles = 0;
	co->cid = DATA_INVALID;
	co->gen_id = TASK_ERRED;
	co->user_data = NULL;
	co->context = NULL;
	co->sleeping = NULL;
	co->task_group = NULL;
	co->garbage = NULL;
	co->generator = NULL;
	co->stack_size = heapsize + sizeof(_results_data_t);
	co->stack_base = (unsigned char *)(co + 1);
	co->magic_number = TASK_MAGIC_NUMBER;

	return co;
}

uint32_t task_push(tasks_t *t) {
	if (t && t->status == TASK_SUSPENDED && t->cid == DATA_INVALID) {
		tasks_t *c = active_task();
		bool is_group = false;
		t->cid = (uint32_t)atomic_fetch_add(&sys_event.id_generate, 1) + 1;
		t->rid = tasks_create_result()->id;

		if (c->group_active && c->task_group != NULL && !c->group_finish) {
			is_group = true;
			t->waiting = true;
			$append(c->task_group->group, t);
		}

		if (!t->is_threaded) {
			t->tid = __thrd()->thrd_id;
			__thrd()->task_count++;
			t->ready = true;
			t->taken = true;
			tasklist_t *l = __thrd()->run_queue;
			enqueue(l, t);
		} else if (!is_group) {
			t->tid = sys_event.cpu_index[(atomic_fetch_add(&sys_event.thrd_id_count, 1) % $size(sys_event.cpu_index))].u_int;
			results_data_t *results = (results_data_t *)atomic_load_explicit(&sys_event.results, memory_order_acquire);
			results[t->rid]->tid = t->tid;
			atomic_store_explicit(&sys_event.results, results, memory_order_release);
			enqueue_tasks(t);
		}
	}

	return (t == NULL) ? TASK_ERRED : t->rid;
}

static EVENTS_INLINE results_data_t task_result_get(uint32_t id) {
	return (results_data_t)atomic_load_explicit(&sys_event.results[id], memory_order_relaxed);
}

EVENTS_INLINE bool task_is_terminated(tasks_t *co) {
	return is_ptr_usable(co) ? co->halt : true;
}

EVENTS_INLINE bool task_is_canceled(void) {
	return task_result_get(task_id())->is_canceled;
}

EVENTS_INLINE values_t await_for(uint32_t id) {
	while (!task_result_get(id)->is_terminated)
		yield_task();

	return results_for(id);
}

EVENTS_INLINE bool task_is_ready(uint32_t id) {
	return task_result_get(id)->is_ready;
}

EVENTS_INLINE uint32_t task_id(void) {
	return active_task()->rid;
}

int results_tid(uint32_t rid) {
	return task_result_get(rid)->tid;
}

EVENTS_INLINE values_t results_for(uint32_t id) {
	results_data_t result = task_result_get(id);
	if (result->is_ready)
		return result->result;

	return data_values_empty->value;
}

bool defer_free(void *data) {
	tasks_t *t = NULL;
	if (data == NULL)
		return false;

	if (__thrd()->running != NULL)
		t = __thrd()->running;
	else
		t = active_task();

	if (t->garbage == NULL)
		t->garbage = array();

	$append(t->garbage, data);
	return true;
}

EVENTS_INLINE tasks_t *active_task(void) {
	if (!__thrd()->active_handle) {
		__thrd()->active_handle = __thrd()->active_buffer;
#if defined(_WIN32) && defined(USE_FIBER)
		ConvertThreadToFiber(0);
		__thrd()->active_handle->type->fiber = GetCurrentFiber();
#endif
	}

	return __thrd()->active_handle;
}

uint32_t async_task_ex(size_t heapsize, param_func_t fn, uint32_t num_of_args, ...) {
	va_list ap;

	va_start(ap, num_of_args);
	param_t params = data_ex(num_of_args, ap);
	va_end(ap);

	return task_push(create_task(heapsize, (data_func_t)fn, params, false));
}

uint32_t async_task(param_func_t fn, uint32_t num_of_args, ...) {
	va_list ap;

	va_start(ap, num_of_args);
	param_t params = data_ex(num_of_args, ap);
	va_end(ap);

	return task_push(create_task(Kb(18), (data_func_t)fn, params, false));
}

static EVENTS_INLINE task_group_t *create_task_group(void) {
	task_group_t *wg = events_calloc(1, sizeof(task_group_t));
	wg->group = array();
	wg->threaded = false;
	wg->taken = false;
	wg->capacity = 0;
	wg->count = 0;
	wg->type = DATA_TASKGROUP;
	return wg;
}

EVENTS_INLINE task_group_t *task_group(void) {
	tasks_t *t = active_task();
	t->group_active = true;
	t->group_finish = false;
	t->task_group = create_task_group();

	return t->task_group;
}

static void tasks_poster(waitgroup_t wg) {
	atomic_thread_fence(memory_order_seq_cst);
	if (__thrd()->is_main) {
		tasks_t *t = active_task();
		int c, i, k;
		if (t->group_finish && t->task_group && !t->task_group->taken && t->task_group->threaded) {
			t->task_group->taken = true;
			for (i = 0; i < $size(sys_event.cpu_index); i++) {
				k = sys_event.cpu_index[i].u_int;
				events_deque_t *q = sys_event.local[k];
				for (c = 0; c < wg->capacity; c++) {
					tasks_t *t = (tasks_t *)$pop(wg->group).object;
					t->tid = k;
					$append(q->jobs, t);
				}
				q->tasks = wg;
			}

			for (i = 0; i < $size(sys_event.cpu_index); i++) {
				events_deque_t *q = sys_event.local[(sys_event.cpu_index[i].u_int)];
				atomic_flag_test_and_set(&q->started);
			}
		}
	}
}

uint32_t go(param_func_t fn, size_t num_of_args, ...) {
	if (is_data(sys_event.cpu_index) && $size(sys_event.cpu_index) > 0) {
		va_list ap;

		va_start(ap, num_of_args);
		param_t params = data_ex(num_of_args, ap);
		va_end(ap);

#if defined(_WIN32) && defined(USE_FIBER)
		return task_push(create_task(Kb(9), (data_func_t)fn, params, true));
#else
		return task_push(create_task(Kb(18), (data_func_t)fn, params, true));
#endif
	}

	panic("MUST call `events_tasks_pool()` first!");
	return TASK_ERRED;
}

EVENTS_INLINE bool is_taskgroup(void *params) {
	return data_type(params) == DATA_TASKGROUP;
}

EVENTS_INLINE bool is_waitgroup(void *params) {
	return data_type(params) == DATA_TASKGROUP && ((waitgroup_t)params)->threaded;
}

EVENTS_INLINE events_t *tasks_loop(void) {
	return __thrd()->loop;
}

waitgroup_t waitgroup(uint32_t capacity) {
	atomic_thread_fence(memory_order_seq_cst);
	waitgroup_t wg = NULL;
	if (is_data(sys_event.cpu_index) && $size(sys_event.cpu_index) > 0) {
		size_t i, active_cores = $size(sys_event.cpu_index), resized = capacity / (active_cores + 1);
		wg = task_group();
		if ($capacity(wg->group) < capacity)
			$reserve(wg->group, capacity + 1);

		wg->threaded = true;
		wg->capacity = resized;
		wg->count = active_cores;

		for (i = 0; i < active_cores; i++) {
			events_deque_t *q = sys_event.local[sys_event.cpu_index[i].u_int];
			if ($capacity(q->jobs) < resized) {
				atomic_lock($lock(q->jobs));
				$reserve(q->jobs, resized + 1);
				atomic_unlock($lock(q->jobs));
			}
		}
	}

	return wg;
}

static EVENTS_INLINE void group_result_set(array_t wgr, tasks_t *co) {
	if (is_data(wgr) && is_ptr_usable(co->results)) {
		atomic_lock($lock(wgr));
		$append_unsigned(wgr, co->rid);
		atomic_unlock($lock(wgr));
	}
}

EVENTS_INLINE size_t tasks_count(task_group_t *wg) {
	if (is_taskgroup(wg))
		return $size(wg->group);

	return 0;
}

static void __thrd_waitfor(events_deque_t *q) {
	tasks_t *co, *t = active_task();
	waitgroup_t wg = q->tasks;
	tasklist_t *l = __thrd()->run_queue;
	array_t wgr = wg->results;
	bool is_sleeping = false;
	q->tasks = NULL;

	foreach(task in q->jobs) {
		co = (tasks_t *)task.object;
		co->ready = true;
		if (!co->taken) {
#if defined(_WIN32) && defined(USE_FIBER)
			coroutine_t *worker = (coroutine_t *)co;
			worker->fiber = CreateFiber((co->stack_size - sizeof(_results_data_t)), fiber_thunk, (void *)task_func);
#endif
			co->taken = true;
			__thrd()->task_count++;
		}
		enqueue(l, co);
	}

	yield_task();
	while ($size(q->jobs) > 0) {
		foreach(group in q->jobs) {
			co = (tasks_t *)task.object;
			if (task_is_terminated(co)) {
				$remove(q->jobs, igroup);
				if (co->results != NULL)
					group_result_set(wgr, co);

				co->waiting = false;
				task_delete(co);
			} else {
				if (co->status == TASK_NORMAL) {
					enqueue(l, co);
				} else if (co->status == TASK_SLEEPING) {
					is_sleeping = true;
					co->sleeping = __thrd()->running;
					suspend_task();
				}

				tasks_info(t, 1);
				yield_task();
			}
		}
		igroup = 0;
	}

	__thrd()->task_count--;
	atomic_lock($lock(wg->group));
	wg->count--;
	atomic_unlock($lock(wg->group));
}

array_t waitfor(waitgroup_t wg) {
	if (!__thrd()->started && __thrd()->is_main) {
		__thrd()->started = true;
		task_name("waitgroup_task #%d", (int)task_id());
	}

	tasks_t *worker, *t = active_task();
	tasklist_t *l = __thrd()->run_queue;
	array_t wgr = NULL;
	bool is_sleeping = false;
	if (t->group_active && t->task_group == wg && t->task_group->threaded) {
		t->group_active = false;
		t->group_finish = true;
		wgr = array();
		wg->results = wgr;
		tasks_poster(wg);
		foreach(co in wg->group) {
			worker = (tasks_t *)co.object;
			worker->ready = true;
			if (!worker->taken) {
#if defined(_WIN32) && defined(USE_FIBER)
				coroutine_t *work = (coroutine_t *)worker;
				work->fiber = CreateFiber((worker->stack_size - sizeof(_results_data_t)), fiber_thunk, (void *)task_func);
#endif
				worker->taken = true;
				__thrd()->task_count++;
			}
			enqueue(l, worker);
		}

		yield_task();
		while ($size(wg->group) > 0) {
			foreach(task in wg->group) {
				worker = (tasks_t *)task.object;
				if (task_is_terminated(worker)) {
					$remove(wg->group, itask);
					if (worker->results != NULL)
						group_result_set(wgr, worker);

					worker->waiting = false;
					task_delete(worker);
				} else {
					if (worker->status == TASK_NORMAL) {
						enqueue(l, worker);
					} else if (worker->status == TASK_SLEEPING) {
						is_sleeping = true;
						worker->sleeping = __thrd()->running;
						suspend_task();
					}

					tasks_info(t, 1);
					yield_task();
				}
			}
			itask = 0;
		}

		while ((int)wg->count > 0)
			yield_task();

		if ($size(wgr) == 0) {
			$delete(wgr);
			wgr = NULL;
		} else {
			defer_free(wgr);
		}

		$delete(wg->group);
		wg->results = NULL;
		wg->group = NULL;
		memset(wg, DATA_INVALID, sizeof(data_types));
		events_free(wg);
		if (!is_sleeping)
			__thrd()->task_count--;
	}

	return wgr;
}

array_t tasks_wait(task_group_t *wg) {
	if (!__thrd()->started && __thrd()->is_main) {
		__thrd()->started = true;
		task_name("main_task");
	}

	tasks_t *worker, *t = active_task();
	tasklist_t *l = __thrd()->run_queue;
	array_t wgr = NULL;
	bool is_sleeping = false;
	if (t->group_active && t->task_group == wg && !t->task_group->threaded) {
		t->group_active = false;
		t->group_finish = true;
		wgr = array();
		yield_task();
		while ($size(wg->group) > 0) {
			foreach(task in wg->group) {
				worker = (tasks_t *)task.object;
				if (task_is_terminated(worker)) {
					$remove(wg->group, itask);
					if (worker->results != NULL)
						$append_unsigned(wgr, worker->rid);

					worker->waiting = false;
					task_delete(worker);
				} else {
					if (worker->status == TASK_NORMAL) {
						enqueue(l, worker);
					} else if (worker->status == TASK_SLEEPING) {
						is_sleeping = true;
						worker->sleeping = __thrd()->running;
						suspend_task();
					}

					tasks_info(t, 1);
					yield_task();
				}
			}
			itask = 0;
		}

		if ($size(wgr) == 0) {
			$delete(wgr);
			wgr = NULL;
		} else {
			defer_free(wgr);
		}

		$delete(wg->group);
		wg->group = NULL;
		memset(wg, DATA_INVALID, sizeof(data_types));
		events_free(wg);
		if (!is_sleeping)
			__thrd()->task_count--;
	}

	return wgr;
}

EVENTS_INLINE void async_run(events_t *loop) {
	__thrd()->loop = loop;
	int status;
	do {
		if (!__thrd()->task_count || (status = tasks_schedulering(true)) == TASK_ERRED)
			break;
	} while (is_ptr_usable(loop) || (!events_shutdown_set && !events_got_signal));
}

EVENTS_INLINE void suspend_task(void) {
	task_yielding(__thrd()->current_handle);
}

EVENTS_INLINE void yield_task(void) {
	tasks_t *t = __thrd()->running;
	tasklist_t *l = __thrd()->run_queue;
	t->ready = true;
	enqueue(l, t);
	suspend_task();
	if (task_id() == 1 && __thrd()->sleep_count == 1) {
#ifndef _WIN32
		__thrd()->active_timer++;
#endif
		task_sleep_switch();
#ifndef _WIN32
		__thrd()->active_timer--;
#endif
	}
}

EVENTS_INLINE void tasks_stack_check(int n) {
	tasks_t *t = __thrd()->running;
	if ((char *)&t <= (char *)t->stack_base
		|| (char *)&t - (char *)t->stack_base < 256 + n
		|| t->magic_number != TASK_MAGIC_NUMBER) {
		fprintf(stderr, "task stack overflow: &t=%p stack=%p n=%d\n", &t, t->stack_base, 256 + n);
		abort();
	}
}

#ifdef _WIN32
EVENTS_INLINE size_t tasks_cpu_count(void) {
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	return (size_t)system_info.dwNumberOfProcessors;
}
#elif (defined(__linux__) || defined(__linux))
#include <sched.h>
EVENTS_INLINE size_t tasks_cpu_count(void) {
	cpu_set_t cpuset;
	sched_getaffinity(0, sizeof(cpuset), &cpuset);
	return CPU_COUNT(&cpuset);
}
#elif defined(__APPLE__) || defined(__MACH__)
EVENTS_INLINE size_t tasks_cpu_count(void) {
	return sysconf(_SC_NPROCESSORS_CONF);
}
#else
EVENTS_INLINE size_t tasks_cpu_count(void) {
	return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif

void task_name(char *fmt, ...) {
	va_list args;
	tasks_t *t = __thrd()->running;
	va_start(args, fmt);
	vsnprintf(t->name, sizeof(t->name), fmt, args);
	va_end(args);
}

/* Collect `tasks` with references preventing immediate cleanup. */
static EVENTS_INLINE void task_gc(tasks_t *co) {
	atomic_lock(&sys_event.lock);
	if (sys_event.gc == NULL)
		sys_event.gc = array();

	if (co->magic_number == TASK_MAGIC_NUMBER)
		$append(sys_event.gc, co);

	atomic_unlock(&sys_event.lock);
}

static int tasks_schedulering(bool do_io) {
	bool has_task = false;
	tasks_t *t = task_dequeue(__thrd()->run_queue);
	if (t != NULL) {
		has_task = true;
		t->ready = false;
		t->cycles++;

		__thrd()->num_others_ran++;
		__thrd()->running = t;
		if (do_io && __thrd()->loop != NULL) {
			__thrd()->in_callback++;
			events_once(__thrd()->loop, 0);
			__thrd()->in_callback--;
		}

		if (!t->halt)
			task_switch(t);
	}

	__thrd()->running = NULL;
	if (t && t->halt) {
		if (!t->system) {
			--__thrd()->task_count;
		}

		if (!t->waiting && !t->referenced) {
			task_delete(t);
		} else if (t->referenced) {
			task_gc(t);
		}
	}

	return has_task ? 0 : TASK_ERRED;
}

static bool task_take(events_deque_t *queue) {
	int i, available;
	tasklist_t *l = __thrd()->run_queue;
	bool work_taken = false;
	atomic_thread_fence(memory_order_seq_cst);
	if ((available = (int)atomic_load_explicit(&queue->available, memory_order_relaxed)) > 0) {
		for (i = 0; i < available; i++) {
			tasks_t *t = deque_steal(queue);
			if (t == TASK_ABORT_T) {
				--i;
				continue;
			} else if (t == TASK_EMPTY_T)
				break;

			atomic_fetch_sub(&queue->available, 1);
			t->ready = true;
#if defined(_WIN32) && defined(USE_FIBER)
			if (!t->taken) {
				coroutine_t *worker = (coroutine_t *)t;
				worker->fiber = CreateFiber((t->stack_size - sizeof(_results_data_t)), fiber_thunk, (void *)task_func);
			}
#endif
			enqueue(l, t);
			if (!t->taken) {
				t->taken = true;
				__thrd()->task_count++;
			}

			work_taken = true;
		}
	}

	return work_taken;
}

void thread_result_set(os_request_t *p, void *res) {
	atomic_lock(&p->mutex);
	if (res != NULL) {
		if (is_data(res)) {
			p->result->value.object = data_copy((array_t)p->result->extended, res);
		} else {
			p->result->value.object = res;
		}
	}
	atomic_unlock(&p->mutex);
	atomic_flag_test_and_set(&p->done);
}

static void enqueue_tasks(tasks_t *t) {
	atomic_thread_fence(memory_order_seq_cst);
	atomic_lock(&sys_event.lock);
	events_deque_t *queue = sys_event.local[t->tid];
	atomic_unlock(&sys_event.lock);
	deque_push(queue, t);
	atomic_fetch_add(&queue->available, 1);
}

static void *__tasks_pool_main(param_t args) {
	events_deque_t *queue = args[0].object;
	events_t *loop = args[1].object;
	__thrd()->started = true;
	task_name("tasks_pool_main #%d", (int)__thrd()->thrd_id);

	while (!atomic_flag_load_explicit(&queue->shutdown, memory_order_relaxed)) {
		tasks_info(active_task(), 1);
		task_take(queue);
		if (queue->tasks != NULL)
			__thrd_waitfor(queue);
		else if (__thrd()->task_count > 1 || __thrd()->loop != NULL)
			yield_task();
		else
			break;
	}

	__thrd()->loop = NULL;
	return 0;
}

static int __tasks_pool_wrapper(void *arg) {
	os_tasks_t *work = (os_tasks_t *)arg;
	events_deque_t *queue = work->queue;
	events_t *loop = queue->loop;
	uint32_t status, res = TASK_ERRED, tid = work->id;

	__thrd_init(false, tid);
	while (!atomic_flag_load_explicit(&queue->started, memory_order_relaxed))
		;

	__thrd()->loop = loop;
	if ((int)async_task_ex(Kb(32), __tasks_pool_main, 2, queue, loop) > 0) {
		__thrd()->pool = work->pool;
		res = 0;
		do {
			if (!__thrd()->task_count || atomic_flag_load_explicit(&queue->shutdown, memory_order_relaxed)
				|| tasks_schedulering(true) == TASK_ERRED)
				break;
		} while (__thrd()->loop != NULL);
		events_destroy(loop);
		__thrd()->pool = NULL;
	}

	$delete(queue->jobs);
	queue->jobs = NULL;
	if (__thrd()->sleep_handle != NULL
		&& __thrd()->sleep_handle->magic_number == TASK_MAGIC_NUMBER) {
#if defined(_WIN32) && defined(USE_FIBER)
		DeleteFiber(__thrd()->sleep_handle->type->fiber);
#endif
		events_free(__thrd()->sleep_handle);
		__thrd()->sleep_handle = NULL;
	}

	events_free(arg);
	os_exit(res);
	return res;
}

events_t *events_thread_init(void) {
	if (__thrd()->loop == NULL)
		events_add_pool(events_create(sys_event.cpu_count));

	int i = __thrd()->loop->loop_id;
	for (i; i < sys_event.cpu_count; i++)
		events_tasks_pool(events_create(sys_event.cpu_count));

	return __thrd()->loop;
}

int events_tasks_pool(events_t *loop) {
	events_deque_t **local = sys_event.local;
	os_tasks_t *t_work = NULL;
	int save_err = errno, index = loop->loop_id;
	errno = EINVAL;
	if (index <= sys_event.cpu_count && local[index] == NULL) {
		errno = ENOMEM;
		if ((local[index] = (events_deque_t *)events_malloc(sizeof(events_deque_t)))) {
			deque_init(local[index], sys_event.queue_size);
			if ((t_work = events_calloc(1, sizeof(os_tasks_t)))) {
				t_work->id = (int)index;
				t_work->queue = local[index];
				t_work->queue->jobs = array();
				t_work->queue->loop = loop;
				t_work->pool = __thrd()->pool;
				t_work->type = DATA_PTR;
				local[index]->thread = os_create(__tasks_pool_wrapper, (void *)t_work);
				if (local[index]->thread != OS_NULL) {
					if (sys_event.cpu_index == NULL)
						sys_event.cpu_index = array();

					errno = save_err;
					$append_unsigned(sys_event.cpu_index, index);
					return 0;
				}
				errno = EAGAIN;
			}
		}
	} else if (is_ptr_usable(local[index])) {
		errno = save_err;
		return 0;
	}

	return TASK_ERRED;
}

static int __threads_wrapper(void *arg) {
	os_worker_t *work = (os_worker_t *)arg;
	events_deque_t *queue = work->queue;
	values_t res[1] = {0};
	int status = 0, tid = work->id;

	while (!atomic_flag_load(&queue->started))
		;

	__thrd()->pool = work;
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
	__thrd()->pool = NULL;
	$delete(queue->jobs);
	events_free(arg);
	os_exit(status);
	return status;
}

os_worker_t *events_add_pool(events_t *loop) {
	events_deque_t **local = sys_event.local;
	os_worker_t *f_work = NULL;
	int index = loop->loop_id;
	if (index <= sys_event.cpu_count && local[index] == NULL) {
		if ((local[index] = (events_deque_t *)events_malloc(sizeof(events_deque_t)))) {
			deque_init(local[index], sys_event.queue_size);
			if ((f_work = events_calloc(1, sizeof(os_worker_t)))) {
				atomic_flag_clear(&f_work->mutex);
				f_work->id = (int)index;
				f_work->queue = local[index];
				f_work->queue->jobs = array();
				f_work->queue->loop = loop;
				f_work->last_fd = TASK_ERRED;
				f_work->type = DATA_PTR;
				local[index]->thread = os_create(__threads_wrapper, (void *)f_work);
				if (local[index]->thread == OS_NULL) {
					events_free(f_work);
					f_work = NULL;
				}
			}
		}
	}

	if (f_work == NULL && __thrd()->pool)
		return __thrd()->pool;

	return f_work;
}
