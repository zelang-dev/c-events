#include "events_internal.h"
#ifdef _WIN32
static CRITICAL_SECTION events_lock;
#define events_block	EnterCriticalSection(&events_lock)
#define events_unblock	LeaveCriticalSection(&events_lock)
#else
static sigset_t events_lock, events_lock_all;
#define events_block	sigfillset(&events_lock);	\
    pthread_sigmask(SIG_SETMASK, &events_lock, &events_lock_all)
#define events_unblock	pthread_sigmask(SIG_SETMASK, &events_lock_all, NULL)
#endif

#define EVENTS_ARGS_LENGTH 32768

static char EVENTS_ARGS[EVENTS_ARGS_LENGTH] = {0};
static volatile bool events_startup_set = false;
static volatile bool events_shutdown_set = false;
static int events_execute(events_t *loop, int max_wait);
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

EVENTS_INLINE bool events_is_shutdown(void) {
	return events_shutdown_set;
}

void events_set_destroy(void) {
	events_block;
	sys_event.loop_destroyed = true;
	events_unblock;
}

EVENTS_INLINE bool events_is_destroy(void) {
	return sys_event.loop_destroyed;
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
	sys_event.fds[fd].events = events & EVENTS_READWRITE;
}

EVENTS_INLINE char *str_cpy(char *dest, const char *src, size_t len) {
	return (char *)memcpy(dest, src, (len ? len : strlen(src)));
}

char *str_cat(int num_args, ...) {
	va_list ap;
	size_t strsize = 0;
	char *res = NULL;
	int i;

	if (num_args > 0) {
		va_start(ap, num_args);
		for (i = 0; i < num_args; i++)
			strsize += strlen(va_arg(ap, char *));
		va_end(ap);

		if ((res = events_calloc(1, strsize + 1)) != NULL) {
			strsize = 0;
			va_start(ap, num_args);
			for (i = 0; i < num_args; i++) {
				char *s = va_arg(ap, char *);
				str_cpy(res + strsize, s, 0);
				strsize += strlen(s);
			}
			va_end(ap);
		}
	}

	return res;
}

static int _str_append(size_t offset, const char *str, size_t len) {
	strncat(EVENTS_ARGS + offset, str, len);
	return offset + len;
}

char *str_cat_argv(int argc, char **argv, int start, char *delim) {
	int i, j, len = 0;
	for (i = start; i < argc; i++) {
		len += strlen(argv[i]) + 1;
	}

	char *str = EVENTS_ARGS;
	for (i = start, j = 0; i < argc; ++i) {
		if (i > start)
			j = _str_append(j, delim, 1);
		j = _str_append(j, argv[i], strlen(argv[i]));
	}

	str[(sizeof(char) * len) - 1] = '\0';
	return str;
}

char *str_swap(const char *haystack, const char *needle, const char *swap) {
	if (!haystack || !needle || !swap)
		return NULL;

	char *result;
	size_t i, cnt = 0;
	size_t newWlen = strlen(swap);
	size_t oldWlen = strlen(needle);

	for (i = 0; haystack[i] != '\0'; i++) {
		if (strstr(&haystack[i], needle) == &haystack[i]) {
			cnt++;
			i += oldWlen - 1;
		}
	}

	if (cnt == 0)
		return NULL;

	result = (char *)events_calloc(1, i + cnt * (newWlen - oldWlen) + 1);
	i = 0;
	while (*haystack) {
		if (strstr(haystack, needle) == haystack) {
			str_cpy(&result[i], swap, newWlen);
			i += newWlen;
			haystack += oldWlen;
		} else {
			result[i++] = *haystack++;
		}
	}

	result[i] = '\0';
	return result;
}

char **str_slice(const char *s, const char *delim, int *count) {
    if ((void *)s == NULL)
		return NULL;

	if ((void *)delim == NULL)
		delim = " ";

	size_t ptrsSize, nbWords = 1, sLen = strlen(s), delimLen = strlen(delim);
	if (sLen == 0)
		return NULL;

    void *data;
    char **ptrs, *_s = (char *)s;
    while ((_s = strstr(_s, delim))) {
        _s += delimLen;
        ++nbWords;
    }

    ptrsSize = (nbWords + 1) * sizeof(char *);
    ptrs = data = events_calloc(1, ptrsSize + sLen + 1);

    if (data) {
        *ptrs = _s = str_cpy((char *)data + ptrsSize, s, sLen);
        if (nbWords > 1) {
            while ((_s = strstr(_s, delim))) {
                *_s = '\0';
                _s += delimLen;
                *++ptrs = _s;
            }
        }

        *++ptrs = NULL;
        if (count)
            *count = (int)nbWords;
    }

    return data;
}

int str_pos(const char *text, char *pattern) {
	size_t c, d, e, text_length, pattern_length, position = -1;
	if (pattern == NULL || (void *)text == NULL)
		return -1;

	text_length = strlen(text);
	pattern_length = strlen(pattern);

	if (pattern_length > text_length)
		return -1;

	for (c = 0; c <= text_length - pattern_length; c++) {
		position = e = c;
		for (d = 0; d < pattern_length; d++)
			if (pattern[d] == text[e])
				e++;
			else
				break;

		if (d == pattern_length)
			return (int)position;
	}

	return -1;
}

EVENTS_INLINE bool str_has(const char *text, char *pattern) {
	return str_pos(text, pattern) >= 0;
}

EVENTS_INLINE int events_init(int max_fd) {
	if (events_shutdown_set || events_startup_set)
		return 0;

	events_startup_set = true;
#ifdef _WIN32
	InitializeCriticalSection(&events_lock);
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif
	assert(!EVENTS_IS_INITD);
	assert(max_fd > 0);

	if (os_init() == -1) {
		return -1;
	}

	if ((sys_event.fds = (events_fd_t *)events_memalign(sizeof(events_fd_t) * max_fd,
		&sys_event._fds_free_addr, 1)) == NULL) {
		os_shutdown();
		return -1;
	}

	atexit(events_deinit);
	sys_event.max_fd = max_fd;
	sys_event.num_loops = 0;
	sys_event.timeout_vec_size = EVENTS_RND_UP(sys_event.max_fd, EVENTS_SIMD_BITS) / EVENTS_SHORT_BITS;
	sys_event.timeout_vec_of_vec_size = EVENTS_RND_UP(sys_event.timeout_vec_size, EVENTS_SIMD_BITS)
		/ EVENTS_SHORT_BITS;

#if defined(_WIN32)
	sys_event.listenType = FD_UNUSED;
	QueryPerformanceFrequency(&sys_event.timer);
#elif defined(__APPLE__) || defined(__MACH__)
	mach_timebase_info(&sys_event.timer);
#endif
	return 0;
}

EVENTS_INLINE void events_deinit(void) {
	if (events_shutdown_set)
		return;

	if (EVENTS_IS_INITD)
		return;

	events_shutdown_set = true;
	events_free(sys_event._fds_free_addr);
	sys_event.fds = NULL;
	sys_event._fds_free_addr = NULL;
	sys_event.max_fd = 0;
	sys_event.num_loops = 0;

	os_shutdown();
#ifdef _WIN32
	WSACleanup();
	DeleteCriticalSection(&events_lock);
#endif
}

EVENTS_INLINE int events_set_nonblocking(sockfd_t fd) {
#ifdef _WIN32
	unsigned long flag = 1;
	return ioctlsocket(fd, FIONBIO, &flag);
#else
	return fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
}

EVENTS_INLINE void events_set_timeout(sockfd_t sfd, int secs) {
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
	events_block;
	events_fd_t *target = sys_event.fds + fd;
	events_unblock;
	return target;
}

EVENTS_INLINE int events_add(events_t *loop, sockfd_t sfd, int event, int timeout_in_secs,
	events_cb callback, void *cb_arg) {
	events_fd_t *target;
	fd_types type = FD_UNKNOWN;
	int sig_idx, fd = socket2fd(sfd);
	bool is_io = false;

	if (!EVENTS_IS_INITD_AND_FD_IN_RANGE(fd)) { return -1; }

	target = events_target(fd);
	if (event == EVENTS_SIGNAL) {
		if ((sig_idx = events_add_signal(fd, callback, cb_arg)) >= 0) {
			loop->signal_set = events_signals();
			loop->active_signals++;
			loop->signal_set[sig_idx].loop = loop;
			target->loop = loop;
			target->signal_idx = sig_idx;
			target->signal_set = true;
			return 0;
		}

		return -1;
	}

	assert(target->loop_id == 0);
	target->is_iodispatch = false;
	target->backend_used = false;
#ifdef _WIN32
	if (valid_fd(fd) || !is_socket(fd)) {
		is_io = true;
		if (valid_fd(fd)) {
			target->_backend = (intptr_t)get_fd(fd);
		} else {
			target->backend_used = true;
			target->_backend = (intptr_t)new_fd(FD_FILE_ASYNC, fd, -1);
		}

		loop->active_io++;
		target->is_iodispatch = true;
	}
#endif
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

EVENTS_INLINE int events_del(sockfd_t sfd) {
	events_fd_t *target = NULL;
	events_t *loop = NULL;
	sys_signal_t *signal_set = NULL;
	int fd = socket2fd(sfd);

	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(fd));
	target = events_target(fd);
	if (target->signal_set) {
		signal_set = events_signals();
		if (signal_set[target->signal_idx].sig == fd
			&& signal_set[target->signal_idx].is_running) {
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

	if (!target->is_iodispatch && events_update_internal(loop, fd, EVENTS_DEL) != 0)
		return -1;

	events_set_timeout(fd, 0);
	loop->active_descriptors--;
	target->loop_id = 0;
	target->loop = NULL;
	return 0;
}

EVENTS_INLINE bool events_is_active(events_t *loop, sockfd_t sfd) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	if (EVENTS_IS_INITD)
		return false;

	return loop != NULL
		? sys_event.fds[socket2fd(sfd)].loop_id == loop->loop_id
		: sys_event.fds[socket2fd(sfd)].loop_id != 0;
}

EVENTS_INLINE bool events_is_running(events_t *loop) {
	return (events_shutdown_set || sys_event.loop_destroyed || events_got_signal)
		? false
		: (int)loop->active_descriptors > 0
		|| (int)loop->active_timers > 0
		|| (int)loop->active_io > 0
		|| (int)loop->active_signals > 0;
}

EVENTS_INLINE int events_get_event(events_t *loop __attribute__((unused)), sockfd_t sfd) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	return sys_event.fds[socket2fd(sfd)].events & EVENTS_READWRITE;
}

int events_set_event(sockfd_t sfd, int event) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	events_t *loop = events_loop(sfd);
	bool is_io = false;
#ifdef _WIN32
	if ((is_io = (valid_fd(sfd) || !is_socket(sfd)))) {
		if (sys_event.fds[socket2fd(sfd)].events != event)
			return -1;

		events_update_polling(loop, socket2fd(sfd), event);
		return 0;
	}
#endif
	if (!is_io && sys_event.fds[socket2fd(sfd)].events != event
		&& events_update_internal(loop, socket2fd(sfd), event) != 0) {
		return -1;
	}

	return 0;
}

EVENTS_INLINE events_cb events_get_callback(events_t *loop __attribute__((unused)),
	sockfd_t sfd, void **cb_arg) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	if (cb_arg != NULL) {
		*cb_arg = sys_event.fds[socket2fd(sfd)].cb_arg;
	}

	return sys_event.fds[socket2fd(sfd)].callback;
}

EVENTS_INLINE void events_set_callback(events_t *loop __attribute__((unused)),
	sockfd_t sfd, events_cb callback, void **cb_arg) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	if (cb_arg != NULL) {
		sys_event.fds[socket2fd(sfd)].cb_arg = *cb_arg;
	}

	sys_event.fds[socket2fd(sfd)].callback = callback;
}

EVENTS_INLINE int events_once(events_t *loop, int max_wait) {
	loop->now = time(NULL);
	if (max_wait > loop->timeout.resolution) {
		max_wait = loop->timeout.resolution;
	}

	if (events_execute(loop, max_wait) != 0) {
		return -1;
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
	loop->loop_id = ++sys_event.num_loops;
	loop->active_descriptors = 0;
	loop->active_io = 0;
	loop->active_timers = 0;
	loop->active_signals = 0;
	loop->signal_set = NULL;
	memset(loop->timers, 0, sizeof(loop->timers));
	assert(EVENTS_TOO_MANY_LOOPS);
	if ((loop->timeout.vec_of_vec = (short *)events_memalign(
		(sys_event.timeout_vec_of_vec_size + sys_event.timeout_vec_size) * sizeof(short) * EVENTS_TIMEOUT_VEC_SIZE,
		&loop->timeout._free_addr, 1)) == NULL) {
		--sys_event.num_loops;
		return -1;
	}

	loop->timeout.vec = loop->timeout.vec_of_vec + sys_event.timeout_vec_of_vec_size * EVENTS_TIMEOUT_VEC_SIZE;
	loop->timeout.base_idx = 0;
	loop->timeout.base_time = time(NULL);
	loop->timeout.resolution = EVENTS_RND_UP(max_timeout, EVENTS_TIMEOUT_VEC_SIZE) / EVENTS_TIMEOUT_VEC_SIZE;
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

EVENTS_INLINE int events_timeofday(struct timeval *tp, struct timezone *tz) {
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
	struct timeval lasttime;
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

EVENTS_INLINE events_t *events_loop(sockfd_t sfd) {
	assert(EVENTS_IS_INITD_AND_FD_IN_RANGE(socket2fd(sfd)));
	events_fd_t *target = events_target(socket2fd(sfd));
	return (target->signal_set)
		? events_signals()[target->signal_idx].loop : target->loop;
}

EVENTS_INLINE events_t *events_actor_loop(actor_t *actor) {
	return actor->loop;
}

/*static EVENTS_INLINE void events_enqueue(timerlist_t *l, actor_t *t) {
	if (l->tail) {
		l->tail->next = t;
		t->prev = l->tail;
	} else {
		l->head = t;
		t->prev = NULL;
	}

	l->tail = t;
	t->next = NULL;
}*/

static EVENTS_INLINE void events_dequeue(timerlist_t *l, actor_t *t) {
	if (t->prev)
		t->prev->next = t->next;
	else
		l->head = t->next;

	if (t->next)
		t->next->prev = t->prev;
	else
		l->tail = t->prev;
}

static int events_execute(events_t *loop, int max_wait) {
	int ms;
	actor_t *t;
	size_t now;

	if ((t = loop->timers->head) == NULL) {
		ms = max_wait;
	} else {
		now = events_nsec();
		if ((now >= t->alarmtime) || (now + 1 * 1000 * 1000 * 1000LL >= t->alarmtime))
			ms = 0;
		else
			ms = max_wait;
	}

	/* wait for events */
	if (loop->active_io)
		os_iodispatch((ms ? ms : 1));

	if (events_poll_once_internal(loop, (loop->active_io ? 0 : ms)) != 0) {
		return -1;
	}

	now = events_nsec();
	while ((t = loop->timers->head) && now >= t->alarmtime) {
		events_dequeue(loop->timers, t);
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

EVENTS_INLINE filefd_t mkfifo_handle(void) {
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
