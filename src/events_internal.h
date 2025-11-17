#ifndef _EVENTS_INTERNAL_H
#define _EVENTS_INTERNAL_H

#include <events.h>

#if defined(USE_DEBUG)
#   include <assert.h>
#else
#   define assert
#endif

#if defined(_MSC_VER)
#   define EVENTS_INLINE __forceinline
#elif defined(__GNUC__)
#	if defined(__STRICT_ANSI__) || !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#		define EVENTS_INLINE __inline__ __attribute__((always_inline))
#	else
#		define EVENTS_INLINE inline __attribute__((always_inline))
#	endif
#elif defined(__WATCOMC__) || defined(__DMC__)
#	define EVENTS_INLINE __inline
#else
#	define EVENTS_INLINE
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	max_event_sig = 32
};

struct sys_signal_s {
	int sig;
	bool is_running;
	sig_cb proc;
	void *data;
	events_t *loop;
};

struct sys_events_s {
  	/* read only */
	events_fd_t *fds;
	void *_fds_free_addr;
	int max_fd;
	int num_loops;
	size_t timeout_vec_size; /* #of elements in events_t.timeout.vec[0] */
	size_t timeout_vec_of_vec_size; /* ... in timeout.vec_of_vec[0] */
#if defined(_WIN32)
	LARGE_INTEGER timer;
	FILE_TYPE listenType;
	int listenfd;
#elif defined(__APPLE__) || defined(__MACH__)
	mach_timebase_info_data_t timer;
#endif
	filefd_t pHandle;
	bool loop_destroyed;
	bool loop_signaled;
	char pNamed[FILENAME_MAX];
};

struct actors_s {
	int repeating;
	size_t alarmtime;
	actor_cb actor;
	void *args;
	actor_t *next;
	actor_t *prev;
	events_t *loop;
};

struct timerlist_s {
	actor_t *head;
	actor_t *tail;
};

struct events_fd_s {
  /* use accessors! */
  /* TODO adjust the size to match that of a cache line */
	events_cb callback;
	void *cb_arg;
	events_t *loop;
	events_id_t loop_id;
	char events;
	unsigned char timeout_idx; /* EVENTS_TIMEOUT_IDX_UNUSED if not used */
	intptr_t _backend; /* can be used by backends (never modified by core) */
	int signal_idx;
	bool signal_set;
	bool is_iodispatch;
	bool backend_used;
};

struct events_loop_s {
	/* read only */
	events_id_t loop_id;
	size_t active_signals;
	size_t active_descriptors;
	size_t active_io;
	size_t active_timers;
	struct {
		short *vec;
		short *vec_of_vec;
		size_t base_idx;
		time_t base_time;
		int resolution;
		void *_free_addr;
	} timeout;
	time_t now;
	sys_signal_t *signal_set;
	timerlist_t timers[1];
};

void events_set_destroy(void);
int events_add_signal(int sig, sig_cb proc, void *data);
void events_del_signal(int sig, int i);
events_fd_t *events_target(int fd);
int events_id(events_t *loop);
int events_init_loop_internal(events_t *loop, int max_timeout);
void events_deinit_loop_internal(events_t *loop);
void events_handle_timeout_internal(events_t *loop);
void *events_memalign(size_t sz, void **orig_addr, int clear);
/* internal: updates events to be watched (defined by each backend) */
int events_update_internal(events_t *loop, int fd, int events);

/* internal: poll once and call the handlers (defined by each backend) */
int events_poll_once_internal(events_t *loop, int max_wait);

void *events_calloc(size_t count, size_t size);
void *events_malloc(size_t size);
void *events_realloc(void *ptr, size_t size);
void events_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* _EVENTS_INTERNAL_H */
