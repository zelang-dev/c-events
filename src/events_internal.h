#ifndef _EVENTS_INTERNAL_H
#define _EVENTS_INTERNAL_H

#include <events.h>
#include <catomics.h>

#if defined(USE_DEBUG)
#   include <assert.h>
#else
#   define assert
#endif

#if defined(_MSC_VER)
  #undef  MPROTECT
  #define MPROTECT
  #define section(name) __declspec(allocate("." #name))
#elif defined(__APPLE__)
  #define section(name) __attribute__((section("__TEXT,__" #name)))
#else
  #define section(name) __attribute__((section("." #name "#")))
#endif

#if !defined(alignas)
  #if defined(__STDC__) /* C Language */
    #if defined(_MSC_VER) /* Don't rely on MSVC's C11 support */
      #define alignas(bytes) __declspec(align(bytes))
    #elif __STDC_VERSION__ >= 201112L /* C11 and above */
      #include <stdalign.h>
    #elif defined(__clang__) || defined(__GNUC__) /* C90/99 on Clang/GCC */
      #define alignas(bytes) __attribute__ ((aligned (bytes)))
    #else /* Otherwise, we ignore the directive (user should provide their own) */
      #define alignas(bytes)
    #endif
  #elif defined(__cplusplus) /* C++ Language */
    #if __cplusplus < 201103L
      #if defined(_MSC_VER)
        #define alignas(bytes) __declspec(align(bytes))
      #elif defined(__clang__) || defined(__GNUC__) /* C++98/03 on Clang/GCC */
        #define alignas(bytes) __attribute__ ((aligned (bytes)))
      #else /* Otherwise, we ignore the directive (unless user provides their own) */
        #define alignas(bytes)
      #endif
    #else /* C++ >= 11 has alignas keyword */
      /* Do nothing */
    #endif
  #endif /* = !defined(__STDC_VERSION__) && !defined(__cplusplus) */
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	max_event_sig = 32
};

 /* The estimated size of the CPU's cache line when atomically updating memory.
  Add this much padding or align to this boundary to avoid atomically-updated
  memory from forcing cache invalidations on near, but non-atomic, memory.

  https://en.wikipedia.org/wiki/False_sharing
  https://github.com/golang/go/search?q=CacheLinePadSize
  https://github.com/ziglang/zig/blob/a69d403cb2c82ce6257bfa1ee7eba52f895c14e7/lib/std/atomic.zig#L445
 */
typedef char events_cacheline_t[__ATOMIC_CACHE_LINE];

struct sys_signal_s {
	int sig;
	bool is_running;
	sig_cb proc;
	void *data;
	events_t *loop;
};

typedef struct results_data {
	data_types type;
	int id;
	bool is_ready;
	values_t result;
} _results_data_t, *results_data_t;
make_atomic(results_data_t, atomic_results_t)

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
make_atomic(events_fd_t *, atomic_events_t)

struct sys_events_s {
  	/* read only */
	void *_fds_free_addr;
	int max_fd;
	size_t cpu_count;
	size_t queue_size;
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
	char pNamed[FILENAME_MAX];
	array_t gc;
	events_cacheline_t pad;
	atomic_spinlock lock;
	atomic_flag loop_signaled;
	/* task unique id generator */
	atomic_size_t id_generate;
	atomic_size_t result_id_generate;
	atomic_size_t num_loops;
	atomic_results_t *results;
	atomic_events_t fds;
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

/* Base events coroutine context. */
struct coro_events_s {
#if defined(_WIN32) && defined(USE_FIBER)
	LPVOID fiber;
#elif defined(USE_SJLJ)
	sigjmp_buf sig_ctx;
	sigcall_t sig_func;
	void *stack;
#else
	unsigned long int uc_flags;
	ucontext_t *uc_link;
	stack_t uc_stack;
	mcontext_t uc_mcontext;
	__sigset_t uc_sigmask;
#endif
};

#if defined(_WIN32)
struct ucontext_s {
	unsigned long int uc_flags;
	ucontext_t *uc_link;
	stack_t uc_stack;
	mcontext_t uc_mcontext;
	__sigset_t uc_sigmask;
};
#endif

/* Extended events coroutine context. */
struct events_task_s {
	coroutine_t type[1];
	/* Stack base address, can be used to scan memory in a garbage collector. */
	void *stack_base;
	/* Used to check stack overflow. */
	size_t magic_number;
	/* Coroutine stack size. */
	size_t stack_size;
	size_t alarm_time;
	size_t cycles;
	task_states status;
	bool ready;
	bool halt;
	bool system;
	bool waiting;
	bool group_active;
	bool group_finish;
	bool referenced;
	int err_code;
	/* unique task id */
	unsigned int cid;
	/* thread id */
	unsigned int tid;
	/* unique result id */
	unsigned int rid;
	tasks_t *next;
	tasks_t *prev;
	tasks_t *context;
	task_group_t *task_group;
	array_t result_group;
	data_func_t func;
	void *args;
	void *user_data;
	values_t *results;
	char name[256];
};

struct execinfo_s {
#ifdef _WIN32
	/* List of process arguments */
	char *argv;
#else
	/* List of process arguments */
	char **argv;
#endif
	/* Set working directory */
	const char *workdir;

	/* List of environment variables */
	const char **env;

	/* Create detached background process */
	bool detached;

	/* Standard file descriptors */
	filefd_t input, output, error;

	/* child process id */
	process_t ps;

	/* child pseudo fd */
	sockfd_t fd;
};

/* scheduler queue struct */
typedef struct tasklist_s {
	tasks_t *head;
	tasks_t *tail;
} tasklist_t;

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
