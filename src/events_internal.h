#ifndef _EVENTS_INTERNAL_H
#define _EVENTS_INTERNAL_H

#include <events.h>

#if defined(USE_DEBUG)
#   include <assert.h>
#else
#   define assert
#endif

#ifndef MAX_PATH
#	define MAX_PATH          260
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

make_atomic(tasks_t *, atomic_tasks_t)
typedef struct {
	atomic_size_t size;
	atomic_tasks_t buffer[];
} deque_array_t;
make_atomic(deque_array_t *, atomic_task_array_t)

typedef struct events_deque_s {
	data_types type;
	os_thread_t thread;
	array_t jobs;
	waitgroup_t tasks;
	events_t *loop;
	events_cacheline_t _pad;
	atomic_flag started, shutdown;
	atomic_size_t available, top, bottom;
	atomic_task_array_t array;
} events_deque_t;

struct _thread_worker {
	data_types type;
	int id;
	int last_fd;
	events_t *loop;
	events_deque_t *queue;
	atomic_spinlock mutex;
	char buffer[MAX_PATH];
};

struct _thread_tasks_worker {
	data_types type;
	int id;
	events_t *loop;
	os_worker_t *pool;
	events_deque_t *queue;
};

struct _request_worker {
	data_types type;
	int id;
	param_t args;
	param_func_t func;
	data_values_t result[1];
	atomic_spinlock mutex;
	atomic_flag done;
};

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
	bool is_terminated;
	values_t result;
} _results_data_t, *results_data_t;
#if __APPLE__ && __MACH__
make_atomic(results_data_t *, atomic_results_t)
#else
make_atomic(results_data_t, atomic_results_t)
#endif

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
	array_t cpu_index;
	events_deque_t **local;
	events_cacheline_t pad;
	atomic_spinlock lock;
	atomic_flag loop_signaled;
	/* task unique id generator */
	atomic_size_t id_generate;
	/* result id generator */
	atomic_size_t result_id_generate;
	/* Used to determent which thread's `run queue`
	receive next `task`, `count % (task thread pool)`,
	must not be greater than cpu cores */
	atomic_size_t thrd_id_count;
	atomic_size_t num_loops;
#if __APPLE__ && __MACH__
	atomic_results_t results;
#else
	atomic_results_t *results;
#endif
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
	sys_signal_t *signal_handlers;
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
typedef struct OVERLAPPED_REQUEST *POVERLAPPED_REQUEST;
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
	bool taken;
	bool halt;
	bool system;
	bool waiting;
	bool group_active;
	bool group_finish;
	bool referenced;
	bool is_generator;
	bool is_threaded;
	int err_code;
	/* unique task id */
	uint32_t cid;
	/* thread id */
	uint32_t tid;
	/* unique result id */
	uint32_t rid;
	/* current generator id */
	uint32_t gen_id;
	tasks_t *next;
	tasks_t *prev;
	tasks_t *context;
	tasks_t *sleeping;
	generator_t generator;
	task_group_t *task_group;
	array_t garbage;
	data_func_t func;
	void *args;
	void *user_data;
	values_t *results;
	char name[MAX_PATH];
};

struct generator_s {
	data_types type;
	uint32_t rid;
	bool is_ready;
	values_t values[1];
	tasks_t *context;
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
	/* Created `spawn` ~io~ controlled process */
	bool is_spawn;
	/* Standard ~pair~ `process` file descriptors */
	filefd_t write_input[2], read_output[2], error;
#ifdef _WIN32
	POVERLAPPED_REQUEST req;
	char *buffer;
#endif
	/* child process id */
	process_t ps;
	/* child pseudo fd */
	fds_t fd;
	uint32_t rid;
	tasks_t *context;
	exit_cb exit_func;
	exec_io_cb io_func;
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

uint32_t async_task_ex(size_t heapsize, param_func_t fn, uint32_t num_of_args, ...);
uint32_t async_task_loop(events_t *loop, size_t heapsize, param_func_t fn, uint32_t num_of_args, ...);
void thread_result_set(os_request_t *p, void *res);
void enqueue_pool_request(os_worker_t *j, os_request_t *r);
uint32_t task_push(tasks_t *t, bool is_thread);
tasks_t *create_task(size_t heapsize, data_func_t func, void *args);

void deque_init(events_deque_t *q, int size_hint);
void deque_resize(events_deque_t *q);
tasks_t *deque_take(events_deque_t *q);
tasks_t *deque_steal(events_deque_t *q);
tasks_t *deque_peek(events_deque_t *q, int index);
void deque_push(events_deque_t *q, tasks_t *w);
void deque_free(events_deque_t *q);
void deque_destroy(void);

#ifdef _WIN32
DWORD __stdcall spawn_io_thread(void *arg);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EVENTS_INTERNAL_H */
