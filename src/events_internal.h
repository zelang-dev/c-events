#ifndef _EVENTS_INTERNAL_H
#define _EVENTS_INTERNAL_H

#include <events.h>

#ifndef USE_ASSEMBLY
/** Coroutines uses the C standard library's `setjump`/`longjmp` API.
Overhead: `~30x` in cost compared to an ordinary function call.
See https://www.usenix.org/legacy/publications/library/proceedings/usenix2000/general/full_papers/engelschall/engelschall_html/index.html
If `assembly`, reduced to:
~5x on `x86`,
~10x (Windows) on `amd64`,
~6x (all other platforms) on `amd64`. */
#	define USE_SJLJ

/** Coroutines uses the Windows "fibers" API.
Overhead: `~15x` in cost compared to an ordinary function call.
If `assembly`, reduced to:
~5x on `x86`,
~10x (Windows) on `amd64`,
~6x (all other platforms) on `amd64`. */
#	define USE_FIBER

/** Coroutines uses the POSIX "ucontext" API.
Overhead: `~300x` in cost compared to an ordinary function call.
If `assembly`, reduced to:
~5x on `x86`,
~10x (Windows) on `amd64`,
~6x (all other platforms) on `amd64`. */
#	define USE_UCONTEXT
#	if __APPLE__ && __MACH__
# 		undef USE_FIBER
# 		undef USE_SJLJ
#	elif !defined(_WIN32)
# 		undef USE_FIBER
# 		undef USE_UCONTEXT
#	else
# 		undef USE_UCONTEXT
# 		undef USE_SJLJ
#	endif
#endif

#if defined(USE_DEBUG)
#   include <assert.h>
#else
#   define assert
#endif

/* In alignas(a), 'a' should be a power of two that is at least the type's
   alignment and at most the implementation's alignment limit.  This limit is
   2**13 on MSVC. To be portable to MSVC through at least version 10.0,
   'a' should be an integer constant, as MSVC does not support expressions
   such as 1 << 3.

   The following C11 requirements are NOT supported on MSVC:

   - If 'a' is zero, alignas has no effect.
   - alignas can be used multiple times; the strictest one wins.
   - alignas (TYPE) is equivalent to alignas (alignof (TYPE)).
*/
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

/*[amd64, arm, ppc, x86]:
   by default, coro_swap_function is marked as a text (code) section
   if not supported, uncomment the below line to use mprotect instead */
/* #define MPROTECT */

/*[amd64]:
   Win64 only: provides a substantial speed-up, but will thrash XMM regs
   do not use this unless you are certain your application won't use SSE */
/* #define NO_SSE */

/*[amd64, aarch64]:
   Win64 only: provides a small speed-up, but will break stack unwinding
   do not use this if your application uses exceptions or setjmp/longjmp */
/* #define NO_TIB */

#if defined(__clang__)
  #pragma clang diagnostic ignored "-Wparentheses"

  /* placing code in section(text) does not mark it executable with Clang. */
#	undef  MPROTECT
#	define MPROTECT
#endif

#if (defined(__clang__) || defined(__GNUC__)) && defined(__i386__)
#	define fastcall __attribute__((fastcall))
#elif defined(_MSC_VER) && defined(_M_IX86)
#	define fastcall __fastcall
#else
#	define fastcall
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

#ifndef NSIG
#	define NSIG 32
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	max_event_sig = NSIG
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
	events_deque_t *queue;
	atomic_spinlock mutex;
	char buffer[MAX_PATH];
};

struct _thread_tasks_worker {
	data_types type;
	int id;
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
	int tid;
	bool is_canceled;
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
	bool is_pathwatcher;
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
	int inotify_fd;
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
#if defined(_WIN32) && defined(_M_IX86) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ) && !defined(USE_FIBER)
	void *rip, *rsp, *rbp, *rbx, *r12, *r13, *r14, *r15;
	void *xmm[20]; /* xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15 */
	void *fiber_storage;
	void *dealloc_stack;
#elif (defined(__x86_64__) || defined(_M_X64)) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ) && !defined(USE_FIBER)
#ifdef _WIN32
	void *rip, *rsp, *rbp, *rbx, *r12, *r13, *r14, *r15, *rdi, *rsi;
	void *xmm[20]; /* xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15 */
	void *fiber_storage;
	void *dealloc_stack;
#else
	void *rip, *rsp, *rbp, *rbx, *r12, *r13, *r14, *r15;
#endif
#elif (defined(__i386) || defined(__i386__)) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ)
	void *eip, *esp, *ebp, *ebx, *esi, *edi;
#elif defined(__riscv) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ)
	void *s[12]; /* s0-s11 */
	void *ra;
	void *pc;
	void *sp;
#ifdef __riscv_flen
#if __riscv_flen == 64
	double fs[12]; /* fs0-fs11 */
#elif __riscv_flen == 32
	float fs[12]; /* fs0-fs11 */
#endif
#endif /* __riscv_flen */
#elif defined(__ARM_EABI__) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ)
#ifndef __SOFTFP__
	void *f[16];
#endif
	void *d[4]; /* d8-d15 */
	void *r[4]; /* r4-r11 */
	void *lr;
	void *sp;
#elif (defined(_M_ARM64) || defined(__aarch64__)) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ)
	void *x[12]; /* x19-x30 */
	void *sp;
	void *lr;
	void *d[8]; /* d8-d15 */
#elif (defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2) && !defined(USE_UCONTEXT) && !defined(USE_SJLJ)
	uint64_t gprs[32];
	uint64_t lr;
	uint64_t ccr;
	/* FPRs */
	uint64_t fprs[32];
#ifdef __ALTIVEC__
	/* Altivec (VMX) */
	uint64_t vmx[12 * 2];
	uint32_t vrsave;
#endif
#elif defined(_WIN32) && defined(USE_FIBER)
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
#if defined(USE_UCONTEXT)
	ucontext_t type[1];
#else
	coroutine_t type[1];
#endif
	/* Stack base address, can be used to scan memory in a garbage collector. */
	void *stack_base;
#if defined(_WIN32) && (defined(_M_X64) || defined(_M_IX86))
	void *stack_limit;
#endif
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
intptr_t events_backend_fd(events_t *);

void *events_calloc(size_t count, size_t size);
void *events_malloc(size_t size);
void *events_realloc(void *ptr, size_t size);
void events_free(void *ptr);

uint32_t async_task_ex(size_t heapsize, param_func_t fn, uint32_t num_of_args, ...);
void thread_result_set(os_request_t *p, void *res);
uint32_t task_push(tasks_t *t);
tasks_t *create_task(size_t heapsize, data_func_t func, void *args, bool is_thread);
int results_tid(uint32_t rid);

void deque_init(events_deque_t *q, int size_hint);
void deque_resize(events_deque_t *q);
tasks_t *deque_take(events_deque_t *q);
tasks_t *deque_steal(events_deque_t *q);
tasks_t *deque_peek(events_deque_t *q, int index);
void deque_push(events_deque_t *q, tasks_t *w);
void deque_free(events_deque_t *q);
void deque_destroy(void);

int inotify_del_monitor(int wd);
int inotify_close(int fd);
void *inotify_task(param_t args);

#ifdef _WIN32
int inotify_wd(int pseudo);
void inotify_handler(int fd, inotify_t *event, watch_cb handler, void *filter);
DWORD __stdcall spawn_io_thread(void *arg);
#endif

#if __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__ || __APPLE__ || __MACH__
int inotify_wd(int pseudo);
void inotify_handler(int fd, inotify_t *event, watch_cb handler, void *filter);
int inotify_flags(int pseudo);
void inotify_update(const char *path, watch_dir_t *dir, inotify_t *event, char *subpath, size_t path_max);
void *inotify_data(int pseudo);
void kqueue_watch_free(watch_dir_t *dir);
int kqueue_add_watch(events_t *loop, int wd);
watch_cb kqueue_watch_callback(events_t *loop);
void *kqueue_watch_filter(events_t *loop);
void kqueue_watch_init(events_t *loop, watch_cb handler, void *filter);
#elif __linux__
void inotify_handler(int fd, inotify_t *event, int len, watch_cb handler, void *filter);
#endif

int fsevents_init(const char *name, watch_cb handler, void *filter);
int fsevents_stop(uint32_t rid);

#ifdef __cplusplus
}
#endif

#endif /* _EVENTS_INTERNAL_H */
