#ifndef _THREADED_H /* _THREADED_H */
#define _THREADED_H

#include <async_io.h>

/* An independent thread handle, a `future` NOT part of any ~thread~ pool. */
typedef struct future_s *future_t;
/* a promise, a `job` to be handled in a `future/future_t` thread */
typedef struct _promise promise;
typedef void *(*thrd_func_t)(param_t);
typedef void (*wait_func)(void);
typedef void (*then_cb)(tuple_t result);

typedef unsigned short events_id_t;
typedef struct events_loop_s events_t;
typedef struct events_fd_s events_fd_t;
typedef struct actors_s actor_t;
typedef struct timerlist_s timerlist_t;
typedef struct sys_events_s sys_events_t;
typedef struct sys_signal_s sys_signal_t;
typedef struct task_group_s task_group_t;
typedef struct generator_s *generator_t;
typedef struct ex_memory_s ex_memory_t;
typedef struct ex_guard_s ex_guard_t;
typedef struct ex_ptr_s ex_ptr_t;
typedef struct ex_context_s ex_context_t;
typedef struct ex_backtrace_s ex_backtrace_t;
typedef struct server_socket_s server_socket;
typedef void (*ex_setup_func)(ex_context_t *, const char *, const char *);
typedef void (*ex_terminate_func)(void);
typedef void (*ex_unwind_func)(void *);
typedef void *(*malloc_cb)(size_t);
typedef void *(*realloc_cb)(void *, size_t);
typedef void *(*calloc_cb)(size_t, size_t);
typedef void (*free_cb)(void *);
typedef void (*events_cb)(fds_t fd, int event, void *args);
typedef void (*actor_cb)(actor_t *, void *);
typedef void (*os_cb)(intptr_t file, int bytes, void *data);
typedef void *(*param_func_t)(param_t);
typedef launch_func_t main_cb;
typedef events_cb sig_cb;
typedef task_group_t *waitgroup_t;

#if !defined(thread_local) /* User can override thread_local for obscure compilers */
	 /* Running in multi-threaded environment */
#	if defined(__STDC__) /* Compiling as C Language */
#		if defined(_MSC_VER) /* Don't rely on MSVC's C11 support */
#			define thread_local __declspec(thread)
#		elif __STDC_VERSION__ < 201112L /* If we are on C90/99 */
#			if defined(__clang__) || defined(__GNUC__) /* Clang and GCC */
#				define thread_local __thread
#			else /* Otherwise, we ignore the directive (unless user provides their own) */
#				define thread_local
#				define emulate_tls 1
#			endif
#		elif __APPLE__ && __MACH__
#			define thread_local __thread
#		else /* C11 and newer define thread_local in threads.h */
#			define HAS_C11_THREADS 1
#			include <threads.h>
#		endif
#	elif defined(__cplusplus) /* Compiling as C++ Language */
#		if __cplusplus < 201103L /* thread_local is a C++11 feature */
#			if defined(_MSC_VER)
#				define thread_local __declspec(thread)
#			elif defined(__clang__) || defined(__GNUC__)
#				define thread_local __thread
#			else /* Otherwise, we ignore the directive (unless user provides their own) */
#				define thread_local
#				define emulate_tls 1
#			endif
#		else /* In C++ >= 11, thread_local in a builtin keyword */
			/* Don't do anything */
#		endif
#		define HAS_C11_THREADS 1
#	endif
#endif

#if !defined(thrd_local)
#if defined(__TINYC__) || defined(emulate_tls)
#	define thrd_local_return(type, var)    return (type *)os_tls_get(emulate_##var##_tss);
#	define thrd_local_get(type, var, _initial, prefix)	\
        prefix type* var(void) {						\
            if (events_##var##_tls == 0) {				\
                events_##var##_tls = sizeof(type);		\
                if (os_tls_alloc(&events_##var##_tss, (emulate_dtor)events_free) == 0)	\
                    atexit(var##_reset);				\
                else									\
                    goto err;							\
            }                                           \
            void *ptr = os_tls_get(events_##var##_tss); \
            if (ptr == NULL) {                          \
                ptr = events_calloc(1, events_##var##_tls);		\
                if (ptr == NULL)                        \
                    goto err;                           \
                if ((os_tls_set(events_##var##_tss, ptr)) != 0)	\
                    goto err;                           \
            }                                           \
            return (type *)ptr;                         \
        err:                                            \
            return NULL;                                \
        }

#	define thrd_local_delete(type, var, _initial, prefix)	\
        prefix void var##_reset(void) {					\
            if(events_##var##_tls != 0) { 				\
                events_##var##_tls = 0;   				\
                os_tls_free(events_##var##_tss);		\
                events_##var##_tss = -1;   				\
            }                               			\
        }

#   define thrd_local_setup(type, var, _initial, prefix)	\
        static type events_##var##_buffer;				\
        prefix int events_##var##_tls = 0;				\
        prefix tls_emulate_t events_##var##_tss = 0;	\
        thrd_local_delete(type, var, _initial, prefix)	\
        prefix EVENTS_INLINE void var##_set(type *value) {	\
            *var() = *value;							\
        }												\
        prefix EVENTS_INLINE bool is_##var##_null(void) {	\
            return (type *)os_tls_get(events_##var##_tss) == (type *)_initial;	\
        }

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#	define thrd_local(type, var, _initial)					\
        thrd_local_setup(type, var, _initial, )	\
        thrd_local_get(type, var, _initial, )

#   define thrd_local_simple(type, var, _initial)	\
        thrd_local_setup(type, var, _initial, )  	\
        thrd_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define thrd_static(type, var, _initial)		\
        static type *var(void);					\
        static void var##_reset(void);			\
        static bool is_##var##_null(void);		\
        thrd_local_setup(type, var, _initial, static)	\
        thrd_local_get(type, var, _initial, static)

#   define thrd_static_simple(type, var, _initial)    thrd_static(type, var, _initial)

#	define thrd_local_proto(type, var, prefix) 		\
        prefix int events_##var##_tls;        	\
        prefix tls_emulate_t events_##var##_tss;	\
        prefix type var(void);                 	\
        prefix void var##_reset(void);			\
        prefix void var##_set(type value);		\
        prefix bool is_##var##_null(void);

	/* Creates a emulated `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#	define thrd_local_extern(type, variable) thrd_local_proto(type *, variable, C_API)
	/* Creates a emulated `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#	define thrd_local_external(type, variable) thrd_local_proto(type, variable, C_API)
#else
#   define thrd_local_return(type, var)    return (type)events_##var##_tls;
#   define thrd_local_get(type, var, _initial, prefix)		\
        prefix EVENTS_INLINE type var(void) {			\
            if (events_##var##_tls == _initial) {		\
                events_##var##_tls = &events_##var##_buffer;	\
            }                                   		\
            thrd_local_return(type, var)        			\
        }

#   define thrd_local_setup(type, var, _initial, prefix)		\
        prefix thread_local type events_##var##_tls = _initial;	\
        prefix EVENTS_INLINE void var##_reset(void) {	\
            events_##var##_tls = NULL;					\
        }												\
        prefix EVENTS_INLINE void var##_set(type value) {	\
            events_##var##_tls = value;					\
        }												\
        prefix EVENTS_INLINE bool is_##var##_null(void) {	\
            return events_##var##_tls == _initial;		\
        }

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define thrd_local(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type *, var, _initial, )		\
        thrd_local_get(type *, var, _initial, )

#   define thrd_local_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type, var, _initial, )			\
        thrd_local_get(type, var, _initial, )

	/* Initialize and setup thread local storage `var` as functions.
	- var();
	- var_reset();
	- is_var_null();
	- var_set(data); */
#   define thrd_static(type, var, _initial)				\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type *, var, _initial, static)	\
        thrd_local_get(type *, var, _initial, static)

#   define thrd_static_simple(type, var, _initial)		\
        static thread_local type events_##var##_buffer;	\
        thrd_local_setup(type, var, _initial, static)	\
        thrd_local_get(type, var, _initial, static)

#   define thrd_local_proto(type, var, prefix)          	\
        prefix thread_local type events_##var##_tls;	\
        prefix void var##_reset(void);					\
        prefix void var##_set(type value);           	\
        prefix bool is_##var##_null(void);             	\
        prefix type var(void);

	/* Creates a native `extern` thread-local storage `variable`,
	a pointer of `type`, and functions. */
#   define thrd_local_extern(type, variable) thrd_local_proto(type *, variable, C_API)
	/* Creates a native `extern` thread-local storage `variable`,
	a non-pointer of `type`, and functions. */
#   define thrd_local_external(type, variable) thrd_local_proto(type, variable, C_API)
#endif
#endif /* thrd_local */

#if defined(c_plusplus) || defined(__cplusplus)
extern "C" {
#endif

C_API int os_tls_alloc(tls_emulate_t *key, emulate_dtor dtor);
C_API void os_tls_free(tls_emulate_t key);
C_API void *os_tls_get(tls_emulate_t key);
C_API int os_tls_set(tls_emulate_t key, void *val);

/** Create a thread, returns `OS_NULL` on error. */
C_API os_thread_t os_create(os_thread_proc proc, void *param);

/** Join with the thread, set timeout, optional get exit_code,
returns `0` if thread exited, `errno` is set to `ETIMEDOUT` if time has expired. */
C_API int os_join(os_thread_t t, uint32_t timeout_ms, int *exit_code);

/** Detach thread. */
C_API int os_detach(os_thread_t t);

/** Add CPU number to mask. */
C_API void os_cpumask_set(os_cpumask *mask, uint32_t i);

/** Set CPU affinity. */
C_API int os_affinity(os_thread_t t, const os_cpumask *mask);

/** Get the current thread descriptor. */
C_API uintptr_t os_self(void);

/** Suspend the thread for the specified time. */
C_API int os_sleep(uint32_t msec);

/** Exit current thread with `result` code. */
C_API void os_exit(uint32_t exit_code);

/* Return an ~thread~ pool `future` handle. */
C_API future *futures_pool(void);
C_API future *active_future(void);
C_API char *future_buffer(void);
C_API bool is_future(void *self);
C_API bool is_promise(void *self);

/* Same as: https://en.cppreference.com/w/cpp/thread/promise/set_value.html */
C_API void promise_set(promise *p, void *res);

/* Same as: https://en.cppreference.com/w/cpp/thread/promise/set_exception.html */
C_API void promise_erred(promise *p, ex_context_t err);
C_API void promise_free(ex_memory_t *scope, void *data);

/*
Checks if the a ~future~ refers to a shared state aka `promise`, and `running`.

Similar to: https://en.cppreference.com/w/cpp/thread/future/valid.html */
C_API bool queue_is_valid(promise *f);

/* This runs the function `fn` in thread `thrd` pool,
asynchronously in a separate `task`. Returns a `promise`
that will eventually hold the result of ~thread pool work~.

Similar to: https://en.cppreference.com/w/cpp/thread/async.html
https://en.cppreference.com/w/cpp/thread/packaged_task.html

MUST call `queue_get()` to get any result, aka `join` for resource cleanup.

NOTE: This is setup to be just an `pass thru` for any function in an separate thread. */
C_API promise *queue_work(future *thrd, param_func_t fn, size_t num_args, ...);

/*
This waits aka `yield` until the `future` or `promise` is ready, then retrieves
the value stored. Right after calling this function `queue_is_valid()` is `false`.

Similar to: https://en.cppreference.com/w/cpp/thread/future/get.html */
C_API values_t queue_get(void *self);

/*
Will `pause` and `yield` to another `coroutine` until `ALL` ~future~ `promise`
results in `array` become available/done. Calls `queue_is_valid()` on each,
will execute `then` with ~result~.

Similar to: https://en.cppreference.com/w/cpp/thread/future/wait.html,
https://en.cppreference.com/w/cpp/thread/promise.html */
void queue_wait(array_t work, then_cb then);

/* Calls ~fn~ (with ~number of args~ then ~actual arguments~) in separate thread, returning without waiting
for the execution of ~fn~ to complete. The value returned by ~fn~ can be accessed
by calling `thrd_get()`.

Same as: https://en.cppreference.com/w/cpp/thread/async.html */
C_API future_t thrd_async(thrd_func_t fn, size_t, ...);

/* Returns the value of `future_t` ~promise~, a thread's shared object, If not ready, this
function blocks the calling thread and waits until it is ready.

Same as: https://en.cppreference.com/w/cpp/thread/future/get.html */
C_API values_t thrd_get(future_t);

/* This function blocks the calling thread and waits until `future_t` is ready,
will execute provided `yield` callback function continuously.

Same as: https://en.cppreference.com/w/cpp/thread/future/wait.html */
C_API void thrd_wait(future_t, wait_func yield);

/* Send `signal` for all `thread` pool ~handles~ to shutdown,
break `async_run()` loop. */
C_API void thrd_pool_shutdown(void);

/* Check status of `future_t` object state, if `true` indicates thread execution has ended,
any call thereafter to `thrd_get` is guaranteed non-blocking.

Similar to: https://en.cppreference.com/w/cpp/thread/future/valid.html */
C_API bool thrd_is_done(future_t);

C_API size_t thrd_cpu_count(void);

/* Return/create an arbitrary `vector/array` set of `values`, only available within ~thread~  `future/future_t` */
C_API param_t thrd_data(size_t, ...);

/* Return/create an single `vector/array` ~value~, only available within within ~thread~  `future/future_t` */
#define $(val) thrd_data(1, (val))

/* Return/create an pair `vector/array` ~values~, only available within ~thread~ `future/future_t` */
#define $$(val1, val2) thrd_data(2, (val1), (val2))

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _THREADED_H */