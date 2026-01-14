#ifndef _THREADED_H /* _THREADED_H */
#define _THREADED_H

#include <os_io.h>

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
C_API uintptr_t os_self();

/** Suspend the thread for the specified time. */
C_API int os_sleep(uint32_t msec);

/** Exit current thread with `result` code. */
C_API void os_exit(uint32_t exit_code);

#if defined (__cplusplus) || defined (c_plusplus)
} /* terminate extern "C" { */
#endif

#endif /* _THREADED_H */