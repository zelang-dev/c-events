#ifndef _EXCEPT_H
#define _EXCEPT_H

#include <events.h>

#define EX_MAX_NAME_LEN  ARRAY_SIZE

#if defined(USE_DEBUG)
#   ifdef _WIN32
#       include <DbgHelp.h>
#       pragma comment(lib,"Dbghelp.lib")
#   else
#       include <execinfo.h>
#   endif
#endif

/***********************************************************
 * Implementation
 */

/* exception state/stages
*/
typedef enum {
    ex_start_st = -1,
    ex_try_st,
    ex_throw_st,
    ex_final_st,
    ex_done_st,
    ex_catch_st,
} ex_stage;

/* some useful macros
*/
#define EX_CAT(a, b) a ## b

#define EX_STR_(a) #a
#define EX_STR(a) EX_STR_(a)

#define EX_NAME(e) EX_CAT(ex_err_, e)
#define EX_PNAME(p) EX_CAT(ex_protected_, p)

/* macros
 */
#define EX_EXCEPTION(E) \
        const char EX_NAME(E)[] = EX_STR(E)

/* context savings
*/
#if defined(sigsetjmp) || defined(__APPLE__) || defined(__MACH__)
#   define ex_jmp_buf           sigjmp_buf
#   define ex_setjmp(buf)       sigsetjmp(buf,1)
#   define ex_longjmp(buf,st)   siglongjmp(buf,st)
#else
#   define ex_jmp_buf           jmp_buf
#   define ex_setjmp(buf)       setjmp(buf)
#   define ex_longjmp(buf,st)   longjmp(buf,st)
#endif

#define ex_throw_loc(E, F, L, C, T)     \
    do {                                \
        C_API const char EX_NAME(E)[];  \
        ex_throw(EX_NAME(E), F, L, C, NULL, T); \
    } while (0)

/* An macro that stops the ordinary flow of control and begins panicking,
throws an exception of given message. */
#define ex_panic(message)					\
    do {                        			\
        C_API const char EX_NAME(panic)[];  \
        ex_throw(EX_NAME(panic), __FILE__, __LINE__, __FUNCTION__, (message), NULL);    \
    } while (0)

#ifdef _WIN32

/* An macro that stops the ordinary flow of control and begins panicking,
throws an `E` defined O.S. exception as:
- invalid_type
- range_error
- divide_by_zero
- logic_error
- future_error
- system_error
- domain_error
- length_error
- out_of_range
- invalid_argument
- division_by_zero
- out_of_memory
- sig_int
- sig_abrt
- sig_alrm
- sig_bus
- sig_fpe
- sig_ill
- sig_quit
- sig_segv
- sig_term
- sig_trap
- sig_hup
- sig_break
- sig_winch
- sig_info
- access_violation
- array_bounds_exceeded
- breakpoint
- datatype_misalignment
- flt_denormal_operand
- flt_divide_by_zero
- flt_inexact_result
- flt_invalid_operation
- flt_overflow
- flt_stack_check
- flt_underflow
- illegal_instruction
- in_page_error
- int_divide_by_zero
- int_overflow
- invalid_disposition
- priv_instruction
- single_step
- stack_overflow
- invalid_handle
- bad_alloc
 */
#define throw(E)    ex_panic(EX_STR(E))
#define ex_signal_block(ctrl)   \
    CRITICAL_SECTION ctrl##__FUNCTION__;    \
    InitializeCriticalSection(&ctrl##__FUNCTION__); \
    EnterCriticalSection(&ctrl##__FUNCTION__);

#define ex_signal_unblock(ctrl) \
    LeaveCriticalSection(&ctrl##__FUNCTION__);  \
    DeleteCriticalSection(&ctrl##__FUNCTION__);
#else
/* An macro that stops the ordinary flow of control and begins panicking,
throws an `E` defined O.S. exception as:
- invalid_type
- range_error
- divide_by_zero
- logic_error
- future_error
- system_error
- domain_error
- length_error
- out_of_range
- invalid_argument
- division_by_zero
- out_of_memory
- sig_int
- sig_abrt
- sig_alrm
- sig_bus
- sig_fpe
- sig_ill
- sig_quit
- sig_segv
- sig_term
- sig_trap
- sig_hup
- sig_break
- sig_winch
- sig_info
- access_violation
- array_bounds_exceeded
- breakpoint
- datatype_misalignment
- flt_denormal_operand
- flt_divide_by_zero
- flt_inexact_result
- flt_invalid_operation
- flt_overflow
- flt_stack_check
- flt_underflow
- illegal_instruction
- in_page_error
- int_divide_by_zero
- int_overflow
- invalid_disposition
- priv_instruction
- single_step
- stack_overflow
- invalid_handle
- bad_alloc
 */
#define throw(E)    ex_throw_loc(E, __FILE__, __LINE__, __FUNCTION__, NULL)
#define ex_signal_block(ctrl)   \
    sigset_t ctrl##__FUNCTION__, ctrl_all##__FUNCTION__; \
    sigfillset(&ctrl##__FUNCTION__);    \
    pthread_sigmask(SIG_SETMASK, &ctrl##__FUNCTION__, &ctrl_all##__FUNCTION__);

#define ex_signal_unblock(ctrl) \
    pthread_sigmask(SIG_SETMASK, &ctrl_all##__FUNCTION__, NULL);
#endif

/* types
*/

struct ex_backtrace_s {
#ifdef _WIN32
    CONTEXT ctx[1];
    HANDLE process;
    HANDLE thread;
#else
    void *ctx[EX_MAX_NAME_LEN];
    size_t size;
    char **dump;
#endif
};

typedef struct ex_error_s {
    bool volatile is_caught;
    /* What stage is the ~try~ block in? */
    ex_stage volatile stage;

    /* The line from whence this handler was made, in order to backtrace it later (if we want to). */
    int volatile line;

    /** The function from which the exception was thrown */
    const char *volatile function;

    /** The name of this exception */
    const char *volatile name;

    /* The file from whence this handler was made, in order to backtrace it later (if we want to). */
    const char *volatile file;

    ex_backtrace_t *backtrace;
} ex_error_t;

/* stack of exception */
struct ex_context_s {
    int type;
    int unstack;
    int volatile caught;

    /* The line from whence this handler was made, in order to backtrace it later (if we want to). */
    int volatile line;

    /* What is our active state? */
    int volatile state;
    bool is_unwind;
    bool is_rethrown;
    bool is_guarded;
    bool is_scoped;
    void *data;
    void *prev;

    /* The handler in the stack (which is a FILO container). */
    ex_context_t *next;
    ex_ptr_t *stack;

    /** The panic error message thrown */
    const char *volatile panic;

    /** The function from which the exception was thrown */
    const char *volatile function;

    /** The name of this exception */
    const char *volatile ex;

    /* The file from whence this handler was made, in order to backtrace it later (if we want to). */
    const char *volatile file;

    ex_backtrace_t backtrace[1];

    /* The program state in which the handler was created, and the one to which it shall return. */
    ex_jmp_buf buf;
};

#ifdef _WIN32
#define ex_try				\
    /* local context */     \
    ex_context_t ex_err;    \
    ex_error_t err;         \
    for (ex_err.state = ex_setjmp(*try_start(ex_start_st, &err, &ex_err)); try_next(&err, &ex_err);)   \
        if (ex_err.state == ex_try_st && err.stage == ex_try_st)    \
            __try

#define ex_catch(E)      \
            __except(catch_seh(EX_STR(E), GetExceptionCode(), GetExceptionInformation())) \
                { ex_err.state = ex_throw_st; }    \
                else if (try_catching(EX_STR(E), &err, &ex_err))

#define ex_catch_if      \
            __except(catch_filter_seh(GetExceptionCode(), GetExceptionInformation())) \
                { ex_err.state = ex_throw_st; }  \
                else if (try_catching("_if", &err, &ex_err))

#define ex_catch_any		\
            __except(catch_filter_seh(GetExceptionCode(), GetExceptionInformation())) \
                { ex_err.state = ex_throw_st; }  \
                else if (try_catching(null, &err, &ex_err))

#define ex_finally			\
        else if (try_finallying(&err, &ex_err))
#else
#define ex_try				\
    /* local context */     \
    ex_context_t ex_err;    \
    ex_error_t err;         \
    for (ex_err.state = ex_setjmp(*try_start(ex_start_st, &err, &ex_err)); try_next(&err, &ex_err);)   \
        if (ex_err.state == ex_try_st && err.stage == ex_try_st)

#define ex_catch_if		else if (try_catching("_if", &err, &ex_err))
#define ex_catch(E)		else if (try_catching(EX_STR(E), &err, &ex_err))
#define ex_catch_any	else if (try_catching(null, &err, &ex_err))
#define ex_finally		else if (try_finallying(&err, &ex_err))
#endif

#define try         ex_try
#define catch_any   ex_catch_any
#define catch_if    ex_catch_if
#define catch(e)    ex_catch(e)
#define finally     ex_finally

/* Compare `E` to current error condition in `scope`,
will mark exception handled, if `true`.
- `E` can be defined like exception macro `throw(E)`.
*/
#define caught(E) 	try_caught(EX_STR(E))
#define rethrow 	try_rethrow(&ex_err)

#define _g_set 		setup_##__FUNCTION__
#define _g_unwind 	unwind_##__FUNCTION__
#define _g_arena 	arena_##__FUNCTION__
#define _g_scope 	scope_##__FUNCTION__

/* Creates an ~scoped~ `guard` section. */
#define guard									\
{												\
    ex_signal_setup();							\
    void *_g_arena = scope_arena();				\
	ex_setup_func _g_set = guard_setup_func;	\
    ex_unwind_func _g_unwind = guard_unwind_func; \
    guard_unwind_func = (ex_unwind_func)scope_unwind; \
    guard_setup_func = guard_set;               \
    ex_memory_t _g_scope[1];					\
    guard_init(_g_scope);						\
    try {										\
        do {

/* Ends an ~scoped~ `guard` section, on scope exit will begin executing deferred functions. */
#define guarded									\
        } while (false);						\
        scope_unwind((_g_scope));				\
    } catch_if {								\
        scope_unwind((_g_scope));				\
    } finally {									\
        guard_reset(_g_arena, _g_set, _g_unwind);	\
    }											\
}

/* Will catch and set `error`, this is for future `queue_work` thread usage. */
#define guarded_exception(error)                \
        } while (false);                        \
        scope_unwind((_g_scope));				\
    } catch_if {                             	\
        scope_unwind((_g_scope));				\
        if (!(_g_scope)->is_recovered && try_caught(try_message())) \
            scope_request_erred(error, ex_err);	\
    } finally {                                 \
		guard_reset(_g_arena, _g_set, _g_unwind);	\
    }                                     		\
}

#ifdef __cplusplus
extern "C" {
#endif

/* low-level api
 */

C_API ex_context_t *ex_local(void);
C_API void ex_throw(const char *ex, const char *file, int, const char *function,
	const char *message, ex_backtrace_t *dump);

/* Prints stack trace based on context record */
C_API void ex_backtrace(ex_backtrace_t *ex);

/* Convert signals into exceptions */
C_API void ex_signal_setup(void);

/* Reset signal handler to default */
C_API void ex_signal_default(void);

#ifdef _WIN32
#	define EXCEPTION_PANIC 0xE0000001
C_API void ex_signal_seh(DWORD sig, const char *ex);
C_API int catch_seh(const char *exception, DWORD code, struct _EXCEPTION_POINTERS *ep);
C_API int catch_filter_seh(DWORD code, struct _EXCEPTION_POINTERS *ep);
#endif

C_API ex_memory_t *scope_local(void);
C_API ex_memory_t *get_scope(void);
C_API ex_memory_t *scope_init(void);
C_API void *scope_arena(void);
C_API void scope_unwind(ex_memory_t *scope);
C_API void scope_request_erred(os_request_t *p, ex_context_t err);

/* Returns an ~protected~ memory pointer from ~current~ `scoped` context, aka `RAII`.

- Creates a lifetime smart handle, an `scoped` object, that binds any additional requests to it's lifetime.
- `Defer` execution of `func`, WILL be `LIFO` executed on `panic/throw/return/exit`.
- To handle/unwind `Platform/O.S. Exceptions` this function MUST be inside `guard` aka `try...catch` blocks.
- Returns `NULL` if `ptr` is NULL, ~example~ `fence(malloc(sizeof(struct)), free);`

Uses either `guard` section, `try/catch` block, or `thread`,
if not an active ~coroutine~ `Events API` environment, as `context`. */
C_API void *fence(void *ptr, func_t func);

C_API ex_memory_t *guard_init(ex_memory_t *scope);
C_API void guard_set(ex_context_t *ctx, const char *ex, const char *message);
C_API void guard_reset(void *scope, ex_setup_func set, ex_unwind_func unwind);

/* Get current `guard` ~scope~ error condition string. */
C_API const char *guard_message(void);

/* extern declaration
*/

C_API ex_setup_func exception_setup_func;
C_API ex_unwind_func exception_unwind_func;
C_API ex_terminate_func exception_terminate_func;
C_API ex_terminate_func exception_ctrl_c_func;

C_API ex_setup_func guard_setup_func;
C_API ex_unwind_func guard_unwind_func;
C_API ex_terminate_func guard_ctrl_c_func;
C_API ex_terminate_func guard_terminate_func;

/* pointer protection
*/
C_API ex_ptr_t ex_protect_ptr(ex_ptr_t *const_ptr, void *ptr, void (*func)(void *));
C_API void ex_unprotected_ptr(ex_ptr_t *const_ptr);

/* Protects dynamically allocated memory against exceptions.
If the object pointed by `ptr` changes before `unprotected()`,
the new object will be automatically protected.

If `ptr` is not null, `func(ptr)` will be invoked during stack unwinding. */
#define protected(ptr, func) ex_ptr_t EX_PNAME(ptr) = ex_protect_ptr(&EX_PNAME(ptr), &ptr, func)

/* Remove memory pointer protection, does not free the memory. */
#define unprotected(p) (ex_local()->stack = EX_PNAME(p).next)

C_API void try_rethrow(ex_context_t *);
C_API ex_jmp_buf *try_start(ex_stage, ex_error_t *, ex_context_t *);
C_API bool try_catching(char *, ex_error_t *, ex_context_t *);
C_API bool try_finallying(ex_error_t *, ex_context_t *);
C_API bool try_next(ex_error_t *, ex_context_t *);

/* Compare `err` to current error condition in `scope`,
will mark exception handled, if `true`. */
C_API bool try_caught(const char *);

/* Get current ~scope~ error condition string. */
C_API const char *try_message(void);

#ifdef __cplusplus
}
#endif

#endif /* _EXCEPT_H */
