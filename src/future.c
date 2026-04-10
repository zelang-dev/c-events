#include "events_internal.h"

static future_t future_create(thrd_func_t func, void *args) {
	future_t fut = events_calloc(1, sizeof(struct future_s));
	if (defer_free(fut)) {
		fut->promise->scope = get_scope();
		fut->promise->args = args;
		fut->promise->func = func;
		atomic_flag_clear(&fut->promise->mutex);
		atomic_flag_clear(&fut->promise->done);
		fut->type = DATA_FUTURE;
	}

    return fut;
}

static EVENTS_INLINE data_values_t *promise_get(promise *p) {
	while (!atomic_flag_load(&p->done))
		os_sleep(0);

	return p->result;
}

void promise_erred(promise *p, ex_context_t err) {
	atomic_lock(&p->mutex);
	p->scope->err = (void *)err.ex;
	p->scope->_panic = err._panic;
	atomic_unlock(&p->mutex);
	atomic_flag_test_and_set(&p->done);
}

void promise_set(promise *p, void *res) {
	atomic_lock(&p->mutex);
	if (!is_empty(res)) {
		if (res == casting(DATA_INVALID))
			p->erred = errno;

		if (is_data(res)) {
			p->result->value.object = data_copy((array_t)p->result->extended, res);
			scope_deferred(p->scope, (func_t)data_delete, p->result->value.object);
		} else {
			p->result->value.object = res;
		}
	}
	atomic_unlock(&p->mutex);
	atomic_flag_test_and_set(&p->done);
}

EVENTS_INLINE bool is_future(void *self) {
	return data_type(self) == DATA_FUTURE;
}

static int _thrd_wrapper(void *arg) {
	future_t f = (future_t)arg;
    int err = 0;
	values_t res[1] = {0};
#ifdef RP_MALLOC_H
	rpmalloc_init();
#endif

	scope_init()->local = (void *)f->promise->args;
	f->promise->scope->err = null;
	f->promise->erred = 0;

	guard {
		defer_free(f->promise->args);
		res->object = f->promise->func(f->promise->args);
		promise_set(f->promise, res->object);
	} guarded_exception(f->promise);

	scope_unwind(scope_local());
#ifdef RP_MALLOC_H
	rpmalloc_thread_finalize(1);
#endif
	os_exit(err);
    return err;
}

static void thrd_start(future_t f) {
	if (is_empty(f) || (f->thread = os_create((os_thread_proc)_thrd_wrapper, f)) == OS_NULL)
        throw(future_error);
}

future_t thrd_async(thrd_func_t fn, size_t num_of_args, ...) {
    va_list ap;

    va_start(ap, num_of_args);
    param_t args = data_ex(num_of_args, ap);
    va_end(ap);

	future_t f = future_create(fn, args);
    thrd_start(f);
	return f;
}

values_t thrd_get(future_t f) {
	if (data_type(f) == DATA_FUTURE) {
		data_values_t *r = promise_get(f->promise);
		if (os_join(f->thread, 0, NULL) == 0) {
			f->type = DATA_RESULT;
			atomic_flag_clear(&f->promise->mutex);
			atomic_flag_clear(&f->promise->done);
			if (f->promise->erred)
				errno = f->promise->erred;

			if (!is_empty(f->promise->scope->err)) {
				ex_throw(f->promise->scope->err,
					"unknown", 0, "_thrd_wrapper", f->promise->scope->_panic, f->promise->scope->backtrace);
			}
		}

		return *((array_t)r->value.object);
	}

	if (data_type(f) == DATA_RESULT)
		return *((array_t)f->promise->result->value.object);

	throw(logic_error);
	return data_values_empty->value;
}

EVENTS_INLINE void thrd_task_yield(void) {
	tasks_info(active_task(), 1);
	yield_task();
}

EVENTS_INLINE void thrd_wait(future_t f, wait_func yield) {
    while (!thrd_is_done(f))
        yield();
}

param_t thrd_data(size_t numof, ...) {
    va_list ap;
	param_t args = null;
    size_t i;
	bool is_arguments = is_data(scope_init()->local);
	if (!is_arguments) {
		va_start(ap, numof);
        args = data_ex(numof, ap);
        va_end(ap);
	} else {
		args = (param_t)scope_local()->local;
		$reset(args);
		if (numof > 0) {
			va_start(ap, numof);
			for (i = 0; i < numof; i++)
				$append(args, va_arg(ap, void *));
			va_end(ap);
		}
    }

	return args;
}

EVENTS_INLINE bool thrd_is_done(future_t f) {
	return atomic_flag_load_explicit(&f->promise->done, memory_order_relaxed);
}

#ifdef _WIN32
EVENTS_INLINE size_t thrd_cpu_count(void) {
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	return (size_t)system_info.dwNumberOfProcessors;
}
#elif (defined(__linux__) || defined(__linux))
#include <sched.h>
EVENTS_INLINE size_t thrd_cpu_count(void) {
	cpu_set_t cpuset;
	sched_getaffinity(0, sizeof(cpuset), &cpuset);
	return CPU_COUNT(&cpuset);
}
#elif defined(__APPLE__) || defined(__MACH__)
EVENTS_INLINE size_t thrd_cpu_count(void) {
	return sysconf(_SC_NPROCESSORS_CONF);
}
#else
EVENTS_INLINE size_t thrd_cpu_count(void) {
	return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif

void thrd_pool_shutdown(void) {
	events_deque_t **queue = sys_event.local;
	if (!is_empty(queue)) {
		size_t i, count = atomic_load(&sys_event.num_loops);
		for (i = 0; i <= count; i++) {
			if (is_ptr_usable(queue[i])) {
				atomic_flag_test_and_set(&queue[i]->started);
				atomic_flag_test_and_set(&queue[i]->shutdown);
			}
		}
	}
}