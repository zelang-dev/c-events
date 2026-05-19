#include "events_internal.h"

static future_t future_create(thrd_func_t func, void *args) {
	future_t fut = events_calloc(1, sizeof(struct future_s));
	if (defer_free(fut)) {
		fut->promise->scope = get_scope();
		fut->promise->result->is_array = false;
		fut->promise->args = args;
		fut->promise->func = func;
		atomic_flag_clear(&fut->promise->mutex);
		atomic_flag_clear(&fut->promise->done);
		fut->promise->type = DATA_PROMISE;
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

void promise_free(ex_memory_t *scope, void *data) {
	if (!is_empty(scope) && is_data(scope->defer_arr)) {
		atomic_lock($lock(scope->defer_arr));
		$append(scope->defer_arr, data);
		atomic_unlock($lock(scope->defer_arr));
	}
}

void promise_set(promise *p, void *res) {
	atomic_lock(&p->mutex);
	if (!is_empty(res)) {
		if (res == casting(DATA_INVALID))
			p->erred = errno;

		if (is_data(res)) {
			p->result->is_array = true;
			p->result->value.object = data_tuple(data_copy((array_t)p->result->extended, res));
		} else {
			p->result->value.object = res;
		}
	}
	atomic_unlock(&p->mutex);
	atomic_flag_test_and_set(&p->done);
}

EVENTS_INLINE values_t promise_wait(promise *p) {
	while (is_promise(p) && !atomic_flag_load(&p->done))
		yield_active_info();

	return p->result->value;
}

EVENTS_INLINE void promise_clean(promise *p) {
	if (is_promise(p) && atomic_flag_load(&p->done)) {
		if (is_data(p->args)) {
			$delete(p->args);
			p->args = null;
		}

		events_free(p);
	}
}

EVENTS_INLINE bool is_future(void *self) {
	return data_type(self) == DATA_FUTURE;
}

EVENTS_INLINE bool is_promise(void *self) {
	return data_type(self) == DATA_PROMISE;
}

EVENTS_INLINE future *futures_pool(void) {
	return sys_event.local[sys_event.future_cpu_idx[(atomic_load(&sys_event.future_id_count)
		% ($size(sys_event.future_cpu_idx)))].u_int]->pool;
}

EVENTS_INLINE char *future_buffer(void) {
	return active_future()->buffer;
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
			if (f->promise->result->is_array)
				defer_free(f->promise->result->value.object);

			if (f->promise->erred)
				errno = f->promise->erred;

			if (!is_empty(f->promise->scope->err)) {
				ex_throw(f->promise->scope->err,
					"unknown", 0, "_thrd_wrapper", f->promise->scope->_panic, f->promise->scope->backtrace);
			}
		}

		if (f->promise->result->is_array)
			return *((array_t)r->value.object);
		else
			return r->value;
	}

	if (data_type(f) == DATA_RESULT) {
		if (f->promise->result->is_array)
			return *((array_t)f->promise->result->value.object);
		else
			return f->promise->result->value;
	}

	throw(logic_error);
	return data_values_empty->value;
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
				atomic_flag_test_and_set(&queue[i]->shutdown);
				atomic_flag_test_and_set(&queue[i]->started);
			}
		}
	}
}

EVENTS_INLINE void enqueue_promise(future *j, promise *r) {
	atomic_lock(&j->mutex);
	events_deque_t *queue = sys_event.local[j->id];
	$append(queue->jobs, r);
	atomic_unlock(&j->mutex);
	atomic_fetch_add(&queue->available, 1);
}

static void queue_work_handler(param_t args) {
	future *thrd = args[0].object;
	promise *job = args[1].object;
	job->id = task_id();
	job->erred = 0;
	job->scope = get_scope();

	task_name("queue_work #%d", job->id);
	enqueue_promise(thrd, job);

	atomic_flag_test_and_set(&thrd->queue->started);
	yield();
	while (!atomic_flag_load(&job->done))
		yield_active_info();

	if (job->erred)
		errno = job->erred;
}

promise *promise_work(promise *f, param_func_t fn, size_t num_args, ...) {
	if (is_promise(f)) {
		va_list ap;
		future *thrd = futures_pool();

		va_start(ap, num_args);
		array_t args = data_ex(num_args, ap);
		va_end(ap);

		if (!is_empty(args)) {
			if (is_data(f->args))
				$delete(f->args);

			f->args = args;
			f->func = fn;
			f->result->is_array = false;
			atomic_flag_clear(&f->mutex);
			atomic_flag_clear(&f->done);
			/* determent which thread tasks pool receive next `future` job. */
			if (thrd->id == sys_event.local[sys_event.future_cpu_idx[(atomic_load(&sys_event.future_id_count)
				% ($size(sys_event.future_cpu_idx)))].u_int]->pool->id)
				atomic_fetch_add(&sys_event.future_id_count, 1);

			array_t data = arrays(2, thrd, f);
			tasks_t *t = create_task(Kb(32), (data_func_t)queue_work_handler, data, false, true);
			if (task_push(t, false) == TASK_ERRED) {
				promise_clean(f);
				if (!is_empty(data))
					$delete(data);

				f = null;
			} else {
				t->tid = thrd->id;
				f->type = DATA_PROMISE;
				yield();
			}

			return f;
		}
	}

	throw(logic_error);
	return f;
}

promise *queue_work(future *thrd, param_func_t fn, size_t num_args, ...) {
	va_list ap;
	promise *f = null;

	va_start(ap, num_args);
	array_t args = data_ex(num_args, ap);
	va_end(ap);

	if (!is_empty(args)) {
		if (!is_empty(f = (promise *)events_calloc(1, sizeof(promise)))) {
			f->args = args;
			f->func = fn;
			f->result->is_array = false;
			atomic_flag_clear(&f->mutex);
			atomic_flag_clear(&f->done);
			/* determent which thread tasks pool receive next `future` job. */
			if (thrd->id == sys_event.local[sys_event.future_cpu_idx[(atomic_load(&sys_event.future_id_count)
				% ($size(sys_event.future_cpu_idx)))].u_int]->pool->id)
				atomic_fetch_add(&sys_event.future_id_count, 1);

			array_t data = arrays(2, thrd, f);
			tasks_t *t = create_task(Kb(32), (data_func_t)queue_work_handler, data, false, true);
			if (task_push(t, false) == TASK_ERRED) {
				events_free(f);
				$delete(args);
				if (!is_empty(data))
					$delete(data);
				f = null;
			} else {
				t->tid = thrd->id;
				f->type = DATA_PROMISE;
				yield();
			}
		} else {
			$delete(args);
		}
	}

	return f;
}

EVENTS_INLINE bool queue_is_valid(promise *f) {
	return is_promise(f) && !atomic_flag_load(&f->done);
}

void queue_wait(array_t work, then_cb then) {
	if (is_data(work)) {
		while ($size(work) > 0) {
			foreach(worker in work) {
				if (!queue_is_valid(worker.object)) {
					if (!is_empty(then)) {
						defer_free(worker.object);
						promise *value = (promise *)worker.object;
						if (value->result->is_array == 1) {
							tuple_t result = (tuple_t)value->result->value.object;
							then(result);
							$delete(result);
						} else if (value->result->is_array == 0) {
							then((tuple_t)&value->result->value);
						}
						value->result->is_array = DATA_INVALID;
						yield();
					}

					$remove(work, iworker);
				}
			}
			iworker = 0;
			yield();
		}
		$delete(work);
	}
}

values_t queue_get(void *self) {
	promise *p = null;
	if (is_future(self)) {
		future_t f = (future_t)self;
		if (is_promise(f->promise))
			p = (promise *)f->promise;
	} else if (is_promise(self)) {
		p = (promise *)self;
	}

	if (!is_empty(p)) {
		while (!atomic_flag_load(&p->done))
			yield_active_info();

		if (p->result->is_array == 1) {
			defer_free(p);
			defer_free(p->result->value.object);
			p->result->is_array = DATA_INVALID;
			return *(tuple_t)(p->result->value.object);
		}

		if (p->result->is_array == 0) {
			p->result->is_array = DATA_INVALID;
			defer_free(p);
			return p->result->value;
		}
	}

	throw(logic_error);
	return data_values_empty->value;
}