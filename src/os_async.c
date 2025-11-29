#include "events_internal.h"

static void thread_request_enqueue(os_worker_t *j, os_request_t *r) {
	atomic_lock(&j->mutex);
	events_deque_t *queue = sys_event.local[j->id];
	$append(queue->jobs, r);
	atomic_unlock(&j->mutex);
	atomic_fetch_add(&queue->available, 1);
}

static unsigned int async_task_loop(events_t *loop, size_t heapsize, param_func_t fn, unsigned int num_of_args, ...) {
	va_list ap;

	va_start(ap, num_of_args);
	param_t params = data_ex(num_of_args, ap);
	va_end(ap);

	tasks_t *t = create_task(heapsize, (data_func_t)fn, params);
	t->tid = loop->loop_id - 1;
	return task_push(t, true);
}

#define CLASS(p) ((*(unsigned char*)(p))>>6)
static int parseip(char *name, unsigned char *ip) {
	unsigned char addr[4];
	char *p;
	int i, x;

	p = name;
	for (i = 0; i < 4 && *p; i++) {
		x = strtoul(p, &p, 0);
		if (x < 0 || x >= 256)
			return -1;
		if (*p != '.' && *p != 0)
			return -1;
		if (*p == '.')
			p++;
		addr[i] = x;
	}

	switch (CLASS(addr)) {
		case 0:
		case 1:
			if (i == 3) {
				addr[3] = addr[2];
				addr[2] = addr[1];
				addr[1] = 0;
			} else if (i == 2) {
				addr[3] = addr[1];
				addr[2] = 0;
				addr[1] = 0;
			} else if (i != 4)
				return -1;
			break;
		case 2:
			if (i == 3) {
				addr[3] = addr[2];
				addr[2] = 0;
			} else if (i != 4)
				return -1;
			break;
	}
	*ip = *(uint32_t *)addr;
	return 0;
}

static int __threads_wrapper(void *arg) {
	os_worker_t *work = (os_worker_t *)arg;
	events_deque_t *queue = work->queue;
	values_t res[1] = {0};
	int status = 0, tid = work->id;

	while (!atomic_flag_load(&queue->started))
		;

	do {
		if ((int)atomic_load(&queue->available) > 0) {
			atomic_fetch_sub(&queue->available, 1);
			atomic_lock(&work->mutex);
			os_request_t *worker = (os_request_t *)$shift(queue->jobs).object;
			atomic_unlock(&work->mutex);
			res->object = worker->func(worker->args);
			thread_result_set(worker, res->object);
			$delete(worker->args);
		} else {
			os_sleep(1);
		}
	} while (!atomic_flag_load_explicit(&queue->shutdown, memory_order_relaxed));
	$delete(queue->jobs);
	events_free(arg);
	os_exit(status);
	return status;
}

os_worker_t *events_addthreads_loop(events_t *loop) {
	events_deque_t **local = sys_event.local;
	os_worker_t *f_work = NULL;
	int index = loop->loop_id - 1;
	if (index <= sys_event.cpu_count) {
		local[index] = (events_deque_t *)events_malloc(sizeof(events_deque_t));
		if (local[index] == NULL)
			abort();

		deque_init(local[index], sys_event.queue_size);
		f_work = events_calloc(1, sizeof(os_worker_t));
		if (f_work == NULL)
			abort();

		atomic_unlock(&f_work->mutex);
		f_work->id = (int)index;
		f_work->queue = local[index];
		f_work->queue->jobs = array();
		f_work->queue->loop = loop;
		f_work->loop = loop;
		f_work->type = DATA_PTR;
		local[index]->thread = os_create(__threads_wrapper, (void *)f_work);
		if (local[index]->thread == OS_NULL)
			abort();
	}

	return f_work;
}

static void *queue_work_handler(param_t args) {
	os_worker_t *thrd = args[0].object;
	os_request_t *job = args[1].object;
	job->id = task_id();

	task_name("queue_work #%d", job->id);
	atomic_flag_test_and_set(&thrd->queue->started);

	thread_request_enqueue(thrd, job);
	yield_task();
	while (!atomic_flag_load(&job->done)) {
		task_info(active_task(), 1);
		yield_task();
	}

	defer_free(job);
	return job->result->value.object;
}

unsigned int queue_work(os_worker_t *thrd, param_func_t fn, size_t num_args, ...) {
	va_list ap;

	va_start(ap, num_args);
	array_t args = data_ex(num_args, ap);
	va_end(ap);

	os_request_t *f = (os_request_t*)events_calloc(1, sizeof(os_request_t));
	f->args = args;
	f->func = fn;
	atomic_unlock(&f->mutex);
	atomic_flag_clear(&f->done);
	unsigned int id = async_task_loop(thrd->loop, Kb(9), queue_work_handler, 2, thrd, f);
	yield_task();
	return id;
}

static EVENTS_INLINE void *os_gethostbyname(param_t name) {
	struct hostent *he = {0};
	if (parseip(name[0].char_ptr, name[1].char_ptr) >= 0) {
		return name[0].char_ptr;
	}

	if ((he = gethostbyname(name->char_ptr)) != NULL) {
		struct in_addr **p1 = (struct in_addr **)he->h_addr_list;
		return (char *)inet_ntop(AF_INET, &p1[0], name[1].char_ptr, INET_ADDRSTRLEN);
	}

	return NULL;
}

EVENTS_INLINE char *async_gethostbyname(os_worker_t *thrd, char *hostname) {
	return await_for(queue_work(thrd, os_gethostbyname, 2, hostname, thrd->buffer)).char_ptr;
}

static EVENTS_INLINE void *os_getaddrinfo(param_t args) {
	return casting(getaddrinfo(args[0].const_char_ptr, args[1].const_char_ptr,
		(const struct addrinfo *)args[2].object, (PADDRINFOA *)args[3].object));
}

EVENTS_INLINE int async_getaddrinfo(os_worker_t *thrd, const char *name,
	const char *service, const struct addrinfo *hints, struct addrinfo *result) {
	return await_for(queue_work(thrd, os_getaddrinfo, 4, name, service, hints, result)).integer;
}