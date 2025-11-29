#include "events_internal.h"

static tasks_t *TASK_EMPTY_T = (tasks_t *)0x300, *TASK_ABORT_T = (tasks_t *)0x400;
static bool deque_thread_set = false;

/*
 * `deque_init` `deque_resize` `deque_take` `deque_push` `deque_steal`
 *
 * Modified from https://github.com/sysprog21/concurrent-programs/blob/master/work-steal/work-steal.c
 *
 * A work-stealing scheduler described in
 * Robert D. Blumofe, Christopher F. Joerg, Bradley C. Kuszmaul, Charles E.
 * Leiserson, Keith H. Randall, and Yuli Zhou. Cilk: An efficient multithreaded
 * runtime system. In Proceedings of the Fifth ACM SIGPLAN Symposium on
 * Principles and Practice of Parallel Programming (PPoPP), pages 207-216,
 * Santa Barbara, California, July 1995.
 * https://people.eecs.berkeley.edu/~kubitron/courses/cs262a-F21/handouts/papers/Cilk-PPoPP95.pdf
 *
 * However, that refers to an outdated model of Cilk; an update appears in
 * the essential idea of work stealing mentioned in Leiserson and Platt,
 * Programming Parallel Applications in Cilk
 */
void deque_init(events_deque_t *q, int size_hint) {
	atomic_init(&q->top, 0);
	atomic_init(&q->bottom, 0);
	atomic_init(&q->available, 0);
	deque_array_t *a = events_calloc(1, sizeof(deque_array_t) + sizeof(tasks_t *) * size_hint);
	if (a == NULL)
		abort();

	atomic_init(&a->size, size_hint);
	atomic_init(&q->array, a);
	atomic_flag_clear(&q->shutdown);
	atomic_flag_clear(&q->started);
	q->jobs = NULL;
	q->loop = NULL;
	q->type = DATA_DEQUE;
	deque_thread_set = true;
}

static void deque_resize(events_deque_t *q) {
	deque_array_t *a = (deque_array_t *)atomic_load_explicit(&q->array, memory_order_relaxed);
	size_t old_size = a->size;
	size_t new_size = old_size * 2;
	deque_array_t *new = events_calloc(1, sizeof(deque_array_t) + sizeof(tasks_t *) * new_size);
	if (new == NULL)
		abort();

	atomic_init(&new->size, new_size);
	size_t i, t = atomic_load_explicit(&q->top, memory_order_relaxed);
	size_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed);
	for (i = t; i < b; i++)
		new->buffer[i % new_size] = a->buffer[i % old_size];

	atomic_store_explicit(&q->array, new, memory_order_relaxed);
	/* The question arises as to the appropriate timing for releasing memory
	 * associated with the previous array denoted by *a. In the original Chase
	 * and Lev paper, this task was undertaken by the garbage collector, which
	 * presumably possessed knowledge about ongoing steal operations by other
	 * threads that might attempt to access data within the array.
	 *
	 * In our context, the responsible deallocation of *a cannot occur at this
	 * point, as another thread could potentially be in the process of reading
	 * from it. Thus, we opt to abstain from freeing *a in this context,
	 * resulting in memory leakage. It is worth noting that our expansion
	 * strategy for these queues involves consistent doubling of their size;
	 * this design choice ensures that any leaked memory remains bounded by the
	 * memory actively employed by the functional queues.
	 */
	events_free(a);
}

static tasks_t *deque_take(events_deque_t *q) {
	size_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed) - 1;
	size_t t = atomic_load_explicit(&q->top, memory_order_relaxed);
	deque_array_t *a = (deque_array_t *)atomic_load_explicit(&q->array, memory_order_relaxed);
	atomic_store_explicit(&q->bottom, b, memory_order_relaxed);
	atomic_thread_fence(memory_order_seq_cst);
	tasks_t *x;
	if (t <= b) {
		/* Non-empty queue */
		x = (tasks_t *)atomic_load_explicit(&a->buffer[b % a->size], memory_order_relaxed);
		if (t == b) {
			/* Single last element in queue */
			if (!atomic_compare_exchange_strong_explicit(&q->top, &t, t + 1,
				memory_order_seq_cst, memory_order_relaxed))
				/* Failed race */
				x = TASK_EMPTY_T;
			atomic_store_explicit(&q->bottom, b + 1, memory_order_relaxed);
		}
	} else { /* Empty queue */
		x = TASK_EMPTY_T;
		atomic_store_explicit(&q->bottom, b + 1, memory_order_relaxed);
	}

	return x;
}

static void deque_push(events_deque_t *q, tasks_t *w) {
	size_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed);
	size_t t = atomic_load_explicit(&q->top, memory_order_acquire);
	deque_array_t *a = (deque_array_t *)atomic_load_explicit(&q->array, memory_order_relaxed);
	if (b - t > a->size - 1) { /* Full queue */
		deque_resize(q);
		a = (deque_array_t *)atomic_load_explicit(&q->array, memory_order_relaxed);
	}

	atomic_store_explicit(&a->buffer[b % a->size], w, memory_order_relaxed);
	atomic_thread_fence(memory_order_release);
	atomic_store_explicit(&q->bottom, b + 1, memory_order_relaxed);
}

static tasks_t *deque_steal(events_deque_t *q) {
	size_t t = atomic_load_explicit(&q->top, memory_order_acquire);
	atomic_thread_fence(memory_order_seq_cst);
	size_t b = atomic_load_explicit(&q->bottom, memory_order_acquire);
	tasks_t *x = TASK_EMPTY_T;
	if (t < b) {
		/* Non-empty queue */
		deque_array_t *a = (deque_array_t *)atomic_load_explicit(&q->array, memory_order_consume);
		x = (tasks_t *)atomic_load_explicit(&a->buffer[t % a->size], memory_order_relaxed);
		if (!atomic_compare_exchange_strong_explicit(
			&q->top, &t, t + 1, memory_order_seq_cst, memory_order_relaxed))
			/* Failed race */
			return TASK_ABORT_T;
	}

	return x;
}

static void deque_free(events_deque_t *q) {
	deque_array_t *a = NULL;
	if (q != NULL) {
		a = atomic_get(deque_array_t *, &q->array);
		if (a != NULL) {
			atomic_store(&q->array, NULL);
			events_free((void *)a);
		}

		memset(q, 0, sizeof(*q));
		events_free(q);
	}
}

static void deque_destroy(void) {
	events_deque_t **queue = sys_event.local;
	if (queue != NULL) {
		size_t i, count = atomic_load(&sys_event.num_loops);
		sys_event.local, NULL;
		if (deque_thread_set) {
			for (i = 0; i < count; i++)
				atomic_flag_test_and_set(&queue[i]->shutdown);

			os_sleep(count);
			for (i = 0; i < count; i++) {
				if (data_type(queue[i]) == DATA_DEQUE) {
					queue[i]->type = DATA_INVALID;
					os_join(queue[i]->thread, -1, NULL);
					deque_free(queue[i]);
				}
			}
		}
		events_free(queue);
	}
}

static tasks_t *deque_peek(events_deque_t *q, int index) {
	deque_array_t *a = (deque_array_t *)atomic_load(&q->array);
	if ((a != NULL) && (index <= a->size))
		return (tasks_t *)atomic_load_explicit(&a->buffer[index % a->size], memory_order_relaxed);

	return NULL;
}
