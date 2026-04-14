#include "assertions.h"

void *task(param_t req) {
	ASSERT_TASK(($size(req) == 1));
	sleep(1);
	return $(casting(req->integer));
}

void *task_after(tuple_t req) {
	ASSERT_TASK(($size(req) == 1));
	ASSERT_TASK((7 <= req->integer));
	return 0;
}

void *task_after2(tuple_t req) {
	ASSERT_TASK(($size(req) == 1));
	ASSERT_TASK((9 == req->integer));
	return 0;
}

void *worker_misc(param_t args) {
	ASSERT_TASK(($size(args) == 3));
	ASSERT_TASK(str_is("queue_work", args[1].char_ptr));
	delay(args[0].u_int);
    return args[2].char_ptr;
}

TEST(queue_work) {
	array_t arr = array(), arr2 = array();
	uint32_t res = async_task(worker_misc, 3, casting(6000), "queue_work", "finish");
	promise *f1 = queue_work(futures_pool(), task, 1, casting(7));

	$append(arr, f1);
	ASSERT_FALSE(task_is_ready(res));
	ASSERT_TRUE(is_promise(f1));
	ASSERT_TRUE(queue_is_valid(f1));
	queue_wait(arr, (then_cb)task_after);
	ASSERT_FALSE(is_data(arr));

	promise *f2 = queue_work(futures_pool(), task, 1, casting(8));
	ASSERT_FALSE(task_is_ready(res));
	$append(arr2, f2);
	ASSERT_TRUE(queue_is_valid(f2));
	queue_wait(arr2, (then_cb)task_after);
	ASSERT_FALSE(is_data(arr2));

	promise *f3 = queue_work(futures_pool(), task, 1, casting(9));
	ASSERT_TRUE(queue_is_valid(f3));
	arr2 = array();

	$append(arr2, f3);
	queue_wait(arr2, (then_cb)task_after2);
	ASSERT_FALSE(is_data(arr2));
	ASSERT_FALSE(is_promise(arr2));

	ASSERT_FALSE(task_is_ready(res));

	ASSERT_FALSE(queue_is_valid(f1));
	ASSERT_FALSE(queue_is_valid(f2));
	ASSERT_FALSE(queue_is_valid(f3));

	try {
		ASSERT_EQ(9, queue_get(f3).integer);
	} catch (logic_error) {
		ASSERT_STR(err.name, "logic_error");
	}

	while (!task_is_ready(res))
		yield();

	ASSERT_TRUE(task_is_ready(res));
	ASSERT_STR(results_for(res).char_ptr, "finish");

	return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(queue_work);

	return result;
}

void *main_main(param_t args) {
	TEST_TASK(list());
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_init_pool(20);
	async_task(main_main, 0);
	async_run(loop);
	events_destroy(loop);
	return 0;
}