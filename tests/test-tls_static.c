#include <events.h>
#include "assertions.h"
#define NUM_THREADS 8

tls_static(int, gLocalVar, 0)

/* Thread function: Compile time thread-local storage */
static int thread_test_local_storage(void *aArg) {
	int thread = *(int *)aArg;
	free(aArg);

	ASSERT_THREAD(is_gLocalVar_null());

	gLocalVar_set(&thread);
	ASSERT_THREAD(!is_gLocalVar_null());

	gLocalVar_reset();
	ASSERT_THREAD(is_gLocalVar_null());

	srand(thread);
	int data = thread + rand();
	*gLocalVar() = data;
	os_sleep(500);
	printf("\nthread #%d, gLocalVar is: %d\n", thread, *gLocalVar());
	ASSERT_THREAD((*gLocalVar() == data));
	os_exit(0);
	return 0;
}

TEST(gLocalVar) {
	os_thread_t t[NUM_THREADS];
	int i;
	/* Clear the TLS variable (it should keep this value after all
	   threads are finished). */
	*gLocalVar() = 1;

	for (i = 0; i < NUM_THREADS; i++) {
		int *n = malloc(sizeof * n);  // Holds a thread serial number
		*n = i;
		/* Start a child thread that modifies gLocalVar */
		t[i] = os_create(thread_test_local_storage, n);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		os_join(t[i], -1, NULL);
	}

	printf("\nmain gLocalVar is: %d\n", *gLocalVar());
	/* Check if the TLS variable has changed */
	ASSERT_TRUE((*gLocalVar() == 1));
	ASSERT_TRUE((++*gLocalVar() == 2));
	ASSERT_TRUE((--*gLocalVar() == 1));

	return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(gLocalVar);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
