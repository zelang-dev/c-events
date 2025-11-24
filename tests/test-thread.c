#include <events.h>
#include "assertions.h"

static int thdfunc(void *param) {
	ASSERT_XEQ(0x12345, (size_t)param);
	printf("tid: %zx\n", os_self());
	os_sleep(1000);
	return 1234;
}

TEST(os_create) {
	os_thread_t th = os_create(&thdfunc, (void *)0x12345);
	ASSERT_NOTNULL(th);

	os_cpumask cs = {0};
	os_cpumask_set(&cs, 0);
	ASSERT_TRUE(!os_affinity(th, &cs));

	puts("\nwaiting for thread...");
	int code;
	ASSERT_TRUE(0 == os_join(th, -1, &code));
	ASSERT_EQ(1234, code);

	os_detach(th); // noop

	ASSERT_NOTNULL((th = os_create(&thdfunc, (void*)0x12345)));
	puts("\nwaiting for thread...");

#if defined __APPLE__ && defined __MACH__
	ASSERT_TRUE(0 == os_join(th, 0, &code));
	ASSERT_EQ(1234, code);

	ASSERT_NOTNULL((th = os_create(&thdfunc, (void *)0x12345)));

#else
	ASSERT_TRUE(0 != os_join(th, 0, &code));
	ASSERT_EQ(ETIMEDOUT, os_geterror());
#endif

	puts("\nwaiting for thread...");
	ASSERT_TRUE(0 == os_join(th, 2000, &code));
	ASSERT_EQ(1234, code);

	return 0;
}

TEST(list) {
	int result = 0;

	EXEC_TEST(os_create);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
