#include "events.h"

int main(int argc, char *argv[]) {
	const char *req_method = getenv("REQUEST_METHOD");
	const char *power_by = getenv("HTTP_X_POWER_BY");
	const char *con_length = getenv("CONTENT_LENGTH");
	cerr("\nThe environment has %s, %s, %s."CLR_LN, req_method, power_by, con_length);
	os_sleep(100);

	cout("The REQUEST_METHOD %s"CLR_LN, req_method);
    os_sleep(25);

	cout("\tSleeping... %s!"CLR_LN, power_by);
	os_sleep(500);

	cout("CONTENT_LENGTH `%s`"CLR_LN, con_length);
	os_sleep(100);

	cout("`%s` argument received"CLR_LN, argv[1]);
	os_sleep(100);

	cerr("Exiting"CLR_LN);

	return 0;
}
