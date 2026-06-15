#include "events.h"

int main(int argc, char *argv[]) {
	cerr("\nThis is stderr"CLR_LN);
	os_sleep(100);

	cout("This is stdout"CLR_LN);
    os_sleep(25);

	cout("\tSleeping..."CLR_LN);
	os_sleep(500);

	cout("`%s` argument received"CLR_LN, argv[1]);
	os_sleep(100);

	cerr("Exiting"CLR_LN);

    return 0;
}
