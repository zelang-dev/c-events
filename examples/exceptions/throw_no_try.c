#include <except.h>

static int div_err(int a, int b) {
    if (b == 0)
        throw(division_by_zero);

    return a / b;
}

int main(int argc, char **argv) {
    ex_signal_setup();
    div_err(1, 0);
    unreachable;

    return 0;
}
