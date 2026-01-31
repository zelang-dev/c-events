
#include <except.h>

static int div_err(int a, int b) {
    if (b == 0)
        throw(division_by_zero);

    return a / b;
}

int main(int argc, char **argv) {
    try {
        div_err(1, 0);
        unreachable;
    } catch (division_by_zero) {
        printf("catch: exception %s (%s:%d) caught\n", err.name, err.file, err.line);
        rethrow;
        unreachable;
    } finally {
        if (err.name) {
            printf("finally: try failed -> %s (%s:%d)\n", err.name, err.file, err.line);
            rethrow;
            unreachable;
        } else
            printf("finally: try succeeded\n");
    }

    return 0;
}
