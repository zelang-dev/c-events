#include <except.h>

static int segfault(int a, int b) {
    return *(int *)0 = b;
}

int main(int argc, char **argv) {
    try {
        segfault(1, 0);
        unreachable;
    } catch_any{
        printf("catch_any: exception %s (%s:%d) caught\n", err.name, err.file, err.line);
    }

    return 0;
}
