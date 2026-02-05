#include <except.h>

int main(int argc, char **argv) {
    try {
        raise(SIGINT);
        unreachable;
    } catch(sig_int) {
        printf("catch: exception %s (%s:%d) caught\n", err.name, err.file, err.line);

        try_backtrace(err.backtrace);
    } finally {
        if (err.name && err.is_caught)
            printf("\nfinally: try failed, but succeeded to catch -> %s (%s:%d)\n\n", err.name, err.file, err.line);
        else
            printf("\nfinally: try failed to `catch()`\n");
    }

    return 0;
}