#include <except.h>

static void pfree(void *p) {
    printf("freeing protected memory pointed by '%s'\n", (char *)p);
    free(p);
}

int main(int argc, char **argv) {
    try {
        char *p = 0;
		p = fence(malloc(3), pfree);
		if (p)
            strcpy(p, "p");

        *(int *)0 = 0;
        unreachable;

        free(p);
    } catch_any {
        printf("catch: exception %s (%s:%d) caught\n", err.name, err.file, err.line);
    }

    return 0;
}
