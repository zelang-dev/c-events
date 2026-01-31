#include <except.h>

static int div_err(int a, int b) {
    if (b == 0)
        throw(division_by_zero);

    return a / b;
}

static void pfree(void *p) {
    printf("freeing protected memory pointed by %s\n", (char *)p);
    free(p);
}

int main(int argc, char **argv) {
    void *p = fence(calloc(1, 3), pfree);
    if (p)
        strcpy(p, "p");
    div_err(1, 0);
    unreachable;

    free(p);

    return 0;
}
