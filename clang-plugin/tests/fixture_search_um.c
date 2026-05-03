// tests/fixture_search_um.c
extern void *malloc(unsigned long);
extern void  free(void *);

void f(unsigned long n) {
    void *p;
    p = malloc(n);                /* UNCHECKED — must be in CSV */

    void *q;
    q = malloc(2 * n);            /* CHECKED via == 0 — must NOT be in CSV */
    if (q == 0) return;

    void *r;
    r = malloc(3 * n);            /* CHECKED via ! — must NOT be in CSV */
    if (!r) return;

    free(p);
    free(q);
    free(r);
}
