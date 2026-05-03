// tests/fixture_search_malloc.c
extern void *malloc(unsigned long);
extern void *calloc(unsigned long, unsigned long);
extern void  free(void *);

void f(unsigned long n) {
    void *p = malloc(n);          /* line 6: counted */
    void *q = (char *)malloc(2*n);/* line 7: counted (cast wraps malloc) */
    void *r = calloc(n, 8);       /* line 8: NOT counted (calloc, not malloc) */
    free(p);
    free(q);
    free(r);
}
