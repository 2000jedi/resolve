/* T3 fixture: cleanup-only `if (p) free(p);` is bm.yaml's `if ($V)`
 * not_seq form.  Pre-fix queryBadMalloc misses this and reports the
 * malloc as unchecked; post-fix the bare-truthy matcher suppresses. */
extern void *malloc(unsigned long);
extern void  free(void *);

void f(unsigned long n) {
    void *p;
    p = malloc(n);          /* CHECKED via cleanup `if (p) free(p)` — must NOT be reported */
    if (p) free(p);
}
