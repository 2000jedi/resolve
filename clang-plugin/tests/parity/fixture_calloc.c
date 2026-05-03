/* T1 fixture: calloc-family allocator should be flagged when its result is
 * never null-checked.  Pre-fix queryBadMalloc uses regex `.*malloc.*` and
 * misses calloc; post-fix uses `.*alloc.*` and reports it. */
extern void *calloc(unsigned long, unsigned long);

void f(unsigned long n) {
    void *p;
    p = calloc(n, 8);   /* UNCHECKED — must be in CSV after T1 */
    (void)p;
}
