/* T2 fixture: declaration-with-initializer `T *p = malloc(n);` shape.
 * Pre-fix queryBadMalloc filters Decl-typed parents and silently misses
 * this form.  Post-fix walks Decl parents too. */
extern void *malloc(unsigned long);

void f(unsigned long n) {
    void *p = malloc(n);   /* UNCHECKED — must be in CSV after T2 */
    (void)p;
}
