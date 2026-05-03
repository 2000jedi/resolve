/* T4 fixture: a pre-malloc check on the same variable must NOT suppress
 * the post-malloc unchecked use.  Pre-fix queryBadMalloc accepts ANY
 * if-stmt anywhere in the TU; post-fix requires the if-stmt to occur
 * after the malloc within the same function. */
extern void *malloc(unsigned long);

void f(unsigned long n) {
    void *p = (void *)0;
    if (p == 0) { /* nothing — pre-malloc */ }
    p = malloc(n);   /* UNCHECKED post-malloc — must be in CSV after T4 */
    (void)p;
}
