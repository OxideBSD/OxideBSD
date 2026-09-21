/* Reproduces the Open POSIX Test Suite's own pthread_cancel/5-1.c scenario in isolation, to find
 * out why a real crash inside it (see this file's own step 3 below) seems to leave the whole
 * kernel unable to run anything further afterward when this exact file runs as part of the full
 * ~1700-file pilot corpus (`pthread_cancel/5-1.c`, `CRASH(139)`, then no further pilot file ever
 * gets classified for the rest of that boot -- see CLAUDE.md's own write-up of this investigation).
 *
 * Steps (identical to the real pthread_cancel/5-1.c, not simplified):
 *  1. Create a thread that immediately calls pthread_exit().
 *  2. pthread_join() it -- real musl's own __pthread_join() really does `munmap(t->map_base,
 *     t->map_size)` on a clean join (external/mit/musl/src/thread/pthread_join.c), unmapping the
 *     joined thread's own stack, which is where its `struct pthread` control block itself lives.
 *  3. Call pthread_cancel() on that now-dead, now-unmapped `pthread_t`. Real musl's own
 *     pthread_cancel() (external/mit/musl/src/thread/pthread_cancel.c) does `a_store(&t->cancel, 1)`
 *     unconditionally -- no "is this thread still alive" check anywhere -- so this is a real write
 *     through freed, unmapped memory. This is expected to fault: on any correctly-behaving kernel,
 *     not just this one, since the target page is genuinely gone.
 *
 * `regress/pthread-cancel-crash-smoke/` (the driver) expects this process to be killed by a real,
 * uncaught SIGSEGV -- that part is the *expected*, not the bug under investigation. What the driver
 * checks is whether the *system* is still healthy immediately afterward.
 */
#include <pthread.h>
#include <stdio.h>

static void *a_thread_func(void *arg) {
    (void)arg;
    pthread_exit(0);
    return NULL;
}

int main(void) {
    pthread_t new_th;
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        fprintf(stderr, "pthread-cancel-crash: pthread_create failed\n");
        return 1;
    }
    pthread_join(new_th, NULL);
    pthread_cancel(new_th); /* expected to crash before returning */
    fprintf(stderr, "pthread-cancel-crash: pthread_cancel unexpectedly returned, no crash\n");
    return 1;
}
