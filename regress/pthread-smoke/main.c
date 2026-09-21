/* OxideBSD's "Real threading" phases 1-5 finish line -- a genuine, unmodified musl
 * pthread_create()/pthread_join() round trip, not a raw syscall(SYS_CLONE, ...) test (see
 * regress/clone-syscall-smoke/ for the kernel-primitive-only proof this builds on). Deliberately
 * plain, ordinary C code -- no kernel-specific tricks anywhere in this file -- since the entire
 * point is proving real musl thread-library code, completely unaware it's running on OxideBSD,
 * works end to end: a second thread genuinely runs on its own musl-managed stack, shares the first
 * thread's own memory (real CLONE_VM), and joins back cleanly through musl's own real futex-based
 * pthread_join (CLONE_THREAD + futex, phases 2/3) -- including musl's own thread return-value
 * propagation, which `clone-syscall-smoke`'s raw-syscall test has no equivalent for at all (there is
 * no "thread return value" concept below the pthread_join API layer).
 *
 * Built via `build_pthread_smoke` in build.rs (same `musl-gcc -static` recipe `build_musl_smoke`
 * already established for `regress/musl-smoke/`, against the existing static sysroot -- no need
 * for `build_musl_sysroot_shared`'s separate -fPIC build; threading needs no dynamic linking),
 * seeded into oxfs as `/pthread-smoke.elf`, and `fork`+`execve`'d by
 * `regress/pthread-syscall-smoke/` (a small Rust driver, the same shape
 * `regress/dynlink-syscall-smoke/` already uses to drive a real musl fixture through a genuine
 * `SYSCALL`/`SYSRETQ` round trip).
 */
#include <pthread.h>
#include <unistd.h>

static volatile long shared_value = 0;

static void *thread_main(void *arg) {
    (void)arg;
    write(1, "pthread-smoke: thread running\n", 31);
    /* Real CLONE_VM proof: visible through the main thread's own view of the same static below,
     * only if the address space really is shared, not copied. */
    shared_value = 424242;
    return (void *)(long)777;
}

int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, thread_main, NULL) != 0) {
        write(2, "pthread-smoke: pthread_create failed\n", 38);
        return 1;
    }

    /* Real futex-based join -- musl's own __timedwait_cp(&t->detach_state, ...), woken by the
     * thread's own __pthread_exit right before its SYS_EXIT. */
    void *retval = 0;
    if (pthread_join(t, &retval) != 0) {
        write(2, "pthread-smoke: pthread_join failed\n", 36);
        return 1;
    }

    if (shared_value != 424242) {
        write(2, "pthread-smoke: shared write not visible -- CLONE_VM broken\n", 61);
        return 1;
    }

    if ((long)retval != 777) {
        write(2, "pthread-smoke: pthread_join didn't report the real thread return value\n", 73);
        return 1;
    }

    write(1, "pthread-smoke: PASS\n", 21);
    return 0;
}
