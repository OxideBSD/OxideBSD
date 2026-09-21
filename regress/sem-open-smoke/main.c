/* Real cross-process named POSIX semaphore coordination via sem_open()+fork() -- the scenario
 * `process::limits::futex_key` (sys/process/limits.rs) exists to make actually work. Real
 * `sem_open()` (external/mit/musl/src/thread/sem_open.c) backs a named semaphore with a real
 * `mmap(MAP_SHARED, ...)` of a `/dev/shm/<name>` file, `sem_init`'d with `pshared=1` -- which
 * clears musl's own `FUTEX_PRIVATE` bit on every subsequent `sem_wait`/`sem_post`. Two independent
 * processes calling `mmap()` on that same fd each land at their own, generally *different*,
 * virtual address (`NEXT_MMAP_PAGE`, `sys/process/mm.rs`'s own bump allocator, is a single counter
 * shared across every process, never reset per caller) -- so a `FUTEX_WAIT`/`FUTEX_WAKE`
 * implementation keyed on bare virtual address can never let this rendezvous actually happen. This
 * is deliberately plain, ordinary C -- no kernel-specific tricks -- matching
 * `regress/pthread-smoke/main.c`'s own "prove real, unmodified musl library code works end to
 * end" approach.
 *
 * Built via `build_sem_open_smoke` in build.rs (same `musl-gcc -static` recipe `build_musl_smoke`/
 * `build_pthread_smoke` already established), seeded into oxfs as `/sem-open-smoke.elf`, and
 * `fork`+`execve`'d by `regress/sem-open-syscall-smoke/` (a small Rust driver, the same shape
 * `regress/pthread-syscall-smoke/` already uses to drive a real musl fixture through a genuine
 * `SYSCALL`/`SYSRETQ` round trip).
 *
 * The child calls `sem_wait()` immediately after `fork()` returns; the parent calls a real,
 * blocking `usleep()` first (this kernel's own cooperative-round-robin scheduler always switches
 * to the only other ready process across a blocking syscall) before posting -- making it
 * overwhelmingly likely the child has already committed to a real `FUTEX_WAIT` block by the time
 * the parent's `sem_post()`/`FUTEX_WAKE` runs, so this genuinely exercises the cross-process wake
 * path rather than the semaphore's own same-process fast path.
 */
#include <fcntl.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <unistd.h>

#define SEM_NAME "/oxbsd-sem-open-smoke"

int main(void) {
    sem_unlink(SEM_NAME); /* clean slate -- harmless ENOENT if it never existed */

    sem_t *sem = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0644, 0);
    if (sem == SEM_FAILED) {
        write(2, "sem-open-smoke: sem_open failed\n", 33);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        write(2, "sem-open-smoke: fork failed\n", 29);
        return 1;
    }

    if (child == 0) {
        /* Real cross-process FUTEX_WAIT: `sem`'s own fd was independently mmap()'d in this
         * process's own address space at its own virtual address, distinct from the parent's. */
        if (sem_wait(sem) != 0) {
            write(2, "sem-open-smoke: child sem_wait failed\n", 39);
            _exit(1);
        }
        write(1, "sem-open-smoke: child woke up\n", 31);
        _exit(0);
    }

    usleep(50000); /* real blocking syscall -- yields to the child, see doc comment above */

    write(1, "sem-open-smoke: parent posting\n", 32);
    if (sem_post(sem) != 0) {
        write(2, "sem-open-smoke: sem_post failed\n", 33);
        return 1;
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        write(2, "sem-open-smoke: child failed\n", 30);
        return 1;
    }

    sem_close(sem);
    sem_unlink(SEM_NAME);
    write(1, "sem-open-smoke: PASS\n", 22);
    return 0;
}
