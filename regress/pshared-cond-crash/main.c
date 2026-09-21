/* Isolates the real cross-process pthread_mutex/pthread_cond mechanism from the Open POSIX Test
 * Suite's own `pthread_cond_broadcast/1-2.c` (external/gpl2/posixtestsuite/conformance/interfaces/
 * pthread_cond_broadcast/1-2.c), which genuinely stalled somewhere in its real `fork==1` ("Pshared
 * ... mutex across processes") scenarios during a full pilot run.
 *
 * **Root cause, confirmed via this file**: a real, previously-undiscovered bug in this project's
 * own musl fork (external/mit/musl, `oxidebsd` branch) -- not a kernel bug. Real `fork()`
 * (external/mit/musl/src/process/fork.c) takes a real `LOCK()` on several internal locks, including
 * stdio's own `ofl_lock` (the "open file list" lock), in the parent *before* the real fork syscall,
 * whenever the process is genuinely multi-threaded (`libc.need_locks > 0` -- true here, since a
 * second real pthread, the timer thread below, already exists). The child therefore inherits
 * `ofl_lock` in a real, genuinely *locked* state. But `_Fork.c`'s own `reset_stdio_locks_in_child`
 * (an earlier fix for a *different* permanent hang, `fork/11-1.c` -- see that function's own doc
 * comment) unconditionally calls `__ofl_lock()` again to safely walk the open-FILE list -- which
 * tries to *re-acquire the exact same lock the child just inherited as held*, deadlocking the
 * child's own sole surviving thread forever (fork()'s own later child-side cleanup, which *would*
 * reset this lock, never gets the chance to run first). Only reproduces with **two or more** real
 * forked children *and* a real second thread already running in the parent at fork time -- one
 * child alone never contends the mutex enough to matter, and without a second thread,
 * `libc.need_locks` never becomes true, so `fork()`'s own pre-fork lock loop never runs at all.
 * Fixed on the musl side (`_Fork.c`'s own doc comment has the fix).
 *
 * Mechanism, matching the real test's own scenario index 8 ("Pshared default mutex across
 * processes") closely enough to reproduce the same real interaction:
 *  1. Real pthread_mutex_t + pthread_cond_t + sem_t in a real file-backed `MAP_SHARED` region
 *     (same `mkstemp("/tmp/...")` + `write` + `mmap` + `unlink` shape the real test uses).
 *  2. Both attrs get real `pthread_mutexattr_setpshared(PTHREAD_PROCESS_SHARED)`/
 *     `pthread_condattr_setpshared(PTHREAD_PROCESS_SHARED)`.
 *  3. A real background timer thread starts (present throughout the real test as its own
 *     userspace rescue-timeout mechanism) and blocks on a real `sem_wait`.
 *  4. `fork()`s `N_CHILDREN` real children. Each locks the mutex, increments a shared counter,
 *     `pthread_cond_wait()`s (real, blocking, cross-process) until the parent sets a predicate,
 *     then unlocks and exits.
 *  5. The parent real-busy-polls (lock/read count/unlock/`sched_yield()`, the real test's own
 *     "Make sure all children are waiting" shape) until *all* children have been counted, posts
 *     the timer thread's semaphore, then locks, sets the predicate, real
 *     `pthread_cond_broadcast()`s, unlocks, and `waitpid()`s each child in turn.
 *
 * `N_CHILDREN` is deliberately small (not the real test's own `MAX_PROCESS_CHILDREN = 200`) to
 * keep a single run fast while still exercising real multi-child pshared contention.
 */
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define N_CHILDREN 10

typedef struct {
    pthread_mutex_t mtx;
    pthread_cond_t cnd;
    sem_t sem_tmr;
    int count;
    int predicate;
} shared_data_t;

static shared_data_t *td;

static void *timer_thread(void *arg) {
    (void)arg;
    sem_wait(&td->sem_tmr);
    /* Real test sleeps up to TIMEOUT=180s then FAILED_KILLALLs; this repro relies on the outer
     * cargo-test harness's own bounded timeout to catch a real hang instead, so this thread just
     * exits once posted rather than replicating that real rescue-abort logic. */
    return NULL;
}

int main(void) {
    char filename[] = "/tmp/pshared_cond_crash-XXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        perror("pshared-cond-crash: mkstemp");
        return 1;
    }
    unlink(filename);

    size_t sz = sizeof(shared_data_t);
    char zeros[sizeof(shared_data_t)];
    memset(zeros, 0, sz);
    if (write(fd, zeros, sz) != (ssize_t)sz) {
        perror("pshared-cond-crash: write");
        return 1;
    }

    td = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (td == MAP_FAILED) {
        perror("pshared-cond-crash: mmap");
        return 1;
    }
    close(fd);

    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&td->mtx, &ma);
    pthread_mutexattr_destroy(&ma);

    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&td->cnd, &ca);
    pthread_condattr_destroy(&ca);

    sem_init(&td->sem_tmr, 0, 0);
    td->count = 0;
    td->predicate = 0;

    pthread_t t_timer;
    if (pthread_create(&t_timer, NULL, timer_thread, NULL) != 0) {
        write(2, "pshared-cond-crash: pthread_create (timer) failed\n", 52);
        return 1;
    }

    pid_t children[N_CHILDREN];
    for (int i = 0; i < N_CHILDREN; i++) {
        pid_t child = fork();
        if (child < 0) {
            perror("pshared-cond-crash: fork");
            return 1;
        }
        if (child == 0) {
            if (pthread_mutex_lock(&td->mtx) != 0) {
                write(2, "pshared-cond-crash: child mutex_lock failed\n", 46);
                _exit(1);
            }
            td->count++;
            while (!td->predicate) {
                if (pthread_cond_wait(&td->cnd, &td->mtx) != 0) {
                    write(2, "pshared-cond-crash: child cond_wait failed\n", 45);
                    _exit(1);
                }
            }
            pthread_mutex_unlock(&td->mtx);
            _exit(0);
        }
        children[i] = child;
    }
    write(1, "pshared-cond-crash: all children forked\n", 42);

    /* Real busy-poll loop, same shape the real test's own "Make sure all children are waiting"
     * step uses: repeatedly lock, read the shared count, unlock, sched_yield() if not everyone's
     * there yet. */
    int ch = 0;
    pthread_mutex_lock(&td->mtx);
    ch = td->count;
    while (ch < N_CHILDREN) {
        pthread_mutex_unlock(&td->mtx);
        sched_yield();
        pthread_mutex_lock(&td->mtx);
        ch = td->count;
    }
    pthread_mutex_unlock(&td->mtx);
    write(1, "pshared-cond-crash: all children counted\n", 43);

    sem_post(&td->sem_tmr);

    write(1, "pshared-cond-crash: parent broadcasting\n", 41);
    pthread_mutex_lock(&td->mtx);
    td->predicate = 1;
    if (pthread_cond_broadcast(&td->cnd) != 0) {
        write(2, "pshared-cond-crash: cond_broadcast failed\n", 43);
        return 1;
    }
    pthread_mutex_unlock(&td->mtx);

    for (int i = 0; i < N_CHILDREN; i++) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            write(2, "pshared-cond-crash: a child failed\n", 36);
            return 1;
        }
    }
    write(1, "pshared-cond-crash: all children joined\n", 41);

    pthread_join(t_timer, NULL);

    write(1, "pshared-cond-crash: PASS\n", 26);
    return 0;
}
