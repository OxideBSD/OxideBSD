/* Real musl ppoll() coverage on OxideBSD (seeded at /ppoll-smoke.elf, run by
 * regress/ppoll-syscall-smoke via tests/ppoll_syscall_smoke.rs). The mask checks are the ones
 * ninja's subprocess loop depends on: a blocked-but-pending signal interrupts a ppoll() whose mask
 * unblocks it, its handler runs, and the caller's original mask is back afterwards. The pipe
 * checks cover real readiness: empty pipes are not readable, write ends report POLLOUT, a closed
 * writer is POLLHUP, and a poll on an empty pipe genuinely waits for another process's write.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t handled;

#define CHECK(cond, what)                                                        \
	do {                                                                         \
		if (cond) {                                                              \
			printf("PASS %s\n", what);                                           \
		} else {                                                                 \
			printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));     \
			failures++;                                                          \
		}                                                                        \
	} while (0)

static void on_usr1(int sig)
{
	(void)sig;
	handled++;
}

static int usr1_blocked(void)
{
	sigset_t cur;
	sigprocmask(SIG_BLOCK, NULL, &cur);
	return sigismember(&cur, SIGUSR1);
}

int main(void)
{
	int p[2];
	CHECK(pipe(p) == 0, "pipe");
	CHECK(write(p[1], "x", 1) == 1, "write to pipe");

	/* readiness, no mask */
	struct pollfd pfd = { .fd = p[0], .events = POLLIN };
	int r = ppoll(&pfd, 1, NULL, NULL);
	CHECK(r == 1 && (pfd.revents & POLLIN), "ppoll reports a readable pipe");

	/* timeout with nothing to wait on */
	struct timespec short_wait = { 0, 20 * 1000 * 1000 };
	CHECK(ppoll(NULL, 0, &short_wait, NULL) == 0, "ppoll times out");

	/* invalid timeout */
	struct timespec bad = { 0, 1000000000 };
	errno = 0;
	CHECK(ppoll(&pfd, 1, &bad, NULL) == -1 && errno == EINVAL, "ppoll rejects tv_nsec >= 1e9");

	/* real pipe readiness */
	int q[2];
	CHECK(pipe(q) == 0, "second pipe");
	struct pollfd both[2] = { { .fd = q[0], .events = POLLIN }, { .fd = q[1], .events = POLLOUT } };
	r = poll(both, 2, 0);
	CHECK(r == 1 && both[0].revents == 0 && (both[1].revents & POLLOUT),
	      "empty pipe: read end not ready, write end POLLOUT");

	pid_t child = fork();
	if (child == 0) {
		usleep(100 * 1000);
		write(q[1], "y", 1);
		_exit(0);
	}
	struct pollfd rd = { .fd = q[0], .events = POLLIN };
	r = poll(&rd, 1, 5000);
	char c = 0;
	CHECK(r == 1 && (rd.revents & POLLIN) && read(q[0], &c, 1) == 1 && c == 'y',
	      "poll waits for another process to write the pipe");
	waitpid(child, NULL, 0);

	close(q[1]);
	r = poll(&rd, 1, 0);
	CHECK(r == 1 && (rd.revents & POLLHUP), "read end with no writers is POLLHUP");
	close(q[0]);

	/* mask semantics */
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr1;
	sigaction(SIGUSR1, &sa, NULL);
	sigset_t block_usr1, empty;
	sigemptyset(&block_usr1);
	sigaddset(&block_usr1, SIGUSR1);
	sigemptyset(&empty);
	sigprocmask(SIG_BLOCK, &block_usr1, NULL);

	raise(SIGUSR1); /* pending, blocked */
	CHECK(handled == 0, "blocked SIGUSR1 stays pending");

	r = ppoll(&pfd, 1, NULL, &block_usr1); /* mask keeps it blocked: the ready pipe wins */
	CHECK(r == 1 && handled == 0, "ppoll with SIGUSR1 still blocked returns the ready fd");

	errno = 0;
	r = ppoll(NULL, 0, NULL, &empty); /* mask unblocks it: EINTR, handler runs */
	CHECK(r == -1 && errno == EINTR, "ppoll whose mask unblocks a pending signal is EINTR");
	CHECK(handled == 1, "the handler ran during ppoll");
	CHECK(usr1_blocked(), "the original mask is restored afterwards");

	printf("%s: %d failure(s)\n", failures ? "ppoll-smoke FAILED" : "ppoll-smoke passed", failures);
	return failures;
}
