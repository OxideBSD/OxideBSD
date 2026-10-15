/*
 * vfork(2) (OxideBSD-doc COW.md §7), through musl: vfork() is system call 586, and
 * posix_spawn() is clone(CLONE_VM|CLONE_VFORK). The child borrows the parent's address space;
 * the parent sleeps until the child execs or exits. Run by regress/vfork-syscall-smoke as
 * /usr/tests/vfork/vfork-smoke; prints one line per check and exits 0 only if all pass.
 */
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

extern char **environ;

static int failures;

static void check(int ok, const char *what)
{
	printf("vfork-smoke: %s: %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		failures++;
}

/* Written by the child, read by the parent: one address space while it borrows. */
static volatile int shared_word;
static volatile sig_atomic_t got_usr1;

static void on_usr1(int sig)
{
	(void)sig;
	got_usr1 = 1;
}

static void sleep_ms(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

/* Reads /proc/<pid>/status and returns whether it holds `needle`. */
static int status_has(pid_t pid, const char *needle)
{
	char path[64], buf[1024];
	snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	return strstr(buf, needle) != NULL;
}

static int exited_zero(pid_t pid)
{
	int status;
	return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* The child's writes land in the parent's memory, and the parent runs only after the child's
 * _exit: everything the child did is there when vfork returns. */
static void test_borrow(void)
{
	shared_word = 0;
	pid_t pid = vfork();
	if (pid == 0) {
		for (int i = 0; i < 1000; i++)
			(void)getpid();
		shared_word = 42;
		_exit(0);
	}
	check(pid > 0, "vfork returns the child's pid");
	check(shared_word == 42, "the child's write is in the parent's memory");
	check(exited_zero(pid), "the child exits 0");
}

/* exec ends the borrow: the parent wakes, and the child keeps running the new program. */
static void test_exec(void)
{
	shared_word = 0;
	pid_t pid = vfork();
	if (pid == 0) {
		shared_word = 7;
		execl("/bin/true", "true", (char *)0);
		_exit(127);
	}
	check(shared_word == 7, "the child wrote before its exec");
	check(exited_zero(pid), "the exec'd /bin/true exits 0");
}

/* A failed exec keeps the borrow; the child's _exit then ends it. */
static void test_failed_exec(void)
{
	volatile int failed_errno = 0;
	pid_t pid = vfork();
	if (pid == 0) {
		execl("/nonexistent/vfork-smoke", "x", (char *)0);
		failed_errno = errno;
		_exit(111);
	}
	int status;
	check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 111,
	      "a failed exec, then _exit(111)");
	check(failed_errno == ENOENT, "the parent sees the child's errno, ENOENT");
}

/* While it waits, the parent shows FreeBSD's ppwait as D, and the child carries PPWait. */
static void test_proc(void)
{
	volatile int parent_ppwait = 0, child_flag = 0;
	pid_t parent = getpid();
	pid_t pid = vfork();
	if (pid == 0) {
		parent_ppwait = status_has(parent, "State:\tD (ppwait)");
		child_flag = status_has(getpid(), "PPWait:\t1");
		_exit(0);
	}
	exited_zero(pid);
	check(parent_ppwait, "/proc/<parent>/status: State D (ppwait) while it waits");
	check(child_flag, "/proc/<child>/status: PPWait 1 while it borrows");
	check(status_has(getpid(), "State:\tR"), "the parent runs again afterwards");
}

/* A caught signal stays pending while the parent waits; it runs once the child is done. */
static void test_signal_pending(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr1;
	sigaction(SIGUSR1, &sa, 0);
	got_usr1 = 0;
	volatile int seen_in_child = -1;
	pid_t parent = getpid();
	pid_t pid = vfork();
	if (pid == 0) {
		kill(parent, SIGUSR1);
		sleep_ms(50);
		/* The handler would have run in the parent, writing this same memory. */
		seen_in_child = got_usr1;
		_exit(0);
	}
	check(seen_in_child == 0, "SIGUSR1 doesn't wake the waiting parent");
	exited_zero(pid);
	check(got_usr1 == 1, "SIGUSR1's handler runs after the child exits");
	signal(SIGUSR1, SIG_DFL);
}

/* SIGKILL ends the waiting parent where it sleeps; the child keeps the address space. Done in a
 * forked process P, whose vfork child C kills it and reports through a pipe. */
static void test_sigkill(void)
{
	int fds[2];
	if (pipe(fds) != 0) {
		check(0, "pipe for the SIGKILL test");
		return;
	}
	pid_t p = fork();
	if (p == 0) {
		close(fds[0]);
		pid_t me = getpid();
		pid_t c = vfork();
		if (c == 0) {
			kill(me, SIGKILL);
			/* P is a zombie now (or already reaped), and this memory still works. */
			char path[64];
			snprintf(path, sizeof path, "/proc/%d/status", (int)me);
			char msg = status_has(me, "State:\tZ") || access(path, F_OK) != 0 ? 'Z' : '?';
			write(fds[1], &msg, 1);
			_exit(0);
		}
		_exit(3); /* never reached: killed in vfork */
	}
	close(fds[1]);
	int status;
	check(waitpid(p, &status, 0) == p && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "SIGKILL kills the parent waiting in vfork");
	char msg = 0;
	ssize_t n = read(fds[0], &msg, 1);
	close(fds[0]);
	check(n == 1 && msg == 'Z', "the child outlives its killed parent");
}

/* The child's shm attachment belongs to the shared address space: its exec doesn't detach it,
 * so the segment survives IPC_RMID until the parent detaches. (With bookkeeping of its own, the
 * exec would free frames the parent still maps.) */
static void test_shm(void)
{
	int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	if (id < 0) {
		check(0, "shmget");
		return;
	}
	volatile char *volatile addr = 0;
	pid_t pid = vfork();
	if (pid == 0) {
		char *p = shmat(id, 0, 0);
		if (p == (char *)-1)
			_exit(1);
		p[0] = 'v';
		addr = p;
		shmctl(id, IPC_RMID, 0);
		execl("/bin/true", "true", (char *)0);
		_exit(127);
	}
	check(exited_zero(pid), "the child shmat, IPC_RMID, exec /bin/true");
	check(addr != 0 && addr[0] == 'v', "the segment is still mapped and intact in the parent");
	struct shmid_ds ds;
	check(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1, "the segment still has nattch 1");
	check(addr != 0 && shmdt((const void *)addr) == 0, "the parent detaches it");
	check(shmctl(id, IPC_STAT, &ds) == -1, "now it's gone");
}

/* malloc in the child moves the shared break; the parent's malloc keeps working after it. */
static void test_malloc(void)
{
	char *volatile p = 0;
	pid_t pid = vfork();
	if (pid == 0) {
		p = malloc(256 * 1024);
		if (p)
			memset(p, 'm', 256 * 1024);
		_exit(0);
	}
	exited_zero(pid);
	check(p && p[0] == 'm' && p[256 * 1024 - 1] == 'm', "the child's malloc is the parent's memory");
	free(p);
	char *q = malloc(512 * 1024);
	check(q != 0, "the parent mallocs afterwards");
	if (q) {
		memset(q, 'q', 512 * 1024);
		free(q);
	}
}

/* posix_spawn: musl's clone(CLONE_VM|CLONE_VFORK), the exec error reported through a pipe. */
static void test_posix_spawn(void)
{
	pid_t pid;
	char *argv[] = { "true", 0 };
	check(posix_spawn(&pid, "/bin/true", 0, 0, argv, environ) == 0 && exited_zero(pid),
	      "posix_spawn /bin/true");
	check(posix_spawn(&pid, "/nonexistent/vfork-smoke", 0, 0, argv, environ) == ENOENT,
	      "posix_spawn of a missing file: ENOENT");
}

int main(void)
{
	setvbuf(stdout, 0, _IONBF, 0);
	test_borrow();
	test_exec();
	test_failed_exec();
	test_proc();
	test_signal_pending();
	test_sigkill();
	test_shm();
	test_malloc();
	test_posix_spawn();
	printf("vfork-smoke: %s\n", failures ? "FAILED" : "all passed");
	return failures ? 1 : 0;
}
