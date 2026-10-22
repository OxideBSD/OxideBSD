/*
 * kern-smoke kthread: kernel threads (OxideBSD-doc KTHREAD.md). The test kernel
 * (tests/kern_syscall_smoke.rs) starts kernel threads that sleep, time out, wake each other, yield
 * and exit, and reports their verdict through SYS_TEST_KTHREAD; one of them sleeps for good, and
 * user mode can neither signal nor renice it (§3.4). The kthread_smoke module's own thread and
 * tasks report through SYS_KTHREAD_MOD (§7).
 */
#include <sched.h>

#define SYS_TEST_KTHREAD 9996
/* sys/modules/kthread_smoke's verdict (KTHREAD.md §7). */
#define SYS_KTHREAD_MOD 9993

static void kthread_main(void)
{
	long tid = syscall(SYS_TEST_KTHREAD, 0);
	check(tid > 1, "a kernel thread has a thread id of its own");
	errno = 0;
	check(kill(tid, SIGKILL) == -1 && errno == EPERM, "kill(SIGKILL) on it fails with EPERM");
	errno = 0;
	check(kill(tid, 0) == -1 && errno == EPERM, "... so does kill(0)");
	errno = 0;
	check(setpriority(PRIO_PROCESS, tid, 10) == -1 && errno == EPERM, "setpriority on it fails with EPERM");
	struct sched_param sp = { .sched_priority = 10 };
	errno = 0;
	check(sched_setscheduler(tid, SCHED_FIFO, &sp) == -1 && errno == EPERM,
	      "sched_setscheduler on it fails with EPERM");
	check(syscall(SYS_TEST_KTHREAD, 2) == 1, "... and it's still there");
	errno = 0;
	check(setpriority(PRIO_USER, 0, 0) == 0, "renicing root's processes passes kernel threads over");

	long verdict = 0;
	for (int i = 0; i < 200 && (verdict = syscall(SYS_TEST_KTHREAD, 1)) == 0; i++)
		usleep(50000);
	if (verdict != 1)
		printf("  kernel threads' verdict %#lx (failed checks %#lx)\n", verdict, verdict >> 8);
	check(verdict == 1, "the kernel threads slept, timed out, woke, yielded and exited");

	verdict = 0;
	for (int i = 0; i < 200 && (verdict = syscall(SYS_KTHREAD_MOD)) == 0; i++)
		usleep(50000);
	if (verdict != 1)
		printf("  kthread_smoke's verdict %#lx (failed checks %#lx)\n", verdict, verdict >> 8);
	check(verdict == 1, "a module's kernel threads and tasks ran through the kernel's exports");
}
