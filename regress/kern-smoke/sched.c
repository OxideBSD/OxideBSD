/*
 * kern-smoke sched: the 4BSD time-sharing scheduler (CLEANUP.md §3): nice shifts CPU between
 * CPU-bound processes, setpriority follows POSIX and the BSDs (PRIO_PGRP, PRIO_USER, EACCES for
 * lowering a nice value without privilege), and times(2)/getrusage(2) split user and system time.
 */
#include <sys/times.h>
#include <time.h>

static double now_seconds(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Spins until `until`, then writes how many loops it managed. */
static void spinner(int nice_value, double until, int out)
{
	setpriority(PRIO_PROCESS, 0, nice_value);
	unsigned long n = 0;
	while (now_seconds() < until)
		for (volatile int i = 0; i < 1000; i++)
			n++;
	write(out, &n, sizeof n);
	_exit(0);
}

static int busy_then_rusage(void)
{
	double until = now_seconds() + 0.6;
	while (now_seconds() < until)
		;
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	long user_ms = ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000;
	long sys_ms = ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000;
	struct tms t;
	times(&t);
	if (user_ms < 300 || sys_ms > user_ms || t.tms_utime < 30)
		return 1;
	return 0;
}

static int unprivileged_nice(void)
{
	if (setgid(4244) != 0 || setuid(4244) != 0)
		return 10;
	if (setpriority(PRIO_PROCESS, 0, 5) != 0)
		return 11; /* raising one's nice value is anyone's */
	errno = 0;
	if (getpriority(PRIO_PROCESS, 0) != 5 || errno != 0)
		return 12;
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, 0) != -1 || errno != EACCES)
		return 13;
	errno = 0;
	if (setpriority(PRIO_PROCESS, 1, 10) != -1 || errno != EPERM)
		return 14; /* pid 1 is root's */
	return 0;
}

static int pgrp_and_user(void)
{
	setpgid(0, 0);
	if (setpriority(PRIO_PGRP, 0, 7) != 0 || getpriority(PRIO_PROCESS, 0) != 7)
		return 1;
	if (setgid(4245) != 0 || setuid(4245) != 0)
		return 2;
	if (setpriority(PRIO_USER, 4245, 9) != 0 || getpriority(PRIO_USER, 0) != 9)
		return 3;
	errno = 0;
	if (setpriority(PRIO_USER, 4246, 9) != -1 || errno != ESRCH)
		return 4;
	return 0;
}

static void sched_main(void)
{
	int p0[2], p1[2];
	pipe(p0);
	pipe(p1);
	double until = now_seconds() + 3.0;
	pid_t a = fork();
	if (a == 0)
		spinner(0, until, p0[1]);
	pid_t b = fork();
	if (b == 0)
		spinner(15, until, p1[1]);
	unsigned long na = 0, nb = 0;
	read(p0[0], &na, sizeof na);
	read(p1[0], &nb, sizeof nb);
	waitpid(a, NULL, 0);
	waitpid(b, NULL, 0);
	printf("kern-smoke: nice 0 ran %lu loops, nice 15 %lu\n", na, nb);
	check(na > 2 * nb, "a nice 0 process gets well over twice a nice 15 one's CPU");
	check(nb > 0, "and the nice 15 one isn't starved");

	check(child_exit_ok(busy_then_rusage), "getrusage and times report user time, little system time");
	struct tms t;
	times(&t);
	check(t.tms_cutime > 0, "times reports reaped children's time");
	struct rusage ru;
	getrusage(RUSAGE_CHILDREN, &ru);
	check(ru.ru_utime.tv_sec > 0 || ru.ru_utime.tv_usec > 0, "and so does getrusage(RUSAGE_CHILDREN)");
	errno = 0;
	check(getrusage(42, &ru) == -1 && errno == EINVAL, "getrusage refuses an unknown who");

	check(child_exit_ok(unprivileged_nice), "only root lowers a nice value; others' processes are EPERM");
	check(child_exit_ok(pgrp_and_user), "PRIO_PGRP and PRIO_USER");
}
