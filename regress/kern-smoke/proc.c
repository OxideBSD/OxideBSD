/*
 * kern-smoke proc: what /proc tells about a process (CLEANUP.md §3): stat's thread count, rss,
 * fault counts and signal masks, environ (the process's own user and root only), wchan, and
 * /proc/stat's boot time.
 */
#include <pthread.h>
#include <sched.h>
#include <time.h>

/* Field n (1-based, as proc(5) numbers them) of /proc/<pid>/stat, or -1. */
static long stat_field(pid_t pid, int n)
{
	char path[64], buf[2048];
	snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t len = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = 0;
	/* Fields after the command's closing parenthesis start at 3. */
	char *p = strrchr(buf, ')');
	if (p == NULL)
		return -1;
	p += 2;
	for (int i = 3; i < n; i++) {
		p = strchr(p, ' ');
		if (p == NULL)
			return -1;
		p++;
	}
	return strtol(p, NULL, 10);
}

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	ssize_t n, total = 0;
	while (total < (ssize_t)cap - 1 && (n = read(fd, buf + total, cap - 1 - total)) > 0)
		total += n;
	int e = n < 0 ? -errno : 0;
	close(fd);
	buf[total] = 0;
	return e < 0 ? e : (int)total;
}

static void *proc_idle(void *arg)
{
	(void)arg;
	pause();
	return NULL;
}

/* The environ of pid 1 (root's) read as another user: refused. */
static int foreign_environ(void)
{
	char buf[64];
	if (setgid(4250) != 0 || setuid(4250) != 0)
		return 10;
	return read_file("/proc/1/environ", buf, sizeof buf) == -EACCES ? 0 : 1;
}

static void proc_main(void)
{
	pid_t me = getpid();
	check(stat_field(me, 20) == 1, "stat: one thread");
	/* Blocked in every thread, so the SIGUSR1 sent below stays pending. */
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &old);
	pthread_t t;
	pthread_create(&t, NULL, proc_idle, NULL);
	check(stat_field(me, 20) == 2, "stat: two once a thread starts");
	check(stat_field(me, 24) > 0, "stat: rss");
	long minflt = stat_field(me, 10);
	volatile char *m = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	for (int i = 0; i < 16; i++)
		m[i * 4096] = 1;
	sched_yield();
	check(stat_field(me, 10) >= minflt + 16, "stat: minflt counts the faults");
	munmap((void *)m, 16 * 4096);

	kill(me, SIGUSR1);
	check(stat_field(me, 31) & (1 << (SIGUSR1 - 1)), "stat: the pending signals");
	signal(SIGUSR1, SIG_IGN);
	sigprocmask(SIG_SETMASK, &old, NULL);
	check(stat_field(me, 33) & (1 << (SIGUSR1 - 1)), "stat: the ignored signals");
	signal(SIGUSR1, SIG_DFL);

	char buf[8192];
	setenv("KERN_SMOKE_PROC", "here", 1);
	pid_t c = fork();
	if (c == 0) {
		char *argv[] = { "/bin/sleep", "5", NULL };
		char *envp[] = { "KERN_SMOKE_PROC=here", NULL };
		execve("/bin/sleep", argv, envp);
		_exit(127);
	}
	char path[64];
	snprintf(path, sizeof path, "/proc/%d/environ", (int)c);
	int got = 0;
	for (int i = 0; i < 50 && !got; i++) {
		usleep(20000);
		got = read_file(path, buf, sizeof buf) > 0 && strcmp(buf, "KERN_SMOKE_PROC=here") == 0;
	}
	check(got, "environ: what execve passed");
	snprintf(path, sizeof path, "/proc/%d/wchan", (int)c);
	got = 0;
	for (int i = 0; i < 50 && !got; i++) {
		usleep(20000);
		got = read_file(path, buf, sizeof buf) > 0 && strcmp(buf, "nanslp\n") == 0;
	}
	check(got, "wchan: nanslp in sleep(1)");
	kill(c, SIGKILL);
	waitpid(c, NULL, 0);
	check(child_exit_ok(foreign_environ), "environ: another user's is EACCES");

	check(read_file("/proc/stat", buf, sizeof buf) > 0 && strstr(buf, "\nbtime ") != NULL, "/proc/stat: btime");
	long btime = strtol(strstr(buf, "\nbtime ") + 7, NULL, 10);
	check(btime > 1700000000 && btime <= time(NULL), "and it is in the past");
}
