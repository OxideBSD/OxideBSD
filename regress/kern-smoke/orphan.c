/*
 * kern-smoke orphan: a process whose parent exits is init's (CLEANUP.md §3): its parent process
 * ID becomes 1 and pid 1 reaps it with waitpid, whether it exits later or had exited already.
 */

/* Whether `pid` is gone (reaped) within about three seconds. */
static int reaped_soon(pid_t pid)
{
	for (int i = 0; i < 300; i++) {
		if (kill(pid, 0) == -1 && errno == ESRCH)
			return 1;
		usleep(10000);
	}
	return 0;
}

static void orphan_main(void)
{
	/* A middle process forks a grandchild and exits; the grandchild reports its new parent. */
	int p[2];
	pipe(p);
	pid_t mid = fork();
	if (mid == 0) {
		pid_t g = fork();
		if (g == 0) {
			close(p[0]);
			while (getppid() != 1)
				usleep(10000);
			char c = 'y';
			write(p[1], &c, 1);
			usleep(200000);
			_exit(0);
		}
		write(p[1], &g, sizeof g);
		_exit(0);
	}
	close(p[1]);
	pid_t g = 0;
	read(p[0], &g, sizeof g);
	waitpid(mid, NULL, 0);
	char c = 0;
	check(read(p[0], &c, 1) == 1 && c == 'y', "an orphan's parent becomes pid 1");
	check(reaped_soon(g), "and pid 1 reaps it when it exits");
	close(p[0]);

	/* A grandchild that has exited before its parent: already a zombie when pid 1 gets it. */
	pipe(p);
	mid = fork();
	if (mid == 0) {
		pid_t z = fork();
		if (z == 0)
			_exit(0);
		write(p[1], &z, sizeof z);
		usleep(200000); /* z is a zombie by now; never waited for */
		_exit(0);
	}
	close(p[1]);
	pid_t z = 0;
	read(p[0], &z, sizeof z);
	close(p[0]);
	waitpid(mid, NULL, 0);
	check(reaped_soon(z), "a zombie handed to pid 1 is reaped too");
}
