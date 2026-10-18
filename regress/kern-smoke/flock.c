/*
 * kern-smoke flock: flock(2) waits for a conflicting lock (CLEANUP.md §4), fails at once with
 * LOCK_NB, gives up on a caught signal (EINTR), and is freed by close.
 */

static const char *flock_path = "/tmp/kern-smoke.flock";

static void on_alarm(int sig)
{
	(void)sig;
}

/* Takes LOCK_EX through an open of its own and reports on `out`. The descriptions inherited
 * from the parent are closed first: a lock belongs to the description, which a fork shares. */
static void flock_waiter(int out)
{
	for (int fd = 3; fd < 64; fd++)
		if (fd != out)
			close(fd);
	int fd = open(flock_path, O_RDWR);
	int r = flock(fd, LOCK_EX);
	char c = r == 0 ? 'y' : 'n';
	write(out, &c, 1);
	_exit(r == 0 ? 0 : 1);
}

/* Whether `fd` has a byte to read within `ms` milliseconds. */
static int readable_within(int fd, int ms)
{
	struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);
	return select(fd + 1, &set, NULL, NULL, &tv) == 1;
}

static int flock_interrupted(void)
{
	int fd = open(flock_path, O_RDWR);
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alarm; /* no SA_RESTART */
	sigaction(SIGALRM, &sa, NULL);
	alarm(1);
	errno = 0;
	int r = flock(fd, LOCK_EX);
	return r == -1 && errno == EINTR ? 0 : 1;
}

static void flock_main(void)
{
	int a = open(flock_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	int b = open(flock_path, O_RDWR);
	check(flock(a, LOCK_SH) == 0 && flock(b, LOCK_SH) == 0, "two shared locks coexist");
	errno = 0;
	check(flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK,
	      "upgrading past another shared lock with LOCK_NB is EWOULDBLOCK");
	flock(b, LOCK_UN);
	check(flock(a, LOCK_EX) == 0, "upgrading with no other holder works");

	int p[2];
	pipe(p);
	pid_t w = fork();
	if (w == 0) {
		close(p[0]);
		flock_waiter(p[1]);
	}
	close(p[1]);
	check(!readable_within(p[0], 300), "a conflicting flock waits");
	flock(a, LOCK_UN);
	char c = 0;
	check(readable_within(p[0], 3000) && read(p[0], &c, 1) == 1 && c == 'y', "and gets the lock once it's released");
	int st;
	waitpid(w, &st, 0);
	close(p[0]);

	check(flock(a, LOCK_EX) == 0, "the waiter's exit released its lock");
	check(child_exit_ok(flock_interrupted), "a caught signal interrupts the wait with EINTR");

	pipe(p);
	w = fork();
	if (w == 0) {
		close(p[0]);
		flock_waiter(p[1]);
	}
	close(p[1]);
	check(!readable_within(p[0], 300), "a second waiter waits");
	close(a); /* the last close of the holder's description */
	check(readable_within(p[0], 3000) && read(p[0], &c, 1) == 1 && c == 'y', "closing the holder wakes it");
	waitpid(w, &st, 0);
	close(p[0]);
	close(b);
	unlink(flock_path);
}
