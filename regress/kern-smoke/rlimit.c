/*
 * kern-smoke rlimit: resource limits (OxideBSD-doc CLEANUP.md §3-4): setrlimit's checks, and
 * RLIMIT_STACK, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_NPROC, RLIMIT_NOFILE (descriptor numbering,
 * SCM_RIGHTS) and RLIMIT_CPU (SIGXCPU, then SIGKILL) enforced.
 */

/* --- setrlimit's own rules --- */

static int unprivileged_raise(void)
{
	struct rlimit rl;
	if (setgid(4242) != 0 || setuid(4242) != 0)
		return 10;
	getrlimit(RLIMIT_CORE, &rl);
	rl.rlim_max = 1 << 20;
	rl.rlim_cur = 1 << 20;
	if (setrlimit(RLIMIT_CORE, &rl) != 0)
		return 11; /* lowering is anyone's */
	rl.rlim_max = 2 << 20;
	if (setrlimit(RLIMIT_CORE, &rl) == 0 || errno != EPERM)
		return 12; /* raising the hard limit is root's */
	rl.rlim_max = 1 << 20;
	rl.rlim_cur = 2 << 20;
	if (setrlimit(RLIMIT_CORE, &rl) == 0 || errno != EINVAL)
		return 13;
	return 0;
}

/* --- RLIMIT_STACK --- */

static volatile char sink;

/* Uses `bytes` of stack: a volatile frame the compiler can neither shrink nor turn into a loop. */
static void recurse(size_t bytes)
{
	volatile char buf[4096];
	buf[0] = (char)bytes;
	buf[sizeof buf - 1] = (char)bytes;
	if (bytes > sizeof buf)
		recurse(bytes - sizeof buf);
	sink = buf[0] + buf[sizeof buf - 1];
}

static int stack_small(void)
{
	struct rlimit rl = { 256 << 10, 256 << 10 };
	setrlimit(RLIMIT_STACK, &rl);
	recurse(1 << 20);
	return 0;
}

static int stack_large(void)
{
	struct rlimit rl = { 32 << 20, 32 << 20 };
	if (setrlimit(RLIMIT_STACK, &rl) != 0)
		return 1;
	recurse(16 << 20); /* past the old fixed 8 MiB reserve */
	return 0;
}

static int stack_exec(void)
{
	struct rlimit rl = { 32 << 10, 32 << 10 };
	setrlimit(RLIMIT_STACK, &rl);
	char *argv[] = { "true", NULL };
	execv("/bin/true", argv);
	return errno == E2BIG ? 0 : 1;
}

/* --- RLIMIT_DATA --- */

static int data_limit(void)
{
	long base = syscall(SYS_brk, 0);
	struct rlimit rl = { 64 << 10, 64 << 10 };
	setrlimit(RLIMIT_DATA, &rl);
	if (syscall(SYS_brk, base + (32 << 10)) == -1)
		return 1; /* under the limit */
	if (syscall(SYS_brk, base + (1 << 20)) != -1 || errno != ENOMEM)
		return 2;
	return 0;
}

/* --- RLIMIT_FSIZE --- */

static volatile sig_atomic_t xfsz;

static void on_xfsz(int sig)
{
	(void)sig;
	xfsz++;
}

static void fsize_checks(void)
{
	static char buf[8192];
	const char *path = "/tmp/rlimit-smoke.fsize";
	struct rlimit old, rl = { 4096, RLIM_INFINITY };
	getrlimit(RLIMIT_FSIZE, &old);
	signal(SIGXFSZ, on_xfsz);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	setrlimit(RLIMIT_FSIZE, &rl);
	check(write(fd, buf, sizeof buf) == 4096, "a write crossing RLIMIT_FSIZE is cut short");
	errno = 0;
	check(write(fd, buf, 1) == -1 && errno == EFBIG, "a write at RLIMIT_FSIZE fails with EFBIG");
	check(xfsz == 1, "and sends SIGXFSZ");
	errno = 0;
	check(ftruncate(fd, 8192) == -1 && errno == EFBIG, "ftruncate past RLIMIT_FSIZE fails");
	check(ftruncate(fd, 4096) == 0, "ftruncate up to RLIMIT_FSIZE works");
	check(pwrite(fd, buf, 16, 100) == 16, "a write under the limit works");
	setrlimit(RLIMIT_FSIZE, &old);
	signal(SIGXFSZ, SIG_DFL);
	close(fd);
	unlink(path);
}

/* --- RLIMIT_NPROC --- */

static int nproc_limit(void)
{
	if (setgid(4243) != 0 || setuid(4243) != 0)
		return 10;
	struct rlimit rl = { 2, 2 };
	if (setrlimit(RLIMIT_NPROC, &rl) != 0)
		return 11;
	int p[2];
	pipe(p);
	pid_t first = fork();
	if (first == 0) {
		char c;
		close(p[1]);
		read(p[0], &c, 1); /* stays until the parent is done */
		_exit(0);
	}
	if (first < 0)
		return 12;
	pid_t second = fork();
	int refused = second < 0 && errno == EAGAIN;
	if (second == 0)
		_exit(0);
	close(p[1]);
	waitpid(first, NULL, 0);
	return refused ? 0 : 13;
}

/* --- RLIMIT_NOFILE: descriptor numbering, SCM_RIGHTS --- */

static void fd_numbering(void)
{
	enum { N = 300 };
	static int fds[N];
	int ok = 1;
	for (int i = 0; i < N; i++)
		if ((fds[i] = open("/dev/null", O_RDONLY)) < 0)
			ok = 0;
	check(ok, "300 descriptors open");
	int lo = fds[70], mid = fds[150];
	close(lo);
	close(mid);
	int a = dup(0), b = dup(0);
	check(a == lo && b == mid, "dup takes the lowest free numbers");
	close(fds[200]);
	int c = fcntl(0, F_DUPFD, fds[150] + 1);
	check(c == fds[200], "F_DUPFD takes the lowest free number at or past its minimum");
	int d = fcntl(0, F_DUPFD, 1000);
	check(d == 1000, "F_DUPFD past every open descriptor");
	close(a);
	close(b);
	close(c);
	close(d);
	for (int i = 0; i < N; i++)
		if (i != 70 && i != 150 && i != 200)
			close(fds[i]);
}

static int rights_past_nofile(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 10;
	int send_fds[3] = { 0, 1, 2 };
	char cbuf[CMSG_SPACE(sizeof send_fds)];
	memset(cbuf, 0, sizeof cbuf);
	char byte = 'x';
	struct iovec iov = { &byte, 1 };
	struct msghdr mh = { 0 };
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof cbuf;
	struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof send_fds);
	memcpy(CMSG_DATA(cm), send_fds, sizeof send_fds);
	if (sendmsg(sv[0], &mh, 0) != 1)
		return 11;
	/* Room for one more descriptor, not three. */
	int highest = sv[0] > sv[1] ? sv[0] : sv[1];
	for (int fd = 3; fd < highest; fd++)
		if (fd != sv[0] && fd != sv[1])
			close(fd);
	struct rlimit rl = { (rlim_t)highest + 2, RLIM_INFINITY };
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		return 12;
	memset(cbuf, 0, sizeof cbuf);
	mh.msg_controllen = sizeof cbuf;
	errno = 0;
	if (recvmsg(sv[1], &mh, 0) != -1 || errno != EMSGSIZE)
		return 13;
	/* The rights are gone; the byte is still there. */
	mh.msg_controllen = sizeof cbuf;
	if (recvmsg(sv[1], &mh, 0) != 1 || byte != 'x' || mh.msg_controllen != 0)
		return 14;
	return 0;
}

static volatile sig_atomic_t got_xcpu;

static void on_xcpu(int sig)
{
	(void)sig;
	got_xcpu = 1;
}

/* Spins past a 1 s soft RLIMIT_CPU (hard 5 s) until SIGXCPU arrives. */
static int cpu_soft(void)
{
	struct rlimit rl = { 1, 5 };
	signal(SIGXCPU, on_xcpu);
	if (setrlimit(RLIMIT_CPU, &rl) != 0)
		return 10;
	while (!got_xcpu)
		;
	return 0;
}

/* Spins into a 1 s hard RLIMIT_CPU: SIGKILL. */
static int cpu_hard(void)
{
	struct rlimit rl = { 1, 1 };
	if (setrlimit(RLIMIT_CPU, &rl) != 0)
		return 10;
	for (;;)
		;
}

static void rlimit_main(void)
{
	struct rlimit rl;

	getrlimit(RLIMIT_STACK, &rl);
	check(rl.rlim_cur == 8 << 20 && rl.rlim_max == 512 << 20, "RLIMIT_STACK starts at 8 MiB / 512 MiB");

	rl.rlim_cur = 2 << 20;
	rl.rlim_max = 1 << 20;
	errno = 0;
	check(setrlimit(RLIMIT_CORE, &rl) == -1 && errno == EINVAL, "a soft limit above the hard one is EINVAL");
	check(child_exit_ok(unprivileged_raise), "only root raises a hard limit");

	int st = in_child(stack_small);
	check(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "growing the stack past RLIMIT_STACK is SIGSEGV");
	if (!(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV))
		printf("kern-smoke: stack_small status %#x\n", st);
	check(child_exit_ok(stack_large), "a raised RLIMIT_STACK lets the stack grow past 8 MiB");
	check(child_exit_ok(stack_exec), "execve with a stack too small for its arguments is E2BIG");

	check(child_exit_ok(data_limit), "brk past RLIMIT_DATA is ENOMEM");
	fsize_checks();
	check(child_exit_ok(nproc_limit), "fork past RLIMIT_NPROC is EAGAIN");

	fd_numbering();
	check(child_exit_ok(rights_past_nofile), "SCM_RIGHTS past RLIMIT_NOFILE is EMSGSIZE, rights discarded");

	check(child_exit_ok(cpu_soft), "past the soft RLIMIT_CPU: SIGXCPU");
	st = in_child(cpu_hard);
	check(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "at the hard RLIMIT_CPU: SIGKILL");
}
