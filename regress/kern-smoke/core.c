/*
 * kern-smoke core: core dumps (CLEANUP.md §3: RLIMIT_CORE): a process killed by SIGABRT or
 * SIGSEGV leaves an ELF core (ET_CORE, a CORE NT_PRSTATUS with the signal, PT_LOAD segments) and
 * its wait status says so (WCOREDUMP); RLIMIT_CORE 0, kern.coredump 0, a changed credential and
 * SIGKILL leave none; kern.corefile names it.
 */
#include <elf.h>

static const char *core_dir = "/tmp/kern-smoke-core";

static int die_abort(void)
{
	chdir(core_dir);
	abort();
	return 1;
}

static int die_segv(void)
{
	chdir(core_dir);
	*(volatile int *)16 = 1;
	return 1;
}

static int die_abort_no_limit(void)
{
	struct rlimit rl = { 0, RLIM_INFINITY };
	setrlimit(RLIMIT_CORE, &rl);
	return die_abort();
}

static int die_after_setuid(void)
{
	setgid(4249);
	setuid(4249);
	return die_abort();
}

/* The core's size, or -1; checks it's an x86-64 ELF core with `sig` in its first NT_PRSTATUS. */
static long check_core(const char *path, int sig)
{
	static char buf[1 << 16];
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof buf);
	struct stat st;
	fstat(fd, &st);
	close(fd);
	if (n < (ssize_t)sizeof(Elf64_Ehdr))
		return -2;
	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_type != ET_CORE || eh->e_machine != EM_X86_64)
		return -3;
	if ((st.st_mode & 0777) != 0600)
		return -4;
	int loads = 0, sig_ok = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff + i * sizeof(Elf64_Phdr));
		if (ph->p_type == PT_LOAD)
			loads++;
		if (ph->p_type == PT_NOTE && ph->p_offset + 32 < (size_t)n) {
			Elf64_Nhdr *nh = (Elf64_Nhdr *)(buf + ph->p_offset);
			int signo = *(int *)(buf + ph->p_offset + sizeof *nh + 8);
			sig_ok = nh->n_type == NT_PRSTATUS && signo == sig;
		}
	}
	if (loads < 3 || !sig_ok)
		return -5;
	return st.st_size;
}

static void core_main(void)
{
	char path[128];
	mkdir(core_dir, 0755);
	snprintf(path, sizeof path, "%s/kern-smoke.core", core_dir);
	unlink(path);

	int st = in_child(die_abort);
	check(WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT && WCOREDUMP(st), "abort() dumps core (WCOREDUMP)");
	check(check_core(path, SIGABRT) > 0, "an ELF core with the signal, 0600, %N.core in the cwd");
	unlink(path);

	st = in_child(die_segv);
	check(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV && WCOREDUMP(st), "a SIGSEGV dumps core");
	check(check_core(path, SIGSEGV) > 0, "with SIGSEGV in it");
	unlink(path);

	st = in_child(die_abort_no_limit);
	check(WIFSIGNALED(st) && !WCOREDUMP(st) && check_core(path, SIGABRT) == -1, "RLIMIT_CORE 0: no core");
	st = in_child(die_after_setuid);
	check(WIFSIGNALED(st) && !WCOREDUMP(st), "changed credentials: no core");

	pid_t p = fork();
	if (p == 0) {
		chdir(core_dir);
		pause();
		_exit(0);
	}
	kill(p, SIGKILL);
	waitpid(p, &st, 0);
	check(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL && !WCOREDUMP(st), "SIGKILL leaves no core");

	check(system("/sbin/sysctl -q kern.coredump=0 >/dev/null") == 0, "kern.coredump=0");
	st = in_child(die_abort);
	check(!WCOREDUMP(st) && check_core(path, SIGABRT) == -1, "turns cores off");
	system("/sbin/sysctl -q kern.coredump=1 >/dev/null");

	check(system("/sbin/sysctl -q kern.corefile=/tmp/kern-smoke-core/%N.%P.core >/dev/null") == 0, "kern.corefile");
	pid_t q = fork();
	if (q == 0)
		_exit(die_abort());
	waitpid(q, &st, 0);
	snprintf(path, sizeof path, "%s/kern-smoke.%d.core", core_dir, (int)q);
	check(WCOREDUMP(st) && check_core(path, SIGABRT) > 0, "names the core %N.%P.core");
	unlink(path);
	system("/sbin/sysctl -q kern.corefile=%N.core >/dev/null");
}
