/*
 * kern-smoke vm: the per-process address-space map (OxideBSD-doc VMMAP.md, CLEANUP.md §3 and
 * §7): addresses are the process's own and reused, munmap and mprotect work on part of a
 * mapping, MAP_FIXED over part of a file mapping leaves the rest answering for itself,
 * RLIMIT_AS holds, shmat takes an address, /proc/<pid>/map(s) list the mappings, and anonymous
 * memory and the heap are made at their first touch.
 */
#include <setjmp.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

static sigjmp_buf vm_jump;
static volatile int vm_signal;

static void vm_catch(int sig)
{
	vm_signal = sig;
	siglongjmp(vm_jump, 1);
}

/* The signal a read of `p` raises, or 0. */
static int touch_signal(volatile char *p)
{
	struct sigaction sa, old_segv, old_bus;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = vm_catch;
	sigaction(SIGSEGV, &sa, &old_segv);
	sigaction(SIGBUS, &sa, &old_bus);
	vm_signal = 0;
	if (sigsetjmp(vm_jump, 1) == 0)
		(void)*p;
	sigaction(SIGSEGV, &old_segv, NULL);
	sigaction(SIGBUS, &old_bus, NULL);
	return vm_signal;
}

/* The signal a write to `p` raises, or 0. */
static int write_signal(volatile char *p)
{
	struct sigaction sa, old_segv;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = vm_catch;
	sigaction(SIGSEGV, &sa, &old_segv);
	vm_signal = 0;
	if (sigsetjmp(vm_jump, 1) == 0)
		*p = 1;
	sigaction(SIGSEGV, &old_segv, NULL);
	return vm_signal;
}

/* /proc/self/stat's vsize (field 23). */
static unsigned long vsize(void)
{
	char buf[1024];
	int fd = open("/proc/self/stat", O_RDONLY);
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	char *p = strrchr(buf, ')');
	int field = 2;
	while (p && *p && field < 23) {
		if (*p == ' ')
			field++;
		p++;
	}
	return p ? strtoul(p, NULL, 10) : 0;
}

static int rlimit_as(void)
{
	unsigned long now = vsize();
	if (now == 0)
		return 10;
	struct rlimit rl = { now + (1 << 20), RLIM_INFINITY };
	if (setrlimit(RLIMIT_AS, &rl) != 0)
		return 11;
	if (mmap(NULL, 4 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) != MAP_FAILED || errno != ENOMEM)
		return 12;
	if (mmap(NULL, 256 << 10, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) == MAP_FAILED)
		return 13;
	long base = syscall(SYS_brk, 0);
	if (syscall(SYS_brk, base + (8 << 20)) != -1 || errno != ENOMEM)
		return 14;
	return 0;
}

static int has_line(const char *path, const char *needle)
{
	static char buf[65536];
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	ssize_t n, total = 0;
	while ((n = read(fd, buf + total, sizeof buf - 1 - total)) > 0)
		total += n;
	close(fd);
	buf[total] = 0;
	return strstr(buf, needle) != NULL;
}

/* The resident pages /proc/self/map reports for the mapping at m (-1 if it lists none). */
static long resident(void *m, size_t len)
{
	static char buf[65536];
	char needle[64];
	int fd = open("/proc/self/map", O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n, total = 0;
	while ((n = read(fd, buf + total, sizeof buf - 1 - total)) > 0)
		total += n;
	close(fd);
	buf[total] = 0;
	snprintf(needle, sizeof needle, "0x%lx 0x%lx ", (unsigned long)m, (unsigned long)m + len);
	char *line = strstr(buf, needle);
	long pages;
	if (line == NULL || sscanf(line + strlen(needle), "%ld", &pages) != 1)
		return -1;
	return pages;
}

static void vm_main(void)
{
	const long pg = 4096;
	char *a = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	munmap(a, 1 << 20);
	char *b = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	check(a != MAP_FAILED && a == b, "an address freed by munmap is used again");
	munmap(b, 1 << 20);

	char *c = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	c[0] = c[2 * pg] = 1;
	check(munmap(c + pg, pg) == 0, "munmap of a mapping's middle page");
	check(touch_signal(c) == 0 && touch_signal(c + 2 * pg) == 0, "leaves the pages around it");
	check(touch_signal(c + pg) == SIGSEGV, "and the middle one gone");
	check(mprotect(c, 3 * pg, PROT_READ) == -1 && errno == ENOMEM, "mprotect over the hole is ENOMEM");
	check(mprotect(c + 2 * pg, pg, PROT_READ) == 0, "mprotect of one page of a mapping");
	check(mprotect(c, pg, PROT_NONE) == 0 && touch_signal(c) == SIGSEGV, "PROT_NONE takes access away");
	check(mprotect(c, pg, PROT_READ | PROT_WRITE) == 0 && touch_signal(c) == 0, "and mprotect gives it back");

	/* A file one page long mapped over four: past its end is SIGBUS (POSIX). */
	const char *path = "/tmp/kern-smoke.vm";
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	char page[4096];
	memset(page, 'x', sizeof page);
	write(fd, page, sizeof page);
	char *f = mmap(NULL, 4 * pg, PROT_READ, MAP_SHARED, fd, 0);
	check(f != MAP_FAILED && f[0] == 'x', "a file mapping");
	check(touch_signal(f + pg) == SIGBUS, "past the file's end is SIGBUS");
	char *g = mmap(f + 2 * pg, 2 * pg, PROT_READ, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
	check(g == f + 2 * pg && touch_signal(g) == 0, "MAP_FIXED over part of it");
	munmap(g, 2 * pg);
	check(touch_signal(f + 2 * pg) == SIGSEGV, "then unmapped: SIGSEGV, not the old SIGBUS");
	check(touch_signal(f + pg) == SIGBUS, "the file's own tail still SIGBUS");
	munmap(f, 2 * pg);
	close(fd);
	int ro = open(path, O_RDONLY);
	char *r = mmap(NULL, pg, PROT_READ, MAP_SHARED, ro, 0);
	errno = 0;
	check(mprotect(r, pg, PROT_READ | PROT_WRITE) == -1 && errno == EACCES,
	      "a shared mapping of a read-only file can't become writable");
	munmap(r, pg);
	close(ro);
	unlink(path);

	unsigned long before = vsize();
	char *big = mmap(NULL, 64 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	check(big != MAP_FAILED && vsize() >= before + (64 << 20), "vsize counts mappings");
	munmap(big, 64 << 20);
	check(vsize() == before, "and stops counting them");
	check(child_exit_ok(rlimit_as), "RLIMIT_AS bounds mmap and brk");

	/* shmat at an address the caller picks. */
	int id = shmget(IPC_PRIVATE, 2 * pg, IPC_CREAT | 0600);
	char *slot = mmap(NULL, 2 * pg, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
	munmap(slot, 2 * pg);
	char *s = shmat(id, slot, 0);
	check(s == slot, "shmat at the address asked for");
	errno = 0;
	check(shmat(id, slot, 0) == (void *)-1 && errno == EINVAL, "not over a mapping");
	check(shmat(id, slot + 1, SHM_RND) == (void *)-1 && errno == EINVAL, "SHM_RND rounds down (still in use)");
	shmdt(s);
	check(shmat(id, slot + 1, SHM_RND) == slot, "SHM_RND rounds down");
	shmdt(slot);
	shmctl(id, IPC_RMID, NULL);

	char needle[64];
	char *m = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	snprintf(needle, sizeof needle, "%lx-%lx rw-p", (unsigned long)m, (unsigned long)m + pg);
	check(has_line("/proc/self/maps", needle), "/proc/self/maps lists a mapping");
	snprintf(needle, sizeof needle, "0x%lx 0x%lx ", (unsigned long)m, (unsigned long)m + pg);
	check(has_line("/proc/self/map", needle), "/proc/self/map, FreeBSD's format");
	check(has_line("/proc/self/maps", "[stack]"), "with the stack");
	munmap(m, pg);

	/* MAP_FIXED_NOREPLACE fails over a mapping instead of replacing it (VMMAP.md §4.3). */
	char *nr = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	nr[pg] = 7;
	check(mmap(nr + pg, pg, PROT_READ, MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED &&
	          errno == EEXIST && nr[pg] == 7,
	      "MAP_FIXED_NOREPLACE over a mapping is EEXIST, the mapping kept");
	munmap(nr + pg, pg);
	check(mmap(nr + pg, pg, PROT_READ, MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0) == nr + pg,
	      "and maps where nothing is");
	munmap(nr, 2 * pg);

	/* Anonymous memory is made at its first touch (VMMAP.md §5). */
	size_t gib = (size_t)1 << 30;
	volatile char *lazy = mmap(NULL, gib, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	check(lazy != MAP_FAILED && resident((void *)lazy, gib) == 0, "a 1 GiB anonymous mapping costs nothing");
	check(lazy[3 * pg] == 0, "an untouched page reads as zero");
	lazy[0] = 1;
	lazy[gib / 2] = 2;
	check(resident((void *)lazy, gib) == 3, "each page touched costs one");
	check(lazy[0] == 1 && lazy[gib / 2] == 2, "and keeps what was written");
	check(mlock((void *)(lazy + 16 * pg), 4 * pg) == 0 && resident((void *)lazy, gib) == 7, "mlock makes its range resident");
	check(mprotect((void *)(lazy + 32 * pg), pg, PROT_READ) == 0 && write_signal(lazy + 32 * pg) == SIGSEGV,
	      "an untouched page made read-only refuses a write");
	check(lazy[32 * pg] == 0, "but reads as zero");
	munmap((void *)lazy, gib);
	/* musl's sbrk() refuses to grow the heap (as its brk() does): the system call itself. */
	char *heap = (char *)syscall(SYS_brk, 0);
	check((char *)syscall(SYS_brk, heap + 64 * pg) == heap + 64 * pg && heap[10 * pg] == 0,
	      "the heap grows on demand");
	heap[63 * pg] = 9;
	check(heap[63 * pg] == 9, "and keeps what was written");
}
