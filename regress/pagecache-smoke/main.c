/* The read-only page cache (OxideBSD-doc PAGECACHE.md §5.1), seeded at /pagecache-smoke.elf and
 * run by regress/pagecache-syscall-smoke via tests/pagecache_syscall_smoke.rs:
 *
 * - a second exec of a program maps its pages from the cache (hits rise, misses don't);
 * - a program changed in place runs its new code at its next exec, even at the same size;
 * - a cached private mapping made writable with mprotect is the process's own copy;
 * - fork shares cached pages, and a child exiting doesn't take them from the parent.
 *
 * Run as "pagecache-smoke.elf mark" it exits with the digit after MARK's '=': the code the test
 * changes in place. Each CHECK prints PASS/FAIL; the exit status is the failure count. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

/* A page of read-only data of its own: mapped from the cache, never shared with a writable
 * segment. */
__attribute__((aligned(4096))) static const char MARK[4096] = "PAGECACHE-MARK=0";

#define PROG "/tmp/pagecache-prog"

static int failures;

#define CHECK(cond, what)                                                        \
	do {                                                                         \
		if (cond) {                                                              \
			printf("PASS %s\n", what);                                           \
		} else {                                                                 \
			printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));     \
			failures++;                                                          \
		}                                                                        \
	} while (0)

static unsigned long counter(const char *name)
{
	unsigned long v = 0;
	size_t len = sizeof v;
	if (sysctlbyname(name, &v, &len, 0, 0) < 0 || len != sizeof v) {
		printf("FAIL sysctlbyname %s (errno=%d)\n", name, errno);
		failures++;
		return 0;
	}
	return v;
}

/* Runs PROG "mark" and returns its exit status, or -1. */
static int run_prog(void)
{
	pid_t pid = fork();
	if (pid == 0) {
		execl(PROG, PROG, "mark", (char *)0);
		_exit(127);
	}
	int status;
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
	return WEXITSTATUS(status);
}

/* The whole of `path`, malloc'd; its size in *size. */
static char *slurp(const char *path, size_t *size)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) < 0) return 0;
	char *buf = malloc(st.st_size);
	size_t got = 0;
	while (buf && got < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + got, st.st_size - got);
		if (n <= 0) break;
		got += n;
	}
	close(fd);
	*size = got;
	return got == (size_t)st.st_size ? buf : 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "mark") == 0) {
		volatile const char *m = MARK;
		return m[15] - '0';
	}

	/* A copy of this program, which the test then changes. */
	size_t size;
	char *image = slurp("/pagecache-smoke.elf", &size);
	CHECK(image != 0, "read /pagecache-smoke.elf");
	if (!image) return 1;
	int fd = open(PROG, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	CHECK(fd >= 0 && write(fd, image, size) == (ssize_t)size, "write " PROG);
	close(fd);

	/* Where MARK's digit is in the file. The key is built at run time, so the only copy of it in
	 * the file is MARK itself. */
	char key[] = "QAGECACHE-MARK=";
	key[0] = 'P';
	char *at = memmem(image, size, key, strlen(key));
	CHECK(at != 0, "find MARK in the file");
	if (!at) return 1;
	off_t digit = at - image + strlen(key);

	/* First exec fills the cache, the second maps from it. */
	unsigned long misses0 = counter("vm.pagecache.misses");
	CHECK(run_prog() == 0, "first exec runs (exit 0)");
	unsigned long hits1 = counter("vm.pagecache.hits"), misses1 = counter("vm.pagecache.misses");
	CHECK(misses1 > misses0, "first exec reads pages into the cache");
	CHECK(run_prog() == 0, "second exec runs (exit 0)");
	unsigned long hits2 = counter("vm.pagecache.hits"), misses2 = counter("vm.pagecache.misses");
	CHECK(misses2 == misses1, "second exec reads nothing new");
	CHECK(hits2 > hits1, "second exec maps cached pages");

	/* Changed in place, same size: the next exec runs the new code. */
	fd = open(PROG, O_WRONLY);
	CHECK(fd >= 0 && pwrite(fd, "7", 1, digit) == 1, "change MARK in place");
	close(fd);
	{
		size_t after_size;
		char *after = slurp(PROG, &after_size);
		CHECK(after && after_size == size, "the change keeps the file's size");
		CHECK(after && after[0] == 0x7f && after[digit] == '7', "the change is in the file, the rest kept");
		if (after) printf("  size %zu (was %zu), byte 0 %#x, digit %c\n", after_size, size,
		                  (unsigned char)after[0], after[digit]);
		free(after);
	}
	int code = run_prog();
	printf("  exec after the change exited %d\n", code);
	CHECK(code == 7, "exec after the change runs the new code (exit 7)");
	CHECK(run_prog() == 7, "and so does the next one");

	/* Two private read-only mappings of the same page share the cache's frame; making one
	 * writable gives this process its own copy, and the other and the file keep the original. */
	fd = open(PROG, O_RDONLY);
	CHECK(fd >= 0, "open " PROG " for mmap");
	unsigned long hits3 = counter("vm.pagecache.hits");
	char *a = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	char *b = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	CHECK(a != MAP_FAILED && b != MAP_FAILED, "two private read-only mappings");
	if (a == MAP_FAILED || b == MAP_FAILED) return failures;
	CHECK(counter("vm.pagecache.hits") >= hits3 + 2, "both map the cached page");
	CHECK(a[0] == 0x7f && b[0] == 0x7f, "both show the file");
	CHECK(mprotect(a, 4096, PROT_READ | PROT_WRITE) == 0, "mprotect one writable");
	a[0] = 'X';
	CHECK(a[0] == 'X', "the write shows in that mapping");
	CHECK(b[0] == 0x7f, "the other mapping keeps the file's byte");
	char byte = 0;
	CHECK(pread(fd, &byte, 1, 0) == 1 && byte == 0x7f, "the file keeps its byte");

	/* fork aliases cached pages; the child exiting leaves them to the parent. */
	pid_t pid = fork();
	if (pid == 0) _exit(b[0] == 0x7f && a[0] == 'X' ? 0 : 1);
	int status;
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "a forked child sees the same pages");
	CHECK(b[0] == 0x7f && a[0] == 'X', "the parent's pages survive the child's exit");
	CHECK(run_prog() == 7, "and the cache still runs the program");

	munmap(a, 4096);
	munmap(b, 4096);
	close(fd);
	unlink(PROG);
	printf("pagecache-smoke: %d failure(s)\n", failures);
	return failures;
}
