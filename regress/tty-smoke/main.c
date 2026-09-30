/* Terminal device nodes and descriptors (TTY.md §6 in OxideBSD-doc) on OxideBSD (seeded at
 * /tty-smoke.elf, run by regress/tty-syscall-smoke via tests/tty_syscall_smoke.rs).
 *
 * Runs in pid 1's session, whose controlling terminal is ttyv0, with fds 0-2 on it. Checks:
 * /dev/ttyv0, /dev/tty and /dev/console open the kernel's terminal; fstat on a terminal descriptor
 * matches stat on its node, so musl's ttyname(3) works through /proc/self/fd; /proc/self and the
 * /proc/<pid>/fd links; /proc/<pid>/stat's session, tty_nr and tpgid; and /dev/tty without a
 * controlling terminal.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

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

/* Expect a -1 return with a specific errno. */
#define CHECK_ERR(expr, want, what)                                              \
	do {                                                                         \
		errno = 0;                                                               \
		long r_ = (long)(expr);                                                  \
		if (r_ == -1 && errno == (want)) {                                       \
			printf("PASS %s\n", what);                                           \
		} else {                                                                 \
			printf("FAIL %s (ret=%ld errno=%d, want %d)\n", what, r_, errno, (want)); \
			failures++;                                                          \
		}                                                                        \
	} while (0)

static int run_child(void (*body)(void))
{
	fflush(stdout); /* or the child re-prints our buffered output */
	pid_t pid = fork();
	if (pid == 0) {
		failures = 0;
		body();
		_exit(failures);
	}
	int status = -1;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* The link /proc/self/fd/<fd> into buf; "" on failure. */
static const char *fd_link(int fd, char *buf, size_t size)
{
	char path[64];
	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	ssize_t n = readlink(path, buf, size - 1);
	buf[n < 0 ? 0 : n] = 0;
	return buf;
}

/* Fields 6-8 of /proc/self/stat (session, tty_nr, tpgid). */
static int proc_stat_tty(long *session, long *tty_nr, long *tpgid)
{
	char buf[512];
	int fd = open("/proc/self/stat", O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	/* After "pid (comm) state": ppid pgrp session tty_nr tpgid. */
	char *p = strrchr(buf, ')');
	long ppid, pgrp;
	char state;
	if (!p || sscanf(p + 1, " %c %ld %ld %ld %ld %ld", &state, &ppid, &pgrp, session, tty_nr, tpgid) != 6)
		return -1;
	return 0;
}

static int same_file(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_rdev == b->st_rdev;
}

/* A new session: no controlling terminal. */
static void child_no_ctty(void)
{
	if (setsid() < 0) {
		printf("FAIL setsid (errno=%d)\n", errno);
		_exit(1);
	}
	CHECK_ERR(open("/dev/tty", O_RDWR), ENXIO, "/dev/tty without a controlling terminal is ENXIO");
	char name[64] = "";
	CHECK(ttyname_r(0, name, sizeof name) == 0 && strcmp(name, "/dev/ttyv0") == 0,
	      "ttyname still names an inherited terminal descriptor");
	long session, tty_nr, tpgid;
	CHECK(proc_stat_tty(&session, &tty_nr, &tpgid) == 0 && session == getpid() && tty_nr == 0
	          && tpgid == -1,
	      "/proc/self/stat: own session, no tty_nr, tpgid -1");
	/* Opening a terminal doesn't make it controlling (TTY.md §5.1). */
	int fd = open("/dev/ttyv0", O_RDWR);
	CHECK(fd >= 0 && open("/dev/tty", O_RDWR) == -1 && errno == ENXIO,
	      "opening /dev/ttyv0 doesn't acquire it");
	close(fd);
}

int main(void)
{
	struct stat st, node, tty_node, console_node;
	char buf[256], name[64];

	/* --- the nodes ---------------------------------------------------------------------- */
	CHECK(stat("/dev/ttyv0", &node) == 0 && S_ISCHR(node.st_mode) && major(node.st_rdev) == 4
	          && minor(node.st_rdev) == 0 && (node.st_mode & 07777) == 0600 && node.st_gid == 4,
	      "/dev/ttyv0 is character device 4,0, root:tty 0600");
	CHECK(stat("/dev/tty", &tty_node) == 0 && S_ISCHR(tty_node.st_mode) && major(tty_node.st_rdev) == 5
	          && minor(tty_node.st_rdev) == 0 && (tty_node.st_mode & 07777) == 0666,
	      "/dev/tty is character device 5,0, 0666");
	CHECK(stat("/dev/console", &console_node) == 0 && S_ISCHR(console_node.st_mode)
	          && major(console_node.st_rdev) == 5 && minor(console_node.st_rdev) == 1,
	      "/dev/console is character device 5,1");

	/* --- fds 0-2 are ttyv0 (§6.1, §6.2) ------------------------------------------------ */
	CHECK(isatty(0) && isatty(1) && isatty(2), "fds 0-2 are terminals");
	CHECK(fstat(0, &st) == 0 && same_file(&st, &node), "fstat(0) matches stat(\"/dev/ttyv0\")");
	CHECK(ttyname_r(0, name, sizeof name) == 0 && strcmp(name, "/dev/ttyv0") == 0,
	      "ttyname(0) is /dev/ttyv0");
	CHECK(strcmp(fd_link(1, buf, sizeof buf), "/dev/ttyv0") == 0, "/proc/self/fd/1 -> /dev/ttyv0");

	/* --- opening them ------------------------------------------------------------------ */
	int fd = open("/dev/tty", O_RDWR);
	CHECK(fd >= 0 && isatty(fd), "open(\"/dev/tty\") gives a terminal");
	CHECK(fstat(fd, &st) == 0 && same_file(&st, &node), "/dev/tty opens the controlling terminal, ttyv0");
	CHECK(ttyname_r(fd, name, sizeof name) == 0 && strcmp(name, "/dev/ttyv0") == 0,
	      "ttyname of a /dev/tty descriptor is /dev/ttyv0");
	CHECK(write(fd, "tty-smoke: written through /dev/tty\n", 36) == 36, "write through /dev/tty");
	struct termios t;
	CHECK(tcgetattr(fd, &t) == 0 && (t.c_lflag & ICANON), "tcgetattr through /dev/tty");
	close(fd);

	fd = open("/dev/ttyv0", O_WRONLY);
	CHECK(fd >= 0, "open(\"/dev/ttyv0\", O_WRONLY)");
	CHECK_ERR(read(fd, buf, 1), EBADF, "read on a write-only terminal descriptor is EBADF");
	close(fd);

	fd = open("/dev/tty", O_RDONLY | O_NONBLOCK);
	CHECK_ERR(read(fd, buf, 1), EAGAIN, "a non-blocking read with no input is EAGAIN");
	CHECK_ERR(write(fd, "x", 1), EBADF, "write on a read-only terminal descriptor is EBADF");
	close(fd);

	fd = open("/dev/console", O_WRONLY);
	CHECK(fd >= 0 && isatty(fd), "open(\"/dev/console\") gives a terminal");
	close(fd);

	/* devfs refuses mknod (DEVFS.md §4.4.3); a node made on disk opens through the registry. */
	CHECK_ERR(mknod("/dev/ttyv9", S_IFCHR | 0600, makedev(4, 9)), EPERM, "mknod in /dev is EPERM");
	CHECK(mknod("/tmp/ttyv9", S_IFCHR | 0600, makedev(4, 9)) == 0, "mknod a ttyv9 node on disk");
	CHECK_ERR(open("/tmp/ttyv9", O_RDWR), ENXIO, "a node for a terminal that doesn't exist is ENXIO");
	unlink("/tmp/ttyv9");

	/* --- /proc/self and /proc/<pid>/stat (§6.3, §6.4) ---------------------------------- */
	char pid[16];
	snprintf(pid, sizeof pid, "%d", getpid());
	ssize_t n = readlink("/proc/self", buf, sizeof buf - 1);
	buf[n < 0 ? 0 : n] = 0;
	CHECK(n > 0 && strcmp(buf, pid) == 0, "readlink(\"/proc/self\") is the pid");
	CHECK(lstat("/proc/self", &st) == 0 && S_ISLNK(st.st_mode), "/proc/self is a symlink");
	CHECK(stat("/proc/self", &st) == 0 && S_ISDIR(st.st_mode), "stat follows /proc/self to a directory");
	CHECK(lstat("/proc/self/fd/0", &st) == 0 && S_ISLNK(st.st_mode), "/proc/self/fd/0 is a symlink");
	CHECK(stat("/proc/self/fd/0", &st) == 0 && same_file(&st, &node), "stat follows /proc/self/fd/0");

	long session, tty_nr, tpgid;
	CHECK(proc_stat_tty(&session, &tty_nr, &tpgid) == 0 && session == getsid(0)
	          && tty_nr == (long)makedev(4, 0) && tpgid == tcgetpgrp(0),
	      "/proc/self/stat reports session, tty_nr and tpgid");

	/* --- the other descriptors' links -------------------------------------------------- */
	int p[2];
	char a[64], b[64];
	CHECK(pipe(p) == 0 && strncmp(fd_link(p[0], a, sizeof a), "pipe:[", 6) == 0
	          && strcmp(a, fd_link(p[1], b, sizeof b)) == 0,
	      "both ends of a pipe link to the same pipe:[N]");
	CHECK(fstat(p[0], &st) == 0 && S_ISFIFO(st.st_mode), "fstat on a pipe is S_IFIFO");
	close(p[0]);
	close(p[1]);

	mkdir("/tty-test", 0755);
	fd = open("/tty-test/new", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	CHECK(strcmp(fd_link(fd, buf, sizeof buf), "/tty-test/new") == 0, "a file being created links to its path");
	close(fd);
	fd = open("/tty-test/new", O_RDONLY);
	CHECK(strcmp(fd_link(fd, buf, sizeof buf), "/tty-test/new") == 0, "an open file links to its path");
	rename("/tty-test/new", "/tty-test/renamed");
	CHECK(strcmp(fd_link(fd, buf, sizeof buf), "/tty-test/renamed") == 0, "the link follows a rename");
	unlink("/tty-test/renamed");
	CHECK(strcmp(fd_link(fd, buf, sizeof buf), "/tty-test/renamed (deleted)") == 0,
	      "an unlinked file's link ends in \" (deleted)\"");
	close(fd);
	int dfd = open("/tty-test", O_RDONLY | O_DIRECTORY);
	CHECK(strcmp(fd_link(dfd, buf, sizeof buf), "/tty-test") == 0, "a directory links to its path");
	close(dfd);

	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int links = 0, others = 0;
	while (d && (e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		if (e->d_type == DT_LNK)
			links++;
		else
			others++;
	}
	if (d)
		closedir(d);
	CHECK(links >= 3 && others == 0, "/proc/self/fd lists symlinks");

	/* --- no controlling terminal ------------------------------------------------------- */
	CHECK(run_child(child_no_ctty) == 0, "a new session (see above)");

	printf("%s: %d failure(s)\n", failures ? "tty-smoke FAILED" : "tty-smoke passed", failures);
	return failures;
}
