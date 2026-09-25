/* Real, unmodified-musl-API coverage of the *at() family on OxideBSD (seeded at /at-smoke.elf,
 * run by regress/at-syscall-smoke via tests/at_syscall_smoke.rs). Every call goes through musl's
 * own public wrapper -- the same code any ported program links -- except execveat, which musl
 * doesn't export, so it's issued through syscall() with the same struct the wrappers build.
 *
 * Also covers the 2026-09 cleanup batch (OxideBSD-doc CLEANUP.md): mkdir modes, umask and owners,
 * permission checks on mkdir/rmdir/rename, POSIX rename of directories, musl's ENOTEMPTY,
 * root-only reboot(2), kill(-1, sig) and a per-exec AT_RANDOM.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

/* musl exports no execveat(), so child_execveat_relative() issues the raw syscall and has to
 * build OxideBSD's wire format itself: struct __oxidebsd_at (musl's src/internal/oxidebsd_at.h)
 * and execve()'s length-prefixed argv/envp arrays (src/process/execve.c). */
struct at_path {
	long dirfd;
	const char *path;
	unsigned long len;
};
struct raw_arg {
	unsigned long ptr;
	unsigned long len;
};

static int run_child(void (*body)(void))
{
	pid_t pid = fork();
	if (pid == 0) {
		body();
		_exit(99);
	}
	int status = -1;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int exec_fd;
static void child_fexecve(void)
{
	char *argv[] = { "true", 0 }, *envp[] = { 0 };
	fexecve(exec_fd, argv, envp);
	_exit(errno == ENOENT ? 42 : 1);
}

static void child_execveat_relative(void)
{
	struct raw_arg argv[] = { { (unsigned long)"true", 4 }, { 0, 0 } }, envp[] = { { 0, 0 } };
	int bin = open("/bin", O_RDONLY | O_DIRECTORY);
	struct at_path at = { bin, "true", 4 };
	syscall(SYS_execveat, &at, argv, envp, 0);
	_exit(1);
}

/* Runs as uid 1000 in a forked child; its exit status is its own failure count. */
static void child_unprivileged(void)
{
	struct stat st;
	failures = 0;
	CHECK(setgid(1000) == 0 && setuid(1000) == 0, "drop to uid 1000");
	CHECK(mkdir("/tmp/cleanup-user-dir", 0777) == 0 && stat("/tmp/cleanup-user-dir", &st) == 0
	      && st.st_uid == 1000 && st.st_gid == 1000, "mkdir records the creator as owner");
	rmdir("/tmp/cleanup-user-dir");
	CHECK_ERR(mkdir("/cleanup-denied", 0777), EACCES, "mkdir needs write permission on the parent");
	CHECK_ERR(rmdir("/at-test/cleanup/perm"), EACCES, "rmdir needs write permission on the parent");
	CHECK_ERR(rename("/at-test/cleanup/perm", "/tmp/stolen"), EACCES,
	          "rename needs write permission on the old parent");
	CHECK_ERR(reboot(RB_AUTOBOOT), EPERM, "reboot(2) is root-only");

	/* kill(-1): reaches every process we may signal except ourselves */
	pid_t victim = fork();
	if (victim == 0) {
		for (;;)
			pause();
	}
	usleep(50 * 1000);
	CHECK(kill(-1, SIGTERM) == 0, "kill(-1, SIGTERM) succeeds");
	int status = 0;
	CHECK(waitpid(victim, &status, 0) == victim && WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM,
	      "kill(-1) reached a same-uid process");
	CHECK_ERR(kill(-1, 0), EPERM, "kill(-1) with only other users' processes left is EPERM");
	fflush(stdout);
	_exit(failures);
}

int main(void)
{
	struct stat st;
	char buf[64];

	mkdir("/at-test", 0755);
	int dfd = open("/at-test", O_RDONLY | O_DIRECTORY);
	CHECK(dfd >= 0, "open(O_DIRECTORY) on a directory");
	CHECK_ERR(open("/hello.c", O_RDONLY | O_DIRECTORY), ENOTDIR, "open(O_DIRECTORY) on a file");

	/* mkdirat / openat / fstatat */
	CHECK(mkdirat(dfd, "sub", 0755) == 0, "mkdirat");
	CHECK(fstatat(dfd, "sub", &st, 0) == 0 && S_ISDIR(st.st_mode), "fstatat on a subdir");
	int fd = openat(dfd, "sub/f", O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0 && write(fd, "hello", 5) == 5, "openat(O_CREAT) + write");
	close(fd);
	CHECK(fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_size == 5, "fstatat size");
	CHECK_ERR(openat(dfd, "sub/f", O_RDONLY | O_DIRECTORY), ENOTDIR, "openat(O_DIRECTORY) on a file");
	CHECK_ERR(fstatat(dfd, "missing", &st, 0), ENOENT, "fstatat on a missing name");
	CHECK_ERR(fstatat(dfd, "", &st, 0), ENOENT, "fstatat empty path without AT_EMPTY_PATH");
	CHECK(fstatat(dfd, "", &st, AT_EMPTY_PATH) == 0 && S_ISDIR(st.st_mode), "fstatat AT_EMPTY_PATH");

	/* dirfd validation; an absolute path ignores dirfd entirely */
	CHECK_ERR(fstatat(-5, "x", &st, 0), EBADF, "fstatat with a bad dirfd");
	int ffd = openat(dfd, "sub/f", O_RDONLY);
	CHECK_ERR(fstatat(ffd, "x", &st, 0), ENOTDIR, "fstatat with a file as dirfd");
	CHECK(fstatat(-5, "/at-test", &st, 0) == 0, "absolute path ignores a bad dirfd");
	CHECK(fstatat(AT_FDCWD, "/at-test/sub", &st, 0) == 0, "AT_FDCWD + absolute path");

	/* symlinkat / readlinkat / O_NOFOLLOW / AT_SYMLINK_NOFOLLOW */
	CHECK(symlinkat("sub/f", dfd, "lnk") == 0, "symlinkat");
	ssize_t n = readlinkat(dfd, "lnk", buf, sizeof buf);
	CHECK(n == 5 && memcmp(buf, "sub/f", 5) == 0, "readlinkat");
	CHECK(fstatat(dfd, "lnk", &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode), "fstatat AT_SYMLINK_NOFOLLOW");
	CHECK(fstatat(dfd, "lnk", &st, 0) == 0 && S_ISREG(st.st_mode) && st.st_size == 5, "fstatat follows a symlink");
	CHECK_ERR(openat(dfd, "lnk", O_RDONLY | O_NOFOLLOW), ELOOP, "openat(O_NOFOLLOW) on a symlink");

	/* linkat / renameat / renameat2 */
	CHECK(linkat(dfd, "sub/f", dfd, "hard", 0) == 0, "linkat");
	CHECK(fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_nlink == 2, "linkat bumps st_nlink");
	CHECK(linkat(dfd, "lnk", dfd, "lnk2", 0) == 0 && fstatat(dfd, "lnk2", &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode),
	      "linkat without AT_SYMLINK_FOLLOW links the symlink itself");
	CHECK(renameat(dfd, "hard", dfd, "hard2") == 0 && fstatat(dfd, "hard2", &st, 0) == 0, "renameat");
	CHECK(renameat(dfd, "hard2", dfd, "hard2") == 0 && fstatat(dfd, "hard2", &st, 0) == 0, "renameat onto itself is a no-op");
	CHECK_ERR(renameat2(dfd, "hard2", dfd, "sub/f", RENAME_NOREPLACE), EEXIST, "renameat2(RENAME_NOREPLACE)");
	CHECK_ERR(renameat2(dfd, "hard2", dfd, "sub/f", RENAME_EXCHANGE), EINVAL, "renameat2(RENAME_EXCHANGE) unsupported");

	/* fchmodat / faccessat */
	CHECK(fchmodat(dfd, "sub/f", 0600, 0) == 0 && fstatat(dfd, "sub/f", &st, 0) == 0 && (st.st_mode & 0777) == 0600, "fchmodat");
	CHECK_ERR(fchmodat(dfd, "lnk", 0600, AT_SYMLINK_NOFOLLOW), EOPNOTSUPP, "fchmodat AT_SYMLINK_NOFOLLOW on a symlink");
	CHECK(faccessat(dfd, "sub/f", R_OK | W_OK, 0) == 0, "faccessat");
	CHECK(faccessat(dfd, "sub/f", R_OK, AT_EACCESS) == 0, "faccessat AT_EACCESS");
	CHECK_ERR(faccessat(dfd, "nope", F_OK, 0), ENOENT, "faccessat on a missing name");

	/* fchownat / lchown / fchown */
	CHECK(fchownat(dfd, "sub/f", 1000, 1000, 0) == 0 && fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_uid == 1000, "fchownat");
	CHECK(lchown("/at-test/lnk", 2000, -1) == 0, "lchown");
	CHECK(fstatat(dfd, "lnk", &st, AT_SYMLINK_NOFOLLOW) == 0 && st.st_uid == 2000, "lchown changed the link");
	CHECK(fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_uid == 1000, "lchown left the target alone");
	CHECK(fchown(ffd, 7, 7) == 0 && fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_uid == 7 && st.st_gid == 7, "fchown");

	/* utimensat / futimens */
	struct timespec t1[2] = { { 1000, 0 }, { 2000, 0 } }, t2[2] = { { 3000, 0 }, { 4000, 0 } };
	CHECK(utimensat(dfd, "sub/f", t1, 0) == 0 && fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_mtime == 2000, "utimensat relative to a dirfd");
	CHECK(futimens(ffd, t2) == 0 && fstatat(dfd, "sub/f", &st, 0) == 0 && st.st_mtime == 4000, "futimens");

	/* mknodat / unlinkat / remove */
	CHECK(mknodat(dfd, "node", S_IFREG | 0644, 0) == 0 && fstatat(dfd, "node", &st, 0) == 0 && S_ISREG(st.st_mode), "mknodat");
	CHECK(unlinkat(dfd, "node", 0) == 0, "unlinkat");
	CHECK_ERR(fstatat(dfd, "node", &st, 0), ENOENT, "unlinkat removed it");
	CHECK(unlinkat(dfd, "sub", AT_REMOVEDIR) == -1, "unlinkat(AT_REMOVEDIR) refuses a non-empty dir");
	CHECK_ERR(unlinkat(dfd, "sub", 0), EISDIR, "unlinkat without AT_REMOVEDIR on a dir");
	CHECK(mkdirat(dfd, "empty", 0755) == 0 && unlinkat(dfd, "empty", AT_REMOVEDIR) == 0, "unlinkat(AT_REMOVEDIR)");
	CHECK(remove("/at-test/hard2") == 0, "remove() a file");
	CHECK(mkdir("/at-test/rmdir-me", 0755) == 0 && remove("/at-test/rmdir-me") == 0, "remove() a directory");

	/* fdopendir over an openat()'d dirfd */
	int sfd = openat(dfd, "sub", O_RDONLY | O_DIRECTORY);
	DIR *d = fdopendir(sfd);
	int entries = 0;
	struct dirent *e;
	while (d && (e = readdir(d)))
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			entries++;
	CHECK(d && entries == 1, "fdopendir + readdir");
	if (d) closedir(d);

	/* a /proc directory fd works as a base */
	int pfd = open("/proc", O_RDONLY | O_DIRECTORY);
	CHECK(pfd >= 0 && fstatat(pfd, "1", &st, 0) == 0 && S_ISDIR(st.st_mode), "/proc dirfd as a base");

	/* stdio's temp-file helpers ride the same calls */
	FILE *tf = tmpfile();
	CHECK(tf && fputs("x", tf) >= 0, "tmpfile");
	if (tf) fclose(tf);
	CHECK(tmpnam(NULL) != NULL, "tmpnam");

	/* execveat: fexecve (AT_EMPTY_PATH), a dirfd-relative path, and a script via fd */
	exec_fd = open("/bin/true", O_RDONLY);
	CHECK(run_child(child_fexecve) == 0, "fexecve");
	CHECK(run_child(child_execveat_relative) == 0, "execveat relative to a dirfd");
	close(exec_fd);
	int sf = openat(dfd, "script", O_CREAT | O_WRONLY, 0755);
	write(sf, "#!/bin/sh\nexit 3\n", 17);
	close(sf);
	exec_fd = openat(dfd, "script", O_RDONLY);
	CHECK(run_child(child_fexecve) == 42, "fexecve of a #! script is ENOENT (no /dev/fd)");

	/* --- cleanup batch --- */
	mkdir("/at-test/cleanup", 0755);
	umask(022);
	CHECK(mkdir("/at-test/cleanup/m755", 0777) == 0 && stat("/at-test/cleanup/m755", &st) == 0
	      && (st.st_mode & 07777) == 0755, "mkdir applies mode and umask 022");
	umask(077);
	CHECK(mkdir("/at-test/cleanup/m700", 0777) == 0 && stat("/at-test/cleanup/m700", &st) == 0
	      && (st.st_mode & 07777) == 0700, "mkdir applies umask 077");
	CHECK(mknod("/at-test/cleanup/node", S_IFREG | 0666, 0) == 0
	      && stat("/at-test/cleanup/node", &st) == 0 && (st.st_mode & 07777) == 0600,
	      "mknod applies the umask");
	umask(022);

	mkdir("/at-test/cleanup/a", 0755);
	mkdir("/at-test/cleanup/b", 0755);
	mkdir("/at-test/cleanup/a/sub", 0755);
	struct stat b_st, dotdot;
	CHECK(rename("/at-test/cleanup/a/sub", "/at-test/cleanup/b/sub") == 0
	      && stat("/at-test/cleanup/b", &b_st) == 0 && stat("/at-test/cleanup/b/sub/..", &dotdot) == 0
	      && dotdot.st_ino == b_st.st_ino, "a directory moved to a new parent gets a new ..");
	CHECK_ERR(rename("/at-test/cleanup/b", "/at-test/cleanup/b/sub/inside"), EINVAL,
	          "a directory can't move into its own subtree");
	mkdir("/at-test/cleanup/empty", 0755);
	CHECK(rename("/at-test/cleanup/a", "/at-test/cleanup/empty") == 0
	      && stat("/at-test/cleanup/a", &st) == -1, "a directory replaces an empty directory");
	CHECK_ERR(rename("/at-test/cleanup/empty", "/at-test/cleanup/b"), ENOTEMPTY,
	          "a directory can't replace a non-empty one (musl's ENOTEMPTY)");
	CHECK_ERR(rmdir("/at-test/cleanup/b"), ENOTEMPTY, "rmdir of a non-empty directory is ENOTEMPTY");

	mkdir("/at-test/cleanup/perm", 0755);
	fflush(stdout); /* or the child re-prints our buffered output */
	CHECK(run_child(child_unprivileged) == 0, "unprivileged checks (see above)");

	const unsigned char *rnd = (const unsigned char *)getauxval(AT_RANDOM);
	CHECK(rnd && memcmp(rnd, "OxideBSDNotRealX", 16) != 0, "AT_RANDOM is real random bytes");

	printf("%s: %d failure(s)\n", failures ? "at-smoke FAILED" : "at-smoke passed", failures);
	return failures;
}
