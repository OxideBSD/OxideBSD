/* File descriptor numbering and named pipes (FIFOs) on OxideBSD (seeded at /fd-smoke.elf, run by
 * regress/fd-syscall-smoke via tests/fd_syscall_smoke.rs).
 *
 * POSIX: open()/pipe()/dup()/socket() return the lowest fd the process doesn't have open, and
 * F_DUPFD the lowest one >= its argument. A FIFO's open() waits for the other side (unless
 * O_NONBLOCK: then a reader opens at once and a lone writer gets ENXIO), readers see EOF once
 * every writer closes, and unread data goes away with the last close. Writing to a pipe with no
 * reader raises SIGPIPE, and fails EPIPE when SIGPIPE is ignored.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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

#define FIFO "/fd-smoke.fifo"

static void on_alarm(int sig)
{
	(void)sig;
}

static void fd_numbering(void)
{
	int a = open("/etc/passwd", O_RDONLY);
	int b = open("/etc/passwd", O_RDONLY);
	CHECK(a >= 3 && b == a + 1, "two opens get consecutive fds");
	close(a);
	int c = open("/etc/passwd", O_RDONLY);
	CHECK(c == a, "open reuses the lowest closed fd");
	close(c);
	CHECK(dup(b) == a, "dup returns the lowest free fd");
	close(a);

	CHECK(fcntl(b, F_DUPFD, 20) == 20, "F_DUPFD honours its minimum");
	CHECK(fcntl(b, F_DUPFD, 20) == 21, "F_DUPFD skips an fd already open");
	close(20);
	close(21);

	int d = dup(b);
	CHECK(fcntl(d, F_SETFD, FD_CLOEXEC) == 0, "set FD_CLOEXEC");
	close(d);
	int e = open("/etc/passwd", O_RDONLY);
	CHECK(e == d && fcntl(e, F_GETFD) == 0, "a reused fd number doesn't inherit FD_CLOEXEC");
	close(e);

	CHECK(dup2(b, b) == b, "dup2(fd, fd) returns fd");
	CHECK(dup2(a, 30) == -1 && errno == EBADF, "dup2 from a closed fd is EBADF");
	close(b);

	pid_t pid = fork();
	if (pid == 0) {
		int p[2];
		close(0);
		_exit(pipe(p) == 0 && p[0] == 0 ? 0 : 1);
	}
	int status;
	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "pipe reuses a closed fd 0");
}

static void fifos(void)
{
	unlink(FIFO);
	CHECK(mkfifo(FIFO, 0644) == 0, "mkfifo");
	struct stat st;
	CHECK(stat(FIFO, &st) == 0 && S_ISFIFO(st.st_mode), "stat reports S_IFIFO");
	CHECK(mkfifo(FIFO, 0644) == -1 && errno == EEXIST, "mkfifo over an existing name is EEXIST");

	int found = 0;
	DIR *dir = opendir("/");
	struct dirent *ent;
	while (dir && (ent = readdir(dir)))
		if (strcmp(ent->d_name, FIFO + 1) == 0)
			found = ent->d_type == DT_FIFO;
	if (dir)
		closedir(dir);
	CHECK(found, "readdir reports DT_FIFO");

	CHECK(open(FIFO, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO,
	      "nonblocking write-only open with no reader is ENXIO");
	int r = open(FIFO, O_RDONLY | O_NONBLOCK);
	CHECK(r >= 0, "nonblocking read-only open succeeds at once");
	char buf[16];
	CHECK(read(r, buf, sizeof buf) == 0, "read with no writer is EOF");
	int w = open(FIFO, O_WRONLY | O_NONBLOCK);
	CHECK(w >= 0, "nonblocking write-only open with a reader succeeds");
	struct pollfd pfd = { .fd = r, .events = POLLIN };
	CHECK(poll(&pfd, 1, 0) == 0, "empty FIFO isn't readable");
	CHECK(write(w, "ab", 2) == 2, "write to FIFO");
	CHECK(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN), "FIFO with data is readable");
	CHECK(read(r, buf, sizeof buf) == 2 && memcmp(buf, "ab", 2) == 0, "read back from FIFO");
	close(w);
	close(r);

	int rw = open(FIFO, O_RDWR);
	CHECK(rw >= 0, "O_RDWR open doesn't wait");
	CHECK(write(rw, "x", 1) == 1, "write through an O_RDWR end");
	close(rw);
	r = open(FIFO, O_RDONLY | O_NONBLOCK);
	w = open(FIFO, O_WRONLY | O_NONBLOCK);
	CHECK(read(r, buf, sizeof buf) == -1 && errno == EAGAIN,
	      "data is discarded when the last end closes");
	close(w);
	close(r);

	/* Blocking rendezvous: the child's write-only open waits for our read-only one. */
	pid_t pid = fork();
	if (pid == 0) {
		int cw = open(FIFO, O_WRONLY);
		_exit(cw >= 0 && write(cw, "hello", 5) == 5 ? 0 : 1);
	}
	r = open(FIFO, O_RDONLY);
	CHECK(r >= 0, "blocking read-only open meets a writer");
	int n = 0, got;
	while ((got = read(r, buf + n, sizeof buf - n)) > 0)
		n += got;
	CHECK(n == 5 && memcmp(buf, "hello", 5) == 0 && got == 0,
	      "reader gets the data, then EOF when the writer exits");
	close(r);
	int status;
	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "writer child succeeded");

	/* A blocked open is interruptible. */
	struct sigaction sa = { .sa_handler = on_alarm };
	sigaction(SIGALRM, &sa, NULL);
	alarm(1);
	r = open(FIFO, O_RDONLY);
	CHECK(r == -1 && errno == EINTR, "blocked FIFO open fails EINTR on a signal");
	alarm(0);
	CHECK(open(FIFO, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO,
	      "an interrupted open leaves no reader behind");

	/* A process killed while blocked in open() mustn't leave its reader count behind. */
	pid = fork();
	if (pid == 0) {
		open(FIFO, O_RDONLY);
		_exit(1);
	}
	usleep(200 * 1000);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "blocked opener was killed");
	CHECK(open(FIFO, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO,
	      "a killed opener leaves no reader behind");

	CHECK(unlink(FIFO) == 0, "unlink FIFO");
}

static void sigpipe(void)
{
	int p[2];
	pipe(p);
	close(p[0]);
	pid_t pid = fork();
	if (pid == 0) {
		write(p[1], "x", 1);
		_exit(0);
	}
	int status;
	waitpid(pid, &status, 0);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE,
	      "writing to a pipe with no reader raises SIGPIPE");

	signal(SIGPIPE, SIG_IGN);
	CHECK(write(p[1], "x", 1) == -1 && errno == EPIPE, "with SIGPIPE ignored, write fails EPIPE");
	signal(SIGPIPE, SIG_DFL);
	close(p[1]);
}

int main(void)
{
	fd_numbering();
	fifos();
	sigpipe();
	printf("fd-smoke: %d failure(s)\n", failures);
	return failures;
}
