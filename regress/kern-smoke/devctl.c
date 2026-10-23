/*
 * kern-smoke devctl: device events (OxideBSD-doc DEVD.md §3-4). /dev/devctl holds the events of
 * boot (each disk's attach line before its nodes' create lines), has one reader at a time, is
 * read-only, reads lines whole or in part, blocks until an event comes (and poll says so), fails
 * with EAGAIN under O_NONBLOCK, keeps its queue across a close, and with a full queue drops the
 * oldest lines and says how many. A pseudo-terminal's pts node makes an event pair on demand.
 * `kern-smoke devctl-dump` prints what is queued, for other tests' scripts.
 */
#include <poll.h>

static const char *devctl = "/dev/devctl";

/* Everything queued, read without blocking from `fd`, NUL-terminated in `buf`; its length. */
static size_t devctl_drain(int fd, char *buf, size_t cap)
{
	size_t total = 0;
	ssize_t n;
	while (total < cap - 1 && (n = read(fd, buf + total, cap - 1 - total)) > 0)
		total += n;
	buf[total] = 0;
	return total;
}

/* Opens and closes /dev/ptmx `times` times: a create and a destroy dev event each. */
static void pty_events(int times)
{
	for (int i = 0; i < times; i++) {
		int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
		if (m >= 0)
			close(m);
	}
}

static int readable_now(int fd)
{
	struct pollfd p = { fd, POLLIN, 0 };
	return poll(&p, 1, 0) == 1 && (p.revents & POLLIN);
}

/* Whether every line of `buf` is `verb class[ name=value...]`, lower-case words first. */
static int lines_well_formed(const char *buf)
{
	for (const char *l = buf; *l; ) {
		const char *end = strchr(l, '\n');
		if (end == NULL || !(l[0] >= 'a' && l[0] <= 'z') || memchr(l, ' ', end - l) == NULL)
			return 0;
		l = end + 1;
	}
	return 1;
}

static long devctl_dropped(void)
{
	FILE *f = popen("/sbin/sysctl -n kern.devctl.dropped", "r");
	long v = -1;
	if (f) {
		if (fscanf(f, "%ld", &v) != 1)
			v = -1;
		pclose(f);
	}
	return v;
}

static int unprivileged_open(void)
{
	if (setgid(4250) != 0 || setuid(4250) != 0)
		return 10;
	errno = 0;
	return open(devctl, O_RDONLY | O_NONBLOCK) == -1 && errno == EACCES ? 0 : 1;
}

static void devctl_main(void)
{
	static char buf[1 << 16];
	char line[256];

	int fd = open(devctl, O_RDONLY | O_NONBLOCK);
	check(fd >= 0, "/dev/devctl opens");
	errno = 0;
	check(open(devctl, O_RDONLY) == -1 && errno == EBUSY, "a second open fails with EBUSY");
	close(fd);
	errno = 0;
	check(open(devctl, O_RDWR) == -1 && errno == EACCES, "an open for writing fails with EACCES");
	check(child_exit_ok(unprivileged_open), "and a user can't open it");
	fd = open(devctl, O_RDONLY | O_NONBLOCK);
	check(fd >= 0, "it opens again once closed");

	/* --- Boot's events --- */
	devctl_drain(fd, buf, sizeof buf);
	check(lines_well_formed(buf), "every line is `verb class name=value ...`");
	char *attach = strstr(buf, "attach disk name=");
	char name[64] = "";
	if (attach)
		sscanf(attach, "attach disk name=%63s", name);
	snprintf(line, sizeof line, "\ncreate dev name=%s major=", name);
	char *node = strstr(buf, line);
	check(attach && name[0] && node && node > attach, "boot's disk is reported, its attach line before its node's");
	if (attach) {
		char *end = strchr(attach, '\n');
		printf("  %.*s\n", end ? (int)(end - attach) : 80, attach);
	}
	check(attach && strstr(attach, " bus=") && strstr(attach, " kind=disk ") && strstr(attach, " sectors=") &&
		      strstr(attach, " sector_size="),
	      "with its bus, kind, size and sector size");
	check(strstr(buf, "create dev name=null major=1 minor=3\n") != NULL, "boot's /dev nodes are reported (null)");
	check(strstr(buf, "create dev name=devctl major=7 minor=1\n") != NULL, "... devctl's own included");

	/* --- Empty, then an event --- */
	errno = 0;
	check(read(fd, line, sizeof line) == -1 && errno == EAGAIN, "an empty queue reads EAGAIN under O_NONBLOCK");
	check(!readable_now(fd), "and poll says it isn't readable");
	int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	check(readable_now(fd), "a new pts node makes it readable");
	devctl_drain(fd, buf, sizeof buf);
	int pts = -1;
	check(sscanf(buf, "create dev name=pts/%d major=136 minor=", &pts) == 1, "with its create dev line");
	close(m);
	devctl_drain(fd, buf, sizeof buf);
	snprintf(line, sizeof line, "destroy dev name=pts/%d major=136 minor=%d\n", pts, pts);
	check(strcmp(buf, line) == 0, "and closing it, its destroy dev line");
	if (strcmp(buf, line) != 0)
		printf("  got: %s", buf);

	/* --- Lines read in part --- */
	pty_events(1);
	char part[256] = "";
	ssize_t a = read(fd, part, 5);
	ssize_t b = read(fd, part + 5, sizeof part - 6);
	check(a == 5 && b > 0 && strncmp(part, "create dev name=pts/", 20) == 0 && strchr(part, '\n') && strstr(part, "destroy dev name=pts/"),
	      "a short read gives part of a line, the next the rest");

	/* --- A blocking read waits for the event --- */
	int flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	pid_t child = fork();
	if (child == 0) {
		usleep(300000);
		pty_events(1);
		_exit(0);
	}
	ssize_t n = read(fd, line, sizeof line - 1);
	line[n > 0 ? n : 0] = 0;
	check(n > 0 && strncmp(line, "create dev name=pts/", 20) == 0, "a blocking read waits for the next event");
	waitpid(child, NULL, 0);
	fcntl(fd, F_SETFL, flags);
	devctl_drain(fd, buf, sizeof buf);

	/* --- Kept across a close, less a line read in part --- */
	pty_events(1);
	read(fd, line, 5);
	close(fd);
	pty_events(1);
	fd = open(devctl, O_RDONLY | O_NONBLOCK);
	devctl_drain(fd, buf, sizeof buf);
	check(strncmp(buf, "destroy dev name=pts/", 21) == 0 && strstr(buf, "\ncreate dev name=pts/") &&
		      strstr(buf, "\ndestroy dev name=pts/"),
	      "the next open starts on a whole line, and gets what came while it was closed");

	/* --- A full queue --- */
	check(system("/sbin/sysctl -q kern.devctl.queue=15 >/dev/null 2>&1") != 0, "kern.devctl.queue below 16 is refused");
	long before = devctl_dropped();
	check(system("/sbin/sysctl -q kern.devctl.queue=16 >/dev/null") == 0, "kern.devctl.queue=16");
	pty_events(20);
	long after = devctl_dropped();
	devctl_drain(fd, buf, sizeof buf);
	int lines = 0;
	for (char *p = buf; (p = strchr(p, '\n')); p++)
		lines++;
	check(strncmp(buf, "lost devctl count=24\n", 21) == 0, "40 events into 16 places: `lost devctl count=24` first");
	check(lines == 17, "then the newest 16");
	check(before >= 0 && after - before == 24, "kern.devctl.dropped counts the 24");
	if (lines != 17 || after - before != 24)
		printf("  %d lines, dropped %ld -> %ld; first: %.40s\n", lines, before, after, buf);
	system("/sbin/sysctl -q kern.devctl.queue=256 >/dev/null");
	close(fd);
}

/* Prints what /dev/devctl holds, without waiting. */
static void devctl_dump_main(void)
{
	static char buf[1 << 16];
	int fd = open(devctl, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		failures++;
		return;
	}
	devctl_drain(fd, buf, sizeof buf);
	fputs(buf, stdout);
	close(fd);
}
