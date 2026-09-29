/* sysctl(2) and the C library's sysctl(3)/sysctlbyname(3)/sysctlnametomib(3) (OxideBSD-doc
 * SYSCTL.md §§3-5, 11.1), seeded at /sysctl-smoke.elf and run by regress/sysctl-syscall-smoke via
 * tests/sysctl_syscall_smoke.rs.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
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

/* A string variable, or "" if it can't be read. */
static const char *str(const char *name)
{
	static char buf[4][256];
	static int slot;
	char *b = buf[slot++ % 4];
	size_t len = 256;
	if (sysctlbyname(name, b, &len, 0, 0) < 0 || len == 0 || b[len - 1] != 0) b[0] = 0;
	return b;
}

/* An int variable, or -12345. Checks the size too. */
static int num(const char *name)
{
	int v;
	size_t len = sizeof v;
	if (sysctlbyname(name, &v, &len, 0, 0) < 0 || len != sizeof v) return -12345;
	return v;
}

/* The type bits of a variable, from {0, 4}. */
static unsigned kind(const char *name, char *fmt)
{
	int mib[CTL_MAXNAME + 2] = { 0, 4 };
	size_t n = CTL_MAXNAME;
	char buf[64];
	size_t len = sizeof buf;
	if (sysctlnametomib(name, mib + 2, &n) < 0) return 0;
	if (sysctl(mib, n + 2, buf, &len, 0, 0) < 0 || len < 5) return 0;
	if (fmt) strcpy(fmt, buf + 4);
	unsigned k;
	memcpy(&k, buf, 4);
	return k;
}

static void variables(void)
{
	struct utsname u;
	uname(&u);
	CHECK(strcmp(str("kern.ostype"), "OxideBSD") == 0, "kern.ostype is OxideBSD");
	CHECK(strcmp(str("kern.osrelease"), u.release) == 0, "kern.osrelease is uname -r");
	char want[80];
	snprintf(want, sizeof want, "%s\n", u.version);
	CHECK(strcmp(str("kern.version"), want) == 0, "kern.version is uname -v and a newline");
	CHECK(num("kern.hz") == 100, "kern.hz is 100");
	CHECK(num("kern.argmax") == 2 * 1024 * 1024, "kern.argmax is 2 MiB");
	CHECK(num("kern.iov_max") == 1024, "kern.iov_max is 1024");
	CHECK(num("kern.ngroups") >= 1, "kern.ngroups");
	CHECK(num("kern.maxproc") > 0 && num("kern.maxfiles") > 0, "kern.maxproc, kern.maxfiles");

	struct clockinfo ci;
	size_t len = sizeof ci;
	CHECK(sysctlbyname("kern.clockrate", &ci, &len, 0, 0) == 0 && len == sizeof ci && ci.hz == 100 &&
		ci.tick == 10000, "kern.clockrate is a struct clockinfo, hz 100, tick 10000");

	struct timeval bt;
	len = sizeof bt;
	time_t now = time(0);
	CHECK(sysctlbyname("kern.boottime", &bt, &len, 0, 0) == 0 && len == sizeof bt &&
		bt.tv_sec > 1700000000 && bt.tv_sec <= now && bt.tv_usec >= 0 && bt.tv_usec < 1000000,
		"kern.boottime is a timeval before now");

	CHECK(strcmp(str("hw.machine"), "amd64") == 0, "hw.machine is amd64");
	CHECK(strcmp(str("hw.machine_arch"), "amd64") == 0, "hw.machine_arch is amd64");
	CHECK(strcmp(u.machine, "amd64") == 0, "uname -m is hw.machine");
	CHECK(strlen(str("hw.model")) > 0, "hw.model is the CPU's brand string");
	printf("     hw.model = %s\n", str("hw.model"));
	CHECK(num("hw.ncpu") == 1, "hw.ncpu is 1");
	CHECK(num("hw.byteorder") == 1234, "hw.byteorder is 1234");
	CHECK(num("hw.pagesize") == 4096, "hw.pagesize is 4096");
	unsigned long mem;
	len = sizeof mem;
	CHECK(sysctlbyname("hw.physmem", &mem, &len, 0, 0) == 0 && len == sizeof mem &&
		mem > 64UL * 1024 * 1024, "hw.physmem is an unsigned long, more than 64 MiB");

	char fmt[32];
	unsigned k = kind("kern.ostype", fmt);
	CHECK((k & CTLTYPE) == CTLTYPE_STRING && (k & CTLFLAG_RD) && !(k & CTLFLAG_WR) &&
		strcmp(fmt, "A") == 0, "{0,4}: kern.ostype is a read-only string, format A");
	k = kind("kern.hostname", 0);
	CHECK((k & CTLFLAG_RW) == CTLFLAG_RW, "{0,4}: kern.hostname is read-write");
	k = kind("kern.maxproc", fmt);
	CHECK((k & CTLTYPE) == CTLTYPE_INT && (k & CTLFLAG_TUN) && strcmp(fmt, "I") == 0,
		"{0,4}: kern.maxproc is a tunable int");
	k = kind("kern.boottime", fmt);
	CHECK((k & CTLTYPE) == CTLTYPE_OPAQUE && strcmp(fmt, "S,timeval") == 0,
		"{0,4}: kern.boottime is S,timeval");
	k = kind("hw.physmem", fmt);
	CHECK((k & CTLTYPE) == CTLTYPE_ULONG && strcmp(fmt, "LU") == 0, "{0,4}: hw.physmem is LU");
	k = kind("kern", 0);
	CHECK((k & CTLTYPE) == CTLTYPE_NODE, "{0,4}: kern is a node");
}

static void names(void)
{
	int mib[CTL_MAXNAME];
	size_t n = CTL_MAXNAME;
	CHECK(sysctlnametomib("kern.ostype", mib, &n) == 0 && n == 2 && mib[0] == CTL_KERN &&
		mib[1] == KERN_OSTYPE, "sysctlnametomib: kern.ostype is {1, 1}");
	n = CTL_MAXNAME;
	CHECK(sysctlnametomib("hw.pagesize", mib, &n) == 0 && n == 2 && mib[0] == CTL_HW &&
		mib[1] == HW_PAGESIZE, "sysctlnametomib: hw.pagesize is {6, 7}");
	n = CTL_MAXNAME;
	CHECK(sysctlnametomib("kern.hz", mib, &n) == 0 && n == 2 && mib[1] >= 256,
		"sysctlnametomib: kern.hz is numbered from 256");
	n = CTL_MAXNAME;
	CHECK(sysctlnametomib("kern", mib, &n) == 0 && n == 1 && mib[0] == 1, "sysctlnametomib: a node");
	n = CTL_MAXNAME;
	CHECK_ERR(sysctlnametomib("kern.nope", mib, &n), ENOENT, "sysctlnametomib: unknown is ENOENT");

	/* sysctl(3) by number and sysctlbyname(3) agree. */
	int byname, bynum;
	size_t len = sizeof byname;
	sysctlbyname("hw.pagesize", &byname, &len, 0, 0);
	int pg[2] = { CTL_HW, HW_PAGESIZE };
	len = sizeof bynum;
	CHECK(sysctl(pg, 2, &bynum, &len, 0, 0) == 0 && bynum == byname, "sysctl and sysctlbyname agree");

	/* {0, 1}: the name of an OID; {0, 5}: its description. */
	int q[4] = { 0, 1, CTL_KERN, KERN_OSTYPE };
	char buf[128];
	len = sizeof buf;
	CHECK(sysctl(q, 4, buf, &len, 0, 0) == 0 && strcmp(buf, "kern.ostype") == 0 && len == 12,
		"{0,1}: the name of {1, 1}");
	q[1] = 5;
	len = sizeof buf;
	CHECK(sysctl(q, 4, buf, &len, 0, 0) == 0 && strlen(buf) > 0, "{0,5}: a description");
}

static void walk(void)
{
	/* {0, 2}: every variable once, in increasing order, then ENOENT. */
	int q[CTL_MAXNAME + 2] = { 0, 2 };
	int cur[CTL_MAXNAME], prev[CTL_MAXNAME];
	size_t curlen = 0, prevlen = 0;
	int count = 0, ordered = 1, named = 1, saw_ostype = 0, saw_model = 0, leaves_only = 1;
	for (;;) {
		memcpy(q + 2, cur, curlen * sizeof(int));
		int next[CTL_MAXNAME];
		size_t len = sizeof next;
		if (sysctl(q, curlen + 2, next, &len, 0, 0) < 0) {
			CHECK(errno == ENOENT, "{0,2}: the walk ends with ENOENT");
			break;
		}
		memcpy(prev, cur, curlen * sizeof(int));
		prevlen = curlen;
		curlen = len / sizeof(int);
		memcpy(cur, next, len);
		/* Strictly after the previous OID, lexicographically. */
		size_t i = 0;
		while (i < prevlen && i < curlen && prev[i] == cur[i]) i++;
		if (prevlen && !(i < prevlen && i < curlen ? cur[i] > prev[i] : curlen > prevlen)) ordered = 0;
		int nq[CTL_MAXNAME + 2] = { 0, 1 };
		memcpy(nq + 2, cur, curlen * sizeof(int));
		char name[128];
		size_t nl = sizeof name;
		if (sysctl(nq, curlen + 2, name, &nl, 0, 0) < 0) named = 0;
		if (strcmp(name, "kern.ostype") == 0) saw_ostype++;
		if (strcmp(name, "hw.model") == 0) saw_model++;
		if ((kind(name, 0) & CTLTYPE) == CTLTYPE_NODE) leaves_only = 0;
		if (++count > 10000) break;
	}
	printf("     walked %d variables\n", count);
	CHECK(count >= 20 && ordered, "{0,2}: the walk is in strictly increasing order");
	CHECK(named && saw_ostype == 1 && saw_model == 1, "{0,2}: each variable visited once");
	CHECK(leaves_only, "{0,2}: the walk visits variables, not nodes");
}

static void semantics(void)
{
	size_t len;
	int ostype[2] = { CTL_KERN, KERN_OSTYPE };

	len = 0;
	CHECK(sysctl(ostype, 2, 0, &len, 0, 0) == 0 && len == 9, "null oldp: *oldlenp is the size");
	char small[3];
	len = sizeof small;
	CHECK_ERR(sysctl(ostype, 2, small, &len, 0, 0), ENOMEM, "short buffer: ENOMEM");
	CHECK(len == 3 && memcmp(small, "Oxi", 3) == 0, "short buffer: as much as fits is copied");

	int nope[2] = { CTL_KERN, 9999 };
	len = 0;
	CHECK_ERR(sysctl(nope, 2, 0, &len, 0, 0), ENOENT, "an unknown OID is ENOENT");
	int deep[3] = { CTL_KERN, KERN_OSTYPE, 1 };
	CHECK_ERR(sysctl(deep, 3, 0, &len, 0, 0), ENOENT, "below a variable is ENOENT");
	CHECK_ERR(sysctl(ostype, 1, 0, &len, 0, 0), EINVAL, "namelen 1 is EINVAL");
	int big[25] = { 1 };
	CHECK_ERR(sysctl(big, 25, 0, &len, 0, 0), EINVAL, "namelen 25 is EINVAL");
	CHECK_ERR(sysctlbyname("kern.ostype", 0, 0, "Linux", 5), EPERM, "writing a read-only variable is EPERM");
	CHECK_ERR(sysctlbyname("kern.maxproc", 0, 0, &(int){ 5 }, sizeof(int)), EPERM,
		"writing a tunable after boot is EPERM");

	/* kern.hostname, sethostname(2), gethostname(3) and uname(2) are one value. */
	char h[256];
	sethostname("alpha", 5);
	CHECK(strcmp(str("kern.hostname"), "alpha") == 0, "sethostname shows in kern.hostname");
	CHECK(sysctlbyname("kern.hostname", 0, 0, "beta", 4) == 0, "set kern.hostname");
	gethostname(h, sizeof h);
	CHECK(strcmp(h, "beta") == 0, "kern.hostname shows in gethostname");
	struct utsname u;
	uname(&u);
	CHECK(strcmp(u.nodename, "beta") == 0, "kern.hostname shows in uname");
	char longname[80];
	memset(longname, 'x', sizeof longname);
	CHECK_ERR(sysctlbyname("kern.hostname", 0, 0, longname, 65), EINVAL, "a 65-byte host name is EINVAL");
	/* The old value comes back and the new one is set, in one call. */
	char old[64];
	len = sizeof old;
	CHECK(sysctlbyname("kern.hostname", old, &len, "gamma", 5) == 0 && strcmp(old, "beta") == 0 &&
		strcmp(str("kern.hostname"), "gamma") == 0, "read old and set new in one call");

	CHECK(strcmp(str("kern.domainname"), "") == 0, "kern.domainname is empty by default");
	sysctlbyname("kern.domainname", 0, 0, "example.org", 11);
	uname(&u);
	CHECK(strcmp(u.domainname, "example.org") == 0, "kern.domainname shows in uname");

	/* Only root may write. */
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(10);
		if (sysctlbyname("kern.hostname", 0, 0, "evil", 4) == 0 || errno != EPERM) _exit(11);
		char b[64];
		size_t bl = sizeof b;
		if (sysctlbyname("kern.hostname", b, &bl, 0, 0) < 0) _exit(12);
		_exit(0);
	}
	int st;
	CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		"another user reads, but writing is EPERM");
}

/* The whole of kern.msgbuf, malloc'd; "" on failure. */
static char *msgbuf(void)
{
	size_t len = 0;
	if (sysctlbyname("kern.msgbuf", 0, &len, 0, 0) < 0) return strdup("");
	len += 4096; /* room for what's printed meanwhile */
	char *b = malloc(len);
	if (sysctlbyname("kern.msgbuf", b, &len, 0, 0) < 0) b[0] = 0;
	return b;
}

/* Makes the kernel print a line naming `n`: it logs unknown system calls. */
static void kernel_says(long n)
{
	syscall(n);
}

/* Reads /dev/klog without blocking until it's drained; true if `needle` was in what came. */
static int drain(int fd, const char *needle)
{
	static char buf[70000];
	size_t got = 0;
	long n;
	while ((n = read(fd, buf + got, sizeof buf - 1 - got)) > 0) {
		got += n;
		if (got >= sizeof buf - 1) got = 0; /* keep only the tail */
	}
	buf[got] = 0;
	return needle && strstr(buf, needle) != 0;
}

static void message_buffer(void)
{
	CHECK(num("kern.msgbufsize") == 65536, "kern.msgbufsize is 64 KiB");
	char *m = msgbuf();
	CHECK(strstr(m, "[boot] kernel initialization starting") != 0,
		"kern.msgbuf holds the first boot message (from before the heap)");
	CHECK(strstr(m, "[module] sysctl: module_init") != 0, "kern.msgbuf holds module messages");
	free(m);
	kernel_says(9871);
	m = msgbuf();
	CHECK(strstr(m, "unrecognized syscall number 9871") != 0, "kern.msgbuf holds a new kernel message");
	free(m);
	printf("USER-OUTPUT-NOT-KERNEL\n");
	m = msgbuf();
	CHECK(strstr(m, "USER-OUTPUT-NOT-KERNEL") == 0, "user output to the console isn't in kern.msgbuf");
	free(m);

	/* /dev/klog: exclusive, consuming, pollable, blocking. */
	int k = open("/dev/klog", O_RDONLY | O_NONBLOCK);
	CHECK(k >= 0, "open /dev/klog");
	CHECK_ERR(open("/dev/klog", O_RDONLY), EBUSY, "a second open of /dev/klog is EBUSY");
	CHECK(drain(k, "[boot] kernel initialization starting"), "/dev/klog reads the buffer from the start");
	CHECK_ERR(read(k, &(char){ 0 }, 1), EAGAIN, "/dev/klog: drained, O_NONBLOCK read is EAGAIN");
	struct pollfd p = { k, POLLIN, 0 };
	CHECK(poll(&p, 1, 0) == 0, "/dev/klog: drained, not readable");
	kernel_says(9872);
	CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN), "/dev/klog: readable after a kernel message");
	CHECK(drain(k, "unrecognized syscall number 9872"), "/dev/klog reads only what's new");
	CHECK_ERR(write(k, "x", 1), EOPNOTSUPP, "writing /dev/klog is EOPNOTSUPP");

	pid_t pid = fork();
	if (pid == 0) {
		usleep(300000);
		kernel_says(9873);
		_exit(0);
	}
	fcntl(k, F_SETFL, 0);
	char buf[512];
	long n = read(k, buf, sizeof buf - 1);
	buf[n > 0 ? n : 0] = 0;
	CHECK(n > 0 && strstr(buf, "9873") != 0, "/dev/klog: a blocking read waits for the next message");
	waitpid(pid, 0, 0);

	pid = fork();
	if (pid == 0) {
		close(k);
		if (setuid(1000) < 0) _exit(10);
		_exit(open("/dev/klog", O_RDONLY) < 0 && errno == EACCES ? 0 : 11);
	}
	int st;
	CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		"/dev/klog is root's (EACCES for another user)");
	close(k);
	k = open("/dev/klog", O_RDONLY | O_NONBLOCK);
	CHECK(k >= 0, "/dev/klog opens again once closed");
	close(k);

	/* kern.msgbuf_clear empties what kern.msgbuf shows. */
	CHECK(sysctlbyname("kern.msgbuf_clear", 0, 0, &(int){ 1 }, sizeof(int)) == 0, "set kern.msgbuf_clear");
	m = msgbuf();
	CHECK(strstr(m, "[boot] kernel initialization starting") == 0, "kern.msgbuf is empty after a clear");
	free(m);
	kernel_says(9874);
	m = msgbuf();
	CHECK(strstr(m, "9874") != 0, "kern.msgbuf fills again after a clear");
	free(m);
}

int main(void)
{
	setvbuf(stdout, 0, _IONBF, 0);
	variables();
	names();
	walk();
	semantics();
	message_buffer();
	printf("sysctl-smoke: %d failure(s)\n", failures);
	return failures;
}
