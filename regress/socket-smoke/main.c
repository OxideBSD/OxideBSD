/* The socket layer through musl's own API (OxideBSD-doc UNIX.md §§3-11), seeded at
 * /socket-smoke.elf and run by regress/socket-syscall-smoke via
 * tests/socket_syscall_smoke.rs. Internet sockets: what needs no peer (there is no loopback
 * interface), plus a connection refused by QEMU's gateway. Local sockets: naming, permissions,
 * each type's semantics, shutdown and close, descriptor passing and its garbage collection, and
 * every credential interface (UNIX.md §§8-9), with forked children as the other side.
 *
 * Each CHECK prints PASS/FAIL; the exit status is the failure count (0 = all passed). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/un.h>
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

static int getint(int fd, int level, int name)
{
	int v = -12345;
	socklen_t len = sizeof v;
	if (getsockopt(fd, level, name, &v, &len) < 0 || len != sizeof v) return -12345;
	return v;
}

static long ms_since(const struct timespec *t0)
{
	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

static struct sockaddr_in inet(const char *ip, int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	inet_pton(AF_INET, ip, &a.sin_addr);
	return a;
}

static void creation(void)
{
	CHECK_ERR(socket(12345, SOCK_DGRAM, 0), EAFNOSUPPORT, "socket: unknown domain is EAFNOSUPPORT");
	CHECK_ERR(socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP), EPROTOTYPE,
		"socket: TCP under SOCK_DGRAM is EPROTOTYPE");
	CHECK_ERR(socket(AF_INET, SOCK_STREAM, 99), EPROTONOSUPPORT,
		"socket: unknown protocol is EPROTONOSUPPORT");

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	CHECK(fd >= 0, "socket: SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK");
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC, "socket: SOCK_CLOEXEC sets FD_CLOEXEC");
	CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK, "socket: SOCK_NONBLOCK sets O_NONBLOCK");
	char c;
	CHECK_ERR(recv(fd, &c, 1, 0), EAGAIN, "recv: nonblocking and empty is EAGAIN");
	close(fd);

	int plain = open("/etc/passwd", O_RDONLY);
	CHECK_ERR(getsockname(plain, 0, 0), ENOTSOCK, "getsockname: a file is ENOTSOCK");
	close(plain);
}

static void options(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(getint(fd, SOL_SOCKET, SO_TYPE) == SOCK_DGRAM, "SO_TYPE");
	CHECK(getint(fd, SOL_SOCKET, SO_DOMAIN) == AF_INET, "SO_DOMAIN");
	CHECK(getint(fd, SOL_SOCKET, SO_PROTOCOL) == 0, "SO_PROTOCOL");
	CHECK(getint(fd, SOL_SOCKET, SO_ERROR) == 0, "SO_ERROR: none");
	CHECK(getint(fd, SOL_SOCKET, SO_ACCEPTCONN) == 0, "SO_ACCEPTCONN: not listening");
	CHECK(getint(fd, SOL_SOCKET, SO_RCVBUF) == 65536, "SO_RCVBUF: 64 KiB default");

	int v = 8192;
	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) == 0, "SO_RCVBUF: set");
	CHECK(getint(fd, SOL_SOCKET, SO_RCVBUF) == 8192, "SO_RCVBUF: reads back");
	v = 1;
	CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v) == 0 &&
		getint(fd, SOL_SOCKET, SO_REUSEADDR) == 1, "SO_REUSEADDR");
	CHECK(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &v, sizeof v) == 0 &&
		getint(fd, SOL_SOCKET, SO_NOSIGPIPE) == 1, "SO_NOSIGPIPE");
	v = 7;
	CHECK(setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof v) == 0 &&
		getint(fd, IPPROTO_IP, IP_TTL) == 7, "IP_TTL: set and read back");
	CHECK_ERR(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5), ENOPROTOOPT,
		"SO_BINDTODEVICE: not supported, ENOPROTOOPT");
	CHECK_ERR(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v), ENOPROTOOPT,
		"TCP_NODELAY on UDP: ENOPROTOOPT");
	short s = 1;
	CHECK_ERR(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &s, sizeof s), EINVAL,
		"SO_KEEPALIVE: too short a value is EINVAL");

	struct linger l = { 1, 5 }, l2;
	socklen_t ll = sizeof l2;
	CHECK(setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0 &&
		getsockopt(fd, SOL_SOCKET, SO_LINGER, &l2, &ll) == 0 && l2.l_onoff && l2.l_linger == 5,
		"SO_LINGER");

	/* SO_RCVTIMEO: a blocking receive gives up with EAGAIN. */
	struct timeval tv = { 0, 300000 };
	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO: set");
	struct timeval tv2;
	socklen_t tl = sizeof tv2;
	CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, &tl) == 0 && tv2.tv_sec == 0 &&
		tv2.tv_usec == 300000, "SO_RCVTIMEO: reads back");
	struct sockaddr_in any = inet("0.0.0.0", 0);
	bind(fd, (struct sockaddr *)&any, sizeof any);
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	char c;
	CHECK_ERR(recv(fd, &c, 1, 0), EAGAIN, "SO_RCVTIMEO: recv times out with EAGAIN");
	long ms = ms_since(&t0);
	CHECK(ms >= 250 && ms < 3000, "SO_RCVTIMEO: after about 300 ms");
	clock_gettime(CLOCK_MONOTONIC, &t0);
	CHECK_ERR(recv(fd, &c, 1, MSG_DONTWAIT), EAGAIN, "MSG_DONTWAIT: EAGAIN at once");
	CHECK(ms_since(&t0) < 200, "MSG_DONTWAIT: didn't wait");
	close(fd);
}

static void udp(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in any = inet("0.0.0.0", 0), gw = inet("10.0.2.2", 9), got;
	socklen_t len = sizeof got;
	CHECK_ERR(getpeername(fd, (struct sockaddr *)&got, &len), ENOTCONN,
		"getpeername: unconnected UDP is ENOTCONN");
	CHECK(bind(fd, (struct sockaddr *)&any, sizeof any) == 0, "bind: ephemeral port");
	CHECK_ERR(bind(fd, (struct sockaddr *)&any, sizeof any), EINVAL, "bind: twice is EINVAL");
	len = sizeof got;
	CHECK(getsockname(fd, (struct sockaddr *)&got, &len) == 0 && len == sizeof got &&
		ntohs(got.sin_port) >= 49152, "getsockname: the bound port, full length");
	len = 4;
	memset(&got, 0, sizeof got);
	CHECK(getsockname(fd, (struct sockaddr *)&got, &len) == 0 && len == sizeof got &&
		got.sin_family == AF_INET && got.sin_addr.s_addr == 0,
		"getsockname: truncated to the room given, real length reported");

	CHECK(connect(fd, (struct sockaddr *)&gw, sizeof gw) == 0, "connect: UDP default destination");
	len = sizeof got;
	CHECK(getpeername(fd, (struct sockaddr *)&got, &len) == 0 && got.sin_port == htons(9) &&
		got.sin_addr.s_addr == gw.sin_addr.s_addr, "getpeername: the connected address");
	CHECK(send(fd, "x", 1, 0) == 1, "send: to the connected address");
	CHECK_ERR(sendto(fd, "x", 1, 0, (struct sockaddr *)&gw, sizeof gw), EISCONN,
		"sendto: with an address while connected is EISCONN");
	CHECK_ERR(send(fd, "x", 1, MSG_OOB), EOPNOTSUPP, "send: MSG_OOB is EOPNOTSUPP");
	CHECK_ERR(send(fd, "x", 1, MSG_MORE), EOPNOTSUPP, "send: an unsupported flag is EOPNOTSUPP");
	CHECK_ERR(send(fd, "x", 1, MSG_EOR), EOPNOTSUPP, "send: MSG_EOR on a datagram socket");

	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	CHECK(connect(fd, &unspec, sizeof unspec) == 0, "connect: AF_UNSPEC disconnects");
	len = sizeof got;
	CHECK_ERR(getpeername(fd, (struct sockaddr *)&got, &len), ENOTCONN,
		"getpeername: ENOTCONN again");
	CHECK_ERR(send(fd, "x", 1, 0), EDESTADDRREQ, "send: no destination is EDESTADDRREQ");
	CHECK_ERR(listen(fd, 1), EOPNOTSUPP, "listen: UDP is EOPNOTSUPP");
	close(fd);
}

static void tcp(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in any = inet("0.0.0.0", 0), got;
	socklen_t len = sizeof got;
	CHECK_ERR(getpeername(fd, (struct sockaddr *)&got, &len), ENOTCONN,
		"getpeername: unconnected TCP is ENOTCONN");
	char c;
	CHECK_ERR(recv(fd, &c, 1, 0), ENOTCONN, "recv: unconnected TCP is ENOTCONN");
	CHECK(bind(fd, (struct sockaddr *)&any, sizeof any) == 0, "bind: TCP");
	CHECK(listen(fd, 4) == 0, "listen");
	CHECK(getint(fd, SOL_SOCKET, SO_ACCEPTCONN) == 1, "SO_ACCEPTCONN: listening");
	int v = 1;
	CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v) == 0, "TCP_NODELAY on TCP");
	fcntl(fd, F_SETFL, O_NONBLOCK);
	CHECK_ERR(accept4(fd, 0, 0, SOCK_CLOEXEC), EAGAIN, "accept4: nonblocking, none waiting");
	CHECK_ERR(accept4(fd, 0, 0, 0x1234), EINVAL, "accept4: unknown flags are EINVAL");
	close(fd);

	/* QEMU's gateway refuses a connection to a port nothing listens on. */
	struct sockaddr_in closed = inet("10.0.2.2", 1);
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	CHECK_ERR(connect(fd, (struct sockaddr *)&closed, sizeof closed), EINPROGRESS,
		"connect: nonblocking is EINPROGRESS");
	struct pollfd p = { fd, POLLOUT, 0 };
	CHECK(poll(&p, 1, 10000) == 1, "poll: the connect attempt ends");
	CHECK(getint(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED, "SO_ERROR: ECONNREFUSED");
	CHECK(getint(fd, SOL_SOCKET, SO_ERROR) == 0, "SO_ERROR: reported once");
	close(fd);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_ERR(connect(fd, (struct sockaddr *)&closed, sizeof closed), ECONNREFUSED,
		"connect: blocking, refused");
	close(fd);
}

static void retired(void)
{
	/* The reduced sendto/recvfrom/setsockopt of the old interface (UNIX.md §4.4). */
	CHECK_ERR(syscall(142, 0, 0, 0, 0), ENOSYS, "syscall 142 (old sendto) is ENOSYS");
	CHECK_ERR(syscall(143, 0, 0, 0, 0), ENOSYS, "syscall 143 (old recvfrom) is ENOSYS");
	CHECK_ERR(syscall(144, 0, 0, 0, 0), ENOSYS, "syscall 144 (old setsockopt) is ENOSYS");
}

/* ---- Local sockets (UNIX.md §§5-7, 10) ---- */

static volatile sig_atomic_t sigpipes;

static void on_sigpipe(int sig)
{
	(void)sig;
	sigpipes++;
}

/* A path address, and its length as UNIX.md §5.4 returns it. */
static socklen_t un_path(struct sockaddr_un *a, const char *path)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	strcpy(a->sun_path, path);
	return offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
}

/* An abstract address of `n` name bytes. */
static socklen_t un_abstract(struct sockaddr_un *a, const char *name, size_t n)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	memcpy(a->sun_path + 1, name, n);
	return offsetof(struct sockaddr_un, sun_path) + 1 + n;
}

static int bound(int type, const char *path)
{
	struct sockaddr_un a;
	socklen_t len = un_path(&a, path);
	int fd = socket(AF_UNIX, type, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&a, len) < 0) return -1;
	return fd;
}

static int connected(int type, const char *path)
{
	struct sockaddr_un a;
	socklen_t len = un_path(&a, path);
	int fd = socket(AF_UNIX, type, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&a, len) < 0) return -1;
	return fd;
}

/* Waits for a forked child; true if it exited 0. */
static int child_ok(pid_t pid)
{
	int st;
	return waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void local_naming(void)
{
	struct sockaddr_un a, got;
	socklen_t len, glen;
	struct stat st;

	CHECK_ERR(socket(AF_UNIX, SOCK_RAW, 0), EPROTONOSUPPORT, "local: SOCK_RAW is EPROTONOSUPPORT");
	CHECK_ERR(socket(AF_UNIX, SOCK_STREAM, 5), EPROTONOSUPPORT,
		"local: nonzero protocol is EPROTONOSUPPORT");

	umask(022);
	mkdir("/ut", 0755);
	int s1 = bound(SOCK_STREAM, "/ut/s1");
	CHECK(s1 >= 0, "local: bind to a path");
	CHECK(stat("/ut/s1", &st) == 0 && S_ISSOCK(st.st_mode), "local: the path is S_IFSOCK");
	CHECK((st.st_mode & 0777) == 0755, "local: socket file mode is 0777 & ~umask");
	CHECK(lstat("/ut/s1", &st) == 0 && S_ISSOCK(st.st_mode), "local: lstat sees S_IFSOCK");
	CHECK_ERR(open("/ut/s1", O_RDWR), EOPNOTSUPP, "local: open(2) on a socket file is EOPNOTSUPP");

	int s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	len = un_path(&a, "/ut/s1");
	CHECK_ERR(bind(s2, (struct sockaddr *)&a, len), EADDRINUSE, "local: bind to an existing path");
	len = un_path(&a, "/ut/s1b");
	CHECK_ERR(bind(s1, (struct sockaddr *)&a, len), EINVAL, "local: bind twice is EINVAL");
	len = un_path(&a, "/ut/nodir/x");
	CHECK_ERR(bind(s2, (struct sockaddr *)&a, len), ENOENT, "local: bind under a missing directory");

	glen = sizeof got;
	CHECK(getsockname(s1, (struct sockaddr *)&got, &glen) == 0 &&
		glen == offsetof(struct sockaddr_un, sun_path) + strlen("/ut/s1") + 1 &&
		strcmp(got.sun_path, "/ut/s1") == 0, "local: getsockname gives the path and its length");
	glen = sizeof got;
	CHECK(getsockname(s2, (struct sockaddr *)&got, &glen) == 0 && glen == sizeof(sa_family_t),
		"local: unnamed getsockname is just the family");

	/* Abstract names, NUL bytes included. */
	int ab = socket(AF_UNIX, SOCK_DGRAM, 0);
	len = un_abstract(&a, "ab\0c", 4);
	CHECK(bind(ab, (struct sockaddr *)&a, len) == 0, "local: bind an abstract name");
	glen = sizeof got;
	CHECK(getsockname(ab, (struct sockaddr *)&got, &glen) == 0 && glen == len &&
		got.sun_path[0] == 0 && memcmp(got.sun_path + 1, "ab\0c", 4) == 0,
		"local: getsockname gives the abstract name");
	int ab2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK_ERR(bind(ab2, (struct sockaddr *)&a, len), EADDRINUSE, "local: abstract name in use");
	len = un_abstract(&a, "ab", 2);
	CHECK(bind(ab2, (struct sockaddr *)&a, len) == 0, "local: a prefix is a different abstract name");
	close(ab2);
	CHECK(bind(socket(AF_UNIX, SOCK_DGRAM, 0), (struct sockaddr *)&a, len) == 0,
		"local: an abstract name is released on close");
	close(ab);

	/* Autobind: sizeof(sa_family_t) binds a fresh five-hex-digit abstract name. */
	int au = socket(AF_UNIX, SOCK_DGRAM, 0);
	a.sun_family = AF_UNIX;
	CHECK(bind(au, (struct sockaddr *)&a, sizeof(sa_family_t)) == 0, "local: autobind");
	glen = sizeof got;
	CHECK(getsockname(au, (struct sockaddr *)&got, &glen) == 0 &&
		glen == sizeof(sa_family_t) + 6 && got.sun_path[0] == 0,
		"local: autobind name is five bytes, abstract");
	close(au);

	/* Connecting. */
	int c = socket(AF_UNIX, SOCK_STREAM, 0);
	len = un_path(&a, "/ut/none");
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), ENOENT, "local: connect to a missing path");
	close(open("/ut/plain", O_CREAT | O_WRONLY, 0666));
	len = un_path(&a, "/ut/plain");
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), ENOTSOCK, "local: connect to a regular file");
	len = un_path(&a, "/ut/s1");
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), ECONNREFUSED,
		"local: connect to a socket that isn't listening");
	int d = bound(SOCK_DGRAM, "/ut/d1");
	len = un_path(&a, "/ut/d1");
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), EPROTOTYPE,
		"local: stream connect to a datagram socket is EPROTOTYPE");
	close(d);
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), ECONNREFUSED,
		"local: a stale socket file refuses");
	CHECK(unlink("/ut/d1") == 0 && stat("/ut/d1", &st) < 0, "local: unlink a socket file");
	len = un_abstract(&a, "nobody-here", 11);
	CHECK_ERR(connect(c, (struct sockaddr *)&a, len), ECONNREFUSED,
		"local: connect to an unbound abstract name");
	close(c);

	/* Permissions: write permission on the file to connect, on the directory to bind. */
	CHECK(listen(s1, 4) == 0, "local: listen on a path");
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(10);
		struct sockaddr_un b;
		socklen_t bl = un_path(&b, "/ut/s1");
		int x = socket(AF_UNIX, SOCK_STREAM, 0);
		if (connect(x, (struct sockaddr *)&b, bl) == 0 || errno != EACCES) _exit(11);
		bl = un_path(&b, "/ut/mine");
		if (bind(x, (struct sockaddr *)&b, bl) == 0 || errno != EACCES) _exit(12);
		_exit(0);
	}
	CHECK(child_ok(pid), "local: another user: connect EACCES without write permission, bind "
		"EACCES in a directory it can't write");
	chmod("/ut/s1", 0777);
	pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(10);
		_exit(connected(SOCK_STREAM, "/ut/s1") >= 0 ? 0 : 11);
	}
	CHECK(child_ok(pid), "local: another user connects once the file is 0777");
	close(s1);
	close(s2);
}

static void local_stream(void)
{
	struct sockaddr_un a, got;
	socklen_t glen;
	char buf[64];

	int l = bound(SOCK_STREAM, "/ut/st");
	CHECK(listen(l, 1) == 0, "stream: listen, backlog 1");
	CHECK(getint(l, SOL_SOCKET, SO_ACCEPTCONN) == 1, "stream: SO_ACCEPTCONN");
	int c = connected(SOCK_STREAM, "/ut/st");
	CHECK(c >= 0, "stream: connect completes at once");
	CHECK(connected(SOCK_STREAM, "/ut/st") < 0 && errno == ECONNREFUSED,
		"stream: connect to a full queue is ECONNREFUSED");
	struct pollfd p = { l, POLLIN, 0 };
	CHECK(poll(&p, 1, 0) == 1 && (p.revents & POLLIN), "stream: listener polls readable");
	glen = sizeof got;
	int s = accept(l, (struct sockaddr *)&got, &glen);
	CHECK(s >= 0 && glen == sizeof(sa_family_t), "stream: accept, the client is unnamed");
	glen = sizeof got;
	CHECK(getpeername(c, (struct sockaddr *)&got, &glen) == 0 && strcmp(got.sun_path, "/ut/st") == 0,
		"stream: getpeername gives the listener's path");
	glen = sizeof got;
	CHECK(getsockname(s, (struct sockaddr *)&got, &glen) == 0 && strcmp(got.sun_path, "/ut/st") == 0,
		"stream: the accepted socket has the listener's name");
	CHECK_ERR(connect(c, (struct sockaddr *)&a, un_path(&a, "/ut/st")), EISCONN,
		"stream: connect twice is EISCONN");

	CHECK(write(c, "hello", 5) == 5, "stream: write");
	CHECK(recv(s, buf, 3, MSG_PEEK) == 3 && memcmp(buf, "hel", 3) == 0, "stream: MSG_PEEK");
	CHECK(read(s, buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0,
		"stream: read after peek gets it all");
	CHECK(write(c, "ab", 2) == 2 && write(c, "cd", 2) == 2 && read(s, buf, sizeof buf) == 4 &&
		memcmp(buf, "abcd", 4) == 0, "stream: no boundaries between writes");
	CHECK_ERR(recv(s, buf, 1, MSG_DONTWAIT), EAGAIN, "stream: empty, MSG_DONTWAIT is EAGAIN");
	CHECK_ERR(send(s, "x", 1, MSG_OOB), EOPNOTSUPP, "stream: MSG_OOB is EOPNOTSUPP");

	/* MSG_WAITALL waits for the rest, sent later by a child. */
	pid_t pid = fork();
	if (pid == 0) {
		write(c, "12", 2);
		usleep(200000);
		write(c, "34", 2);
		_exit(0);
	}
	CHECK(recv(s, buf, 4, MSG_WAITALL) == 4 && memcmp(buf, "1234", 4) == 0, "stream: MSG_WAITALL");
	child_ok(pid);

	/* A full buffer: SO_RCVBUF bounds what the peer can queue. */
	int v = 4096;
	setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
	fcntl(c, F_SETFL, O_NONBLOCK);
	long total = 0, n;
	char big[1000];
	memset(big, 'z', sizeof big);
	while ((n = write(c, big, sizeof big)) > 0) total += n;
	CHECK(n < 0 && errno == EAGAIN && total == 4096, "stream: SO_RCVBUF bounds the queue, then EAGAIN");
	p = (struct pollfd){ c, POLLOUT, 0 };
	CHECK(poll(&p, 1, 0) == 0, "stream: full, not writable");
	fcntl(c, F_SETFL, 0);
	/* A blocked writer resumes once a child drains. */
	pid = fork();
	if (pid == 0) {
		usleep(200000);
		char sink[8192];
		long got_ = 0;
		while (got_ < 4096 + 3000) {
			long r = read(s, sink, sizeof sink);
			if (r <= 0) _exit(1);
			got_ += r;
		}
		_exit(0);
	}
	CHECK(write(c, big, 1000) == 1000 && write(c, big, 1000) == 1000 && write(c, big, 1000) == 1000,
		"stream: a blocked write completes once the reader drains");
	CHECK(child_ok(pid), "stream: the reader got every byte");

	/* shutdown(SHUT_WR): the peer reads end-of-file; the other direction still works. */
	CHECK(shutdown(c, SHUT_WR) == 0, "stream: shutdown SHUT_WR");
	CHECK(read(s, buf, sizeof buf) == 0, "stream: peer reads EOF after SHUT_WR");
	CHECK(write(s, "back", 4) == 4 && read(c, buf, sizeof buf) == 4, "stream: other direction still works");
	signal(SIGPIPE, on_sigpipe);
	sigpipes = 0;
	CHECK_ERR(write(c, "x", 1), EPIPE, "stream: write after SHUT_WR is EPIPE");
	CHECK(sigpipes == 1, "stream: ... and raises SIGPIPE");
	CHECK_ERR(send(c, "x", 1, MSG_NOSIGNAL), EPIPE, "stream: MSG_NOSIGNAL: EPIPE");
	CHECK(sigpipes == 1, "stream: ... without SIGPIPE");

	/* The peer closes: EOF, EPIPE, POLLHUP. */
	close(c);
	p = (struct pollfd){ s, POLLIN, 0 };
	CHECK(poll(&p, 1, 0) == 1 && (p.revents & POLLHUP), "stream: POLLHUP once the peer is gone");
	CHECK(read(s, buf, sizeof buf) == 0, "stream: read after the peer closed is EOF");
	v = 1;
	setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &v, sizeof v);
	CHECK_ERR(write(s, "x", 1), EPIPE, "stream: write to a closed peer is EPIPE");
	CHECK(sigpipes == 1, "stream: SO_NOSIGPIPE suppresses SIGPIPE");
	glen = sizeof got;
	CHECK_ERR(getpeername(s, (struct sockaddr *)&got, &glen), ENOTCONN,
		"stream: getpeername after the peer closed is ENOTCONN");
	close(s);

	/* SHUT_RD: incoming data is discarded, reads see EOF. */
	c = connected(SOCK_STREAM, "/ut/st");
	s = accept(l, 0, 0);
	CHECK(shutdown(s, SHUT_RD) == 0 && write(c, "lost", 4) == 4 && read(s, buf, sizeof buf) == 0,
		"stream: after SHUT_RD, data is dropped and reads see EOF");
	close(s);
	close(c);

	/* Connections still queued when the listener closes are reset. */
	c = connected(SOCK_STREAM, "/ut/st");
	close(l);
	CHECK_ERR(read(c, buf, 1), ECONNRESET, "stream: a queued connection is reset when the listener closes");
	close(c);
	CHECK(connected(SOCK_STREAM, "/ut/st") < 0 && errno == ECONNREFUSED,
		"stream: the closed listener's file refuses");
	signal(SIGPIPE, SIG_DFL);

	/* Unconnected. */
	c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK_ERR(write(c, "x", 1), ENOTCONN, "stream: write unconnected is ENOTCONN");
	CHECK_ERR(listen(c, 1), EINVAL, "stream: listen unbound is EINVAL");
	CHECK_ERR(shutdown(c, SHUT_RDWR), ENOTCONN, "stream: shutdown unconnected is ENOTCONN");
	close(c);
}

static void local_dgram(void)
{
	struct sockaddr_un a, from;
	socklen_t alen, flen;
	char buf[64];

	int srv = bound(SOCK_DGRAM, "/ut/dg");
	CHECK(srv >= 0, "dgram: bind");
	CHECK_ERR(listen(srv, 1), EOPNOTSUPP, "dgram: listen is EOPNOTSUPP");
	alen = un_path(&a, "/ut/dg");
	int cl = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(sendto(cl, "one", 3, 0, (struct sockaddr *)&a, alen) == 3, "dgram: sendto a path");
	flen = sizeof from;
	CHECK(recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 3 &&
		flen == sizeof(sa_family_t), "dgram: from an unnamed sender");

	struct sockaddr_un me;
	socklen_t melen = un_abstract(&me, "dgram-client", 12);
	bind(cl, (struct sockaddr *)&me, melen);
	sendto(cl, "a", 1, 0, (struct sockaddr *)&a, alen);
	sendto(cl, "bc", 2, 0, (struct sockaddr *)&a, alen);
	flen = sizeof from;
	CHECK(recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 1 && flen == melen &&
		memcmp(from.sun_path + 1, "dgram-client", 12) == 0, "dgram: sender's name, boundaries kept (1)");
	CHECK(recv(srv, buf, sizeof buf, 0) == 2, "dgram: boundaries kept (2)");

	/* Truncation. */
	sendto(cl, "0123456789", 10, 0, (struct sockaddr *)&a, alen);
	struct iovec iov = { buf, 4 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1 };
	CHECK(recvmsg(srv, &m, 0) == 4 && (m.msg_flags & MSG_TRUNC), "dgram: truncated, MSG_TRUNC");
	sendto(cl, "0123456789", 10, 0, (struct sockaddr *)&a, alen);
	CHECK(recv(srv, buf, 4, MSG_TRUNC) == 10, "dgram: recv(MSG_TRUNC) gives the real length");
	CHECK_ERR(recv(srv, buf, 4, MSG_DONTWAIT), EAGAIN, "dgram: the rest was discarded");

	/* Limits: EMSGSIZE over the sender's SO_SNDBUF, ENOBUFS when the receiver's queue is full. */
	int v = 4096;
	setsockopt(cl, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
	setsockopt(srv, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
	char big[5000];
	memset(big, 'q', sizeof big);
	CHECK_ERR(sendto(cl, big, 5000, 0, (struct sockaddr *)&a, alen), EMSGSIZE,
		"dgram: bigger than SO_SNDBUF is EMSGSIZE");
	int k, ok = 1;
	for (k = 0; k < 4; k++) ok &= sendto(cl, big, 1000, 0, (struct sockaddr *)&a, alen) == 1000;
	CHECK(ok, "dgram: queue fills to SO_RCVBUF");
	CHECK_ERR(sendto(cl, big, 1000, 0, (struct sockaddr *)&a, alen), ENOBUFS,
		"dgram: a full receiver is ENOBUFS");
	while (recv(srv, big, sizeof big, MSG_DONTWAIT) > 0) {}

	/* A blocked receiver wakes for a datagram sent by a child. */
	pid_t pid = fork();
	if (pid == 0) {
		usleep(200000);
		_exit(sendto(socket(AF_UNIX, SOCK_DGRAM, 0), "late", 4, 0, (struct sockaddr *)&a, alen) == 4 ? 0 : 1);
	}
	CHECK(recv(srv, buf, sizeof buf, 0) == 4, "dgram: blocking recv wakes for a datagram");
	child_ok(pid);

	/* connect(2) sets a default destination. */
	int c2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK_ERR(send(c2, "x", 1, 0), ENOTCONN, "dgram: send without a destination is ENOTCONN");
	CHECK(connect(c2, (struct sockaddr *)&a, alen) == 0 && send(c2, "hi", 2, 0) == 2 &&
		recv(srv, buf, sizeof buf, 0) == 2, "dgram: connect, then send");
	struct sockaddr_un st;
	socklen_t stl = un_path(&st, "/ut/st2");
	int stream = bound(SOCK_STREAM, "/ut/st2");
	CHECK_ERR(sendto(c2, "x", 1, 0, (struct sockaddr *)&st, stl), EPROTOTYPE,
		"dgram: sendto a stream socket is EPROTOTYPE");
	close(stream);
	close(srv);
	CHECK_ERR(send(c2, "x", 1, 0), ENOTCONN, "dgram: destination closed is ENOTCONN");
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	CHECK(connect(c2, &unspec, sizeof unspec) == 0, "dgram: connect AF_UNSPEC disconnects");
	close(c2);
	close(cl);
}

static void local_seqpacket(void)
{
	char buf[64];
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0, "seqpacket: socketpair");
	send(sv[0], "abc", 3, 0);
	send(sv[0], "de", 2, 0);
	struct iovec iov = { buf, sizeof buf };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1 };
	CHECK(recvmsg(sv[1], &m, 0) == 3 && (m.msg_flags & MSG_EOR) && !(m.msg_flags & MSG_TRUNC),
		"seqpacket: one record, MSG_EOR");
	iov.iov_len = 1;
	m.msg_flags = 0;
	CHECK(recvmsg(sv[1], &m, 0) == 1 && (m.msg_flags & MSG_TRUNC), "seqpacket: truncated, MSG_TRUNC");
	CHECK_ERR(recv(sv[1], buf, sizeof buf, MSG_DONTWAIT), EAGAIN,
		"seqpacket: the rest of the record was discarded");
	CHECK(send(sv[0], "eor", 3, MSG_EOR) == 3, "seqpacket: MSG_EOR accepted on send");
	recv(sv[1], buf, sizeof buf, 0);
	close(sv[0]);
	CHECK(recv(sv[1], buf, sizeof buf, 0) == 0, "seqpacket: EOF once the peer closes");
	close(sv[1]);

	int l = bound(SOCK_SEQPACKET, "/ut/sp");
	listen(l, 4);
	int c = connected(SOCK_SEQPACKET, "/ut/sp");
	int s = accept(l, 0, 0);
	CHECK(c >= 0 && s >= 0 && send(c, "rec", 3, 0) == 3 && recv(s, buf, sizeof buf, 0) == 3,
		"seqpacket: listen, connect, accept, one record");
	close(c);
	close(s);
	close(l);
}

static void local_socketpair(void)
{
	int sv[2];
	char buf[16];
	struct stat st;
	CHECK_ERR(socketpair(AF_INET, SOCK_STREAM, 0, sv), EOPNOTSUPP, "socketpair: AF_INET is EOPNOTSUPP");
	CHECK_ERR(socketpair(AF_UNIX, SOCK_RAW, 0, sv), EPROTONOSUPPORT,
		"socketpair: SOCK_RAW is EPROTONOSUPPORT");
	CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0 && send(sv[0], "d", 1, 0) == 1 &&
		recv(sv[1], buf, sizeof buf, 0) == 1 && send(sv[1], "e", 1, 0) == 1 &&
		recv(sv[0], buf, sizeof buf, 0) == 1, "socketpair: SOCK_DGRAM, both ways");
	close(sv[0]);
	CHECK_ERR(send(sv[1], "x", 1, 0), ENOTCONN, "socketpair: SOCK_DGRAM, peer closed is ENOTCONN");
	close(sv[1]);

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sv) == 0,
		"socketpair: SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK");
	CHECK((fcntl(sv[0], F_GETFD) & FD_CLOEXEC) && (fcntl(sv[1], F_GETFL) & O_NONBLOCK),
		"socketpair: the flags apply to both");
	CHECK(fstat(sv[0], &st) == 0 && S_ISSOCK(st.st_mode), "socketpair: fstat is S_IFSOCK");
	CHECK(getint(sv[0], SOL_SOCKET, SO_TYPE) == SOCK_STREAM &&
		getint(sv[0], SOL_SOCKET, SO_DOMAIN) == AF_UNIX, "socketpair: SO_TYPE, SO_DOMAIN");
	struct sockaddr_un got;
	socklen_t glen = sizeof got;
	CHECK(getpeername(sv[0], (struct sockaddr *)&got, &glen) == 0 && glen == sizeof(sa_family_t),
		"socketpair: getpeername, unnamed");
	CHECK_ERR(read(sv[0], buf, 1), EAGAIN, "socketpair: nonblocking read, empty");
	CHECK(write(sv[1], "pair", 4) == 4 && read(sv[0], buf, sizeof buf) == 4, "socketpair: data flows");
	CHECK(shutdown(sv[0], SHUT_WR) == 0 && read(sv[1], buf, sizeof buf) == 0,
		"socketpair: shutdown SHUT_WR gives the peer EOF");
	close(sv[0]);
	close(sv[1]);
}

/* ---- Descriptor and credential passing (UNIX.md §§8-9) ---- */

/* Sends `n` descriptors and `len` bytes of `data` in one message. */
static int send_fds(int s, const int *fds, int n, const void *data, size_t len)
{
	char cbuf[CMSG_SPACE(sizeof(int) * 64)];
	struct iovec iov = { (void *)data, len };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1 };
	if (n > 0) {
		memset(cbuf, 0, sizeof cbuf);
		m.msg_control = cbuf;
		m.msg_controllen = CMSG_SPACE(sizeof(int) * n);
		struct cmsghdr *c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int) * n);
		memcpy(CMSG_DATA(c), fds, sizeof(int) * n);
	}
	return sendmsg(s, &m, 0);
}

/* Receives into `buf`, collecting up to `max` descriptors (the control buffer has room for
 * `room` of them). Returns the byte count; *nfds and *mflags report the rest. */
static long recv_fds(int s, void *buf, size_t len, int *fds, int max, int room, int flags, int *nfds, int *mflags)
{
	char cbuf[CMSG_SPACE(sizeof(int) * 64)];
	struct iovec iov = { buf, len };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf,
		.msg_controllen = room ? CMSG_SPACE(sizeof(int) * room) : 0 };
	if (!room) m.msg_control = 0;
	long r = recvmsg(s, &m, flags);
	*nfds = 0;
	*mflags = m.msg_flags;
	if (r < 0) return r;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
			int k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (int i = 0; i < k && *nfds < max; i++)
				memcpy(&fds[(*nfds)++], CMSG_DATA(c) + i * sizeof(int), sizeof(int));
		}
	}
	return r;
}

/* True if the pipe whose read end is `rd` has lost every writer (read gives EOF). */
static int writers_gone(int rd)
{
	int fl = fcntl(rd, F_GETFL);
	fcntl(rd, F_SETFL, fl | O_NONBLOCK);
	char c;
	long r = read(rd, &c, 1);
	fcntl(rd, F_SETFL, fl);
	return r == 0;
}

static void rights(void)
{
	int sv[2], got[8], n, fl;
	char buf[16];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	int f = open("/ut/passed", O_CREAT | O_RDWR | O_TRUNC, 0644);
	write(f, "abc", 3);
	lseek(f, 0, SEEK_SET);
	CHECK(send_fds(sv[0], &f, 1, "x", 1) == 1, "SCM_RIGHTS: send a descriptor");
	close(f); /* the message holds the description */
	CHECK(recv_fds(sv[1], buf, sizeof buf, got, 8, 8, 0, &n, &fl) == 1 && n == 1, "SCM_RIGHTS: receive it");
	CHECK(n == 1 && read(got[0], buf, 3) == 3 && memcmp(buf, "abc", 3) == 0,
		"SCM_RIGHTS: it's the same open file, offset and all");
	CHECK(n == 1 && !(fcntl(got[0], F_GETFD) & FD_CLOEXEC), "SCM_RIGHTS: no FD_CLOEXEC by default");
	send_fds(sv[0], &got[0], 1, "y", 1);
	recv_fds(sv[1], buf, sizeof buf, got + 1, 7, 8, MSG_CMSG_CLOEXEC, &n, &fl);
	CHECK(n == 1 && (fcntl(got[1], F_GETFD) & FD_CLOEXEC), "MSG_CMSG_CLOEXEC sets FD_CLOEXEC");
	close(got[0]);
	close(got[1]);

	/* Several in one message; a short control buffer truncates. */
	int three[3] = { 0, 1, 2 };
	send_fds(sv[0], three, 3, "z", 1);
	recv_fds(sv[1], buf, sizeof buf, got, 8, 8, 0, &n, &fl);
	CHECK(n == 3 && !(fl & MSG_CTRUNC), "SCM_RIGHTS: three at once");
	for (int i = 0; i < n; i++) close(got[i]);
	send_fds(sv[0], three, 3, "z", 1);
	/* CMSG_SPACE(sizeof(int)) is 24 bytes: a header and room for two descriptors. */
	recv_fds(sv[1], buf, sizeof buf, got, 8, 1, 0, &n, &fl);
	CHECK(n == 2 && (fl & MSG_CTRUNC), "SCM_RIGHTS: a short buffer gets what fits, MSG_CTRUNC");
	for (int i = 0; i < n; i++) close(got[i]);

	int bad = 999;
	errno = 0;
	CHECK(send_fds(sv[0], &bad, 1, "q", 1) < 0 && errno == EBADF, "SCM_RIGHTS: a closed descriptor is EBADF");
	CHECK_ERR(recv(sv[1], buf, 1, MSG_DONTWAIT), EAGAIN, "SCM_RIGHTS: ... and nothing was sent");

	/* A stream doesn't run bytes sent with descriptors into earlier ones (§6.4). */
	write(sv[0], "ab", 2);
	send_fds(sv[0], &three[0], 1, "cd", 2);
	CHECK(recv_fds(sv[1], buf, sizeof buf, got, 8, 8, 0, &n, &fl) == 2 && n == 0 && memcmp(buf, "ab", 2) == 0,
		"stream: a read stops before bytes that came with control data");
	CHECK(recv_fds(sv[1], buf, sizeof buf, got, 8, 8, 0, &n, &fl) == 2 && n == 1 && memcmp(buf, "cd", 2) == 0,
		"stream: the next read gets them and their descriptor");
	close(got[0]);
	write(sv[0], "ef", 2);
	send_fds(sv[0], &three[0], 1, "gh", 2);
	CHECK(recv(sv[1], buf, 4, MSG_WAITALL) == 2, "stream: MSG_WAITALL stops there too");
	recv_fds(sv[1], buf, sizeof buf, got, 8, 8, 0, &n, &fl);
	close(got[0]);

	/* read(2) has nowhere to put descriptors: they're closed. */
	int p[2];
	pipe(p);
	send_fds(sv[0], &p[1], 1, "r", 1);
	close(p[1]);
	CHECK(read(sv[1], buf, 1) == 1 && writers_gone(p[0]), "read(2) closes descriptors it can't return");
	close(p[0]);

	/* A message discarded unread releases what it held (§8.3). */
	pipe(p);
	send_fds(sv[0], &p[1], 1, "d", 1);
	close(p[1]);
	CHECK(!writers_gone(p[0]), "in flight, the pipe's write end is still open");
	close(sv[1]);
	CHECK(writers_gone(p[0]), "closing the receiver releases descriptors in its queue");
	close(p[0]);
	close(sv[0]);

	/* Datagrams, by name. */
	struct sockaddr_un a;
	socklen_t al = un_path(&a, "/ut/rdg");
	int d = bound(SOCK_DGRAM, "/ut/rdg");
	int c = socket(AF_UNIX, SOCK_DGRAM, 0);
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { "dg", 2 };
	struct msghdr m = { .msg_name = &a, .msg_namelen = al, .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = cbuf, .msg_controllen = sizeof cbuf };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	int one = 1;
	memcpy(CMSG_DATA(cm), &one, sizeof one);
	CHECK(sendmsg(c, &m, 0) == 2, "SCM_RIGHTS over a datagram socket");
	CHECK(recv_fds(d, buf, sizeof buf, got, 8, 8, 0, &n, &fl) == 2 && n == 1, "... received with the datagram");
	close(got[0]);
	close(c);
	close(d);
	int in = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK_ERR(send_fds(in, &one, 1, "x", 1), EOPNOTSUPP, "SCM_RIGHTS on an Internet socket is EOPNOTSUPP");
	close(in);
}

static void collection(void)
{
	/* A socket sent over itself: once its own descriptor is closed only its own message holds
	 * it, and nobody can ever read that message (its peer can only send to it). The pipe riding
	 * along shows whether the message was released (§8.4). */
	int sv[2], p[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	pipe(p);
	int both[2] = { sv[1], p[1] };
	send_fds(sv[0], both, 2, "g", 1); /* into sv[1]'s own queue */
	close(p[1]);
	close(sv[0]);
	CHECK(!writers_gone(p[0]), "gc: nothing is collected while it could still be read");
	close(sv[1]);
	CHECK(writers_gone(p[0]), "gc: a socket sent over itself is collected once unreachable");
	close(p[0]);

	/* A cycle of two. */
	int x[2], y[2];
	socketpair(AF_UNIX, SOCK_DGRAM, 0, x);
	socketpair(AF_UNIX, SOCK_DGRAM, 0, y);
	pipe(p);
	int xs[2] = { y[1], p[1] };
	send_fds(x[0], xs, 2, "1", 1); /* y[1] rides in x[1]'s queue */
	send_fds(y[0], &x[1], 1, "2", 1); /* x[1] rides in y[1]'s queue */
	close(p[1]);
	close(x[0]);
	close(y[0]);
	close(x[1]);
	CHECK(!writers_gone(p[0]), "gc: a cycle stays while one of its sockets is open (y[1] can read x[1])");
	close(y[1]);
	CHECK(writers_gone(p[0]), "gc: an unreachable cycle is collected");
	close(p[0]);
}

static void limits(void)
{
	/* 1024 in flight per user, 4096 in all; root has only the second (§8.5). Zero-byte
	 * datagrams, so only the descriptor count limits. */
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(100);
		int s[2], k = 0;
		socketpair(AF_UNIX, SOCK_DGRAM, 0, s);
		while (k < 2000 && send_fds(s[0], &s[0], 1, "", 0) == 0) k++;
		_exit(k == 1024 && errno == ETOOMANYREFS ? 0 : 1);
	}
	int st;
	CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		"another user may have 1024 descriptors in flight, then ETOOMANYREFS");
	int s[2], k = 0;
	socketpair(AF_UNIX, SOCK_DGRAM, 0, s);
	while (k < 5000 && send_fds(s[0], &s[0], 1, "", 0) == 0) k++;
	printf("     root sent %d before %s\n", k, strerror(errno));
	CHECK(k == 4096 && errno == ETOOMANYREFS, "root is held to the system-wide 4096");
	close(s[0]);
	close(s[1]);
	CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, s) == 0 && send_fds(s[0], &s[0], 1, "", 0) == 0,
		"closing releases them: sending works again");
	close(s[0]);
	close(s[1]);
}

/* The control message of `type` in `m`, or 0. */
static struct cmsghdr *find_cmsg(struct msghdr *m, int type)
{
	for (struct cmsghdr *c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c))
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == type) return c;
	return 0;
}

static int count_cmsg(struct msghdr *m, int type)
{
	int n = 0;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c))
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == type) n++;
	return n;
}

/* Receives one message from `s` into `m` (control buffer `cbuf`). */
static long recv_ctl(int s, struct msghdr *m, char *cbuf, size_t clen, char *buf, size_t len)
{
	static struct iovec iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	memset(m, 0, sizeof *m);
	m->msg_iov = &iov;
	m->msg_iovlen = 1;
	m->msg_control = cbuf;
	m->msg_controllen = clen;
	return recvmsg(s, m, 0);
}

/* Sends one byte with one control message of `type` carrying `len` bytes of `data`. */
static long send_ctl(int s, int type, const void *data, size_t len)
{
	char sc[CMSG_SPACE(128)];
	memset(sc, 0, sizeof sc);
	struct iovec iov = { "c", 1 };
	struct msghdr sm = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = sc, .msg_controllen = CMSG_SPACE(len) };
	struct cmsghdr *h = CMSG_FIRSTHDR(&sm);
	h->cmsg_level = SOL_SOCKET;
	h->cmsg_type = type;
	h->cmsg_len = CMSG_LEN(len);
	memcpy(CMSG_DATA(h), data, len);
	return sendmsg(s, &sm, 0);
}

static void credentials(void)
{
	int sv[2], st;
	uid_t eu;
	gid_t eg;
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	CHECK(getpeereid(sv[0], &eu, &eg) == 0 && eu == getuid() && eg == getgid(), "getpeereid on a socket pair");
	struct xucred xu;
	socklen_t len = sizeof xu;
	CHECK(getsockopt(sv[0], SOL_LOCAL, LOCAL_PEERCRED, &xu, &len) == 0 && len == sizeof xu &&
		xu.cr_version == XUCRED_VERSION && xu.cr_uid == getuid() && xu.cr_ngroups == 1 &&
		xu.cr_groups[0] == getgid() && xu.cr_pid == getpid(), "LOCAL_PEERCRED: struct xucred");
	struct ucred uc;
	len = sizeof uc;
	CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0 && len == sizeof uc &&
		uc.pid == getpid() && uc.uid == getuid() && uc.gid == getgid(), "SO_PEERCRED: struct ucred");
	int lone = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK_ERR(getpeereid(lone, &eu, &eg), ENOTCONN, "getpeereid unconnected is ENOTCONN");
	close(lone);
	int inet = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_ERR(getpeereid(inet, &eu, &eg), EINVAL, "getpeereid on an Internet socket is EINVAL");
	len = sizeof uc;
	CHECK_ERR(getsockopt(inet, SOL_SOCKET, SO_PEERCRED, &uc, &len), EINVAL, "SO_PEERCRED on one is EINVAL");
	close(inet);

	/* Connection credentials: as of listen(2) and connect(2), across users. */
	int l = bound(SOCK_STREAM, "/ut/cred");
	chmod("/ut/cred", 0777);
	listen(l, 4);
	int rp[2];
	pipe(rp);
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(100);
		int c = connected(SOCK_STREAM, "/ut/cred");
		uid_t u;
		gid_t g;
		int ok = c >= 0 && getpeereid(c, &u, &g) == 0 && u == 0; /* the listener is root's */
		write(rp[1], &ok, sizeof ok);
		pause();
		_exit(0);
	}
	int ok = 0;
	read(rp[0], &ok, sizeof ok);
	int s = accept(l, 0, 0);
	CHECK(ok, "the connecting side sees the listener's credentials");
	CHECK(getpeereid(s, &eu, &eg) == 0 && eu == 1000 && eg == 0, "the accepting side sees the connector's");
	len = sizeof uc;
	CHECK(getsockopt(s, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0 && uc.pid == pid, "... and its pid");
	kill(pid, SIGKILL);
	waitpid(pid, 0, 0);
	close(s);
	close(l);
	close(rp[0]);
	close(rp[1]);

	char buf[16], cbuf[512];
	struct msghdr m;
	struct cmsghdr *c;

	/* SCM_CREDS from the sender: the kernel fills it in, whatever was written (§9.3). */
	struct cmsgcred forged_cc;
	memset(&forged_cc, 0xee, sizeof forged_cc);
	CHECK(send_ctl(sv[0], SCM_CREDS, &forged_cc, sizeof forged_cc) == 1, "SCM_CREDS: send with a forged struct cmsgcred");
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	c = find_cmsg(&m, SCM_CREDS);
	struct cmsgcred cc;
	if (c) memcpy(&cc, CMSG_DATA(c), sizeof cc);
	CHECK(c && c->cmsg_len == CMSG_LEN(sizeof cc) && cc.cmcred_pid == getpid() && cc.cmcred_uid == getuid() &&
		cc.cmcred_euid == geteuid() && cc.cmcred_gid == getgid() && cc.cmcred_ngroups == 1,
		"SCM_CREDS: the receiver gets the kernel's, not the forgery");

	/* LOCAL_CREDS: a stream gives struct sockcred with the first receive only. */
	int on = 1;
	CHECK(setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS, &on, sizeof on) == 0, "LOCAL_CREDS: set");
	CHECK_ERR(setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS_PERSISTENT, &on, sizeof on), EINVAL,
		"LOCAL_CREDS and LOCAL_CREDS_PERSISTENT are exclusive");
	write(sv[0], "1", 1);
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	c = find_cmsg(&m, SCM_CREDS);
	struct sockcred sk;
	if (c) memcpy(&sk, CMSG_DATA(c), sizeof sk);
	CHECK(c && c->cmsg_len == CMSG_LEN(SOCKCREDSIZE(1)) && sk.sc_uid == getuid() && sk.sc_ngroups == 1,
		"LOCAL_CREDS: struct sockcred with the first receive");
	write(sv[0], "2", 1);
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	CHECK(!find_cmsg(&m, SCM_CREDS), "LOCAL_CREDS on a stream: not with later ones");
	on = 0;
	setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS, &on, sizeof on);

	/* LOCAL_CREDS_PERSISTENT: struct sockcred2 with every message; a sender's SCM_CREDS is
	 * dropped, so only the kernel's credentials arrive (§9.5). */
	on = 1;
	setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS_PERSISTENT, &on, sizeof on);
	for (int i = 0; i < 2; i++) {
		send_ctl(sv[0], SCM_CREDS, &forged_cc, sizeof forged_cc);
		recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
		c = find_cmsg(&m, SCM_CREDS2);
		struct sockcred2 s2;
		if (c) memcpy(&s2, CMSG_DATA(c), sizeof s2);
		CHECK(c && s2.sc_version == 0 && s2.sc_pid == getpid() && s2.sc_uid == getuid() && !find_cmsg(&m, SCM_CREDS),
			i ? "LOCAL_CREDS_PERSISTENT: ... and the next" : "LOCAL_CREDS_PERSISTENT: struct sockcred2, the sender's SCM_CREDS dropped");
	}
	on = 0;
	setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS_PERSISTENT, &on, sizeof on);
	close(sv[0]);
	close(sv[1]);

	/* LOCAL_CREDS on datagrams: with every one. */
	socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	on = 1;
	setsockopt(sv[1], SOL_LOCAL, LOCAL_CREDS, &on, sizeof on);
	send(sv[0], "a", 1, 0);
	send(sv[0], "b", 1, 0);
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	int first = count_cmsg(&m, SCM_CREDS);
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	CHECK(first == 1 && count_cmsg(&m, SCM_CREDS) == 1, "LOCAL_CREDS on datagrams: every message");
	close(sv[0]);
	close(sv[1]);

	/* SO_PASSCRED: SCM_CREDENTIALS with every message; a sender may supply its own, but only
	 * root someone else's (§9.4). */
	socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	on = 1;
	CHECK(setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0, "SO_PASSCRED: set");
	send(sv[0], "a", 1, 0);
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	c = find_cmsg(&m, SCM_CREDENTIALS);
	if (c) memcpy(&uc, CMSG_DATA(c), sizeof uc);
	CHECK(c && uc.pid == getpid() && uc.uid == getuid(), "SO_PASSCRED: SCM_CREDENTIALS with a message");
	struct ucred forged = { 4242, 77, 77 };
	CHECK(send_ctl(sv[0], SCM_CREDENTIALS, &forged, sizeof forged) == 1, "SCM_CREDENTIALS: root may send any");
	recv_ctl(sv[1], &m, cbuf, sizeof cbuf, buf, sizeof buf);
	c = find_cmsg(&m, SCM_CREDENTIALS);
	if (c) memcpy(&uc, CMSG_DATA(c), sizeof uc);
	CHECK(c && uc.pid == 4242 && uc.uid == 77, "... and the receiver gets them");
	pid = fork();
	if (pid == 0) {
		if (setuid(1000) < 0) _exit(100);
		_exit(send_ctl(sv[0], SCM_CREDENTIALS, &forged, sizeof forged) < 0 && errno == EPERM ? 0 : 1);
	}
	CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
		"SCM_CREDENTIALS: another user's forgery is EPERM");
	close(sv[0]);
	close(sv[1]);
}

int main(void)
{
	setvbuf(stdout, 0, _IONBF, 0);
	creation();
	options();
	udp();
	tcp();
	retired();
	local_naming();
	local_stream();
	local_dgram();
	local_seqpacket();
	local_socketpair();
	rights();
	collection();
	limits();
	credentials();
	printf("socket-smoke: %d failure(s)\n", failures);
	return failures;
}
