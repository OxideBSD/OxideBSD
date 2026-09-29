/* The socket layer through musl's own API (OxideBSD-doc UNIX.md §§3-4, 11), seeded at
 * /socket-smoke.elf and run by regress/socket-syscall-smoke via
 * tests/socket_syscall_smoke.rs. There is no loopback interface, so data between two sockets is
 * checked once local sockets exist; this covers what needs no peer, plus a connection refused
 * by QEMU's gateway.
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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
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

int main(void)
{
	setvbuf(stdout, 0, _IONBF, 0);
	creation();
	options();
	udp();
	tcp();
	retired();
	printf("socket-smoke: %d failure(s)\n", failures);
	return failures;
}
