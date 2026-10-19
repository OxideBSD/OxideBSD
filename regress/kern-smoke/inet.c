/*
 * kern-smoke inet: the IP-level socket options (CLEANUP.md §6): IP_TTL, IP_TOS and DF
 * (IP_MTU_DISCOVER) go into the headers a socket sends, and a raw socket's bind address is its
 * source and the destination it receives for. Root: raw sockets are root's.
 */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static uint16_t inet_cksum(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)p[i] << 8 | p[i + 1];
	if (len & 1)
		sum += (uint32_t)p[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum);
}

/* Sends an echo request to 127.0.0.1 on `s` and returns the header of the first copy of it the
 * socket receives back (raw sockets see every ICMP packet, their own included), or 0. */
static int own_request(int s, uint16_t id, unsigned char *hdr)
{
	unsigned char pkt[16] = { ICMP_ECHO, 0 };
	pkt[4] = id >> 8;
	pkt[5] = id & 0xff;
	uint16_t c = inet_cksum(pkt, sizeof pkt);
	memcpy(pkt + 2, &c, 2);
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	if (sendto(s, pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) != sizeof pkt)
		return 0;
	struct timeval tv = { 2, 0 };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	unsigned char buf[256];
	for (int i = 0; i < 8; i++) {
		ssize_t n = recv(s, buf, sizeof buf, 0);
		if (n < 28)
			return 0;
		if (buf[20] == ICMP_ECHO && buf[24] == pkt[4] && buf[25] == pkt[5]) {
			memcpy(hdr, buf, 20);
			return 1;
		}
	}
	return 0;
}

static void inet_main(void)
{
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	int ttl = 300;
	check(setsockopt(u, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) == -1 && errno == EINVAL, "IP_TTL past 255 is EINVAL");
	ttl = 9;
	socklen_t len = sizeof ttl;
	check(setsockopt(u, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) == 0 && (ttl = 0, getsockopt(u, IPPROTO_IP, IP_TTL, &ttl, &len)) == 0 && ttl == 9,
	      "IP_TTL is kept");
	close(u);

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	check(s >= 0, "a raw ICMP socket");
	unsigned char hdr[20];
	check(own_request(s, 0x4b01, hdr) && hdr[8] == 64 && hdr[1] == 0 && !(hdr[6] & 0x40), "the default header: TTL 64, TOS 0, no DF");
	ttl = 33;
	int tos = 0x10, pmtu = IP_PMTUDISC_DO;
	setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl);
	setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof tos);
	setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof pmtu);
	check(own_request(s, 0x4b02, hdr) && hdr[8] == 33, "IP_TTL goes into the header");
	check(hdr[1] == 0x10, "IP_TOS too");
	check(hdr[6] & 0x40, "IP_PMTUDISC_DO sets DF");

	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("192.0.2.1") };
	check(bind(s, (struct sockaddr *)&a, sizeof a) == -1 && errno == EADDRNOTAVAIL, "a raw socket binds only a local address");
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	struct sockaddr_in got;
	len = sizeof got;
	check(bind(s, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(s, (struct sockaddr *)&got, &len) == 0 &&
	          got.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
	      "and keeps it");
	close(s);
}
