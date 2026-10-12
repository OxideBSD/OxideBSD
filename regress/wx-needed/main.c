/*
 * W^X's escape hatch (OxideBSD-doc/THREAT_MODEL.md section 3.3), run by
 * regress/wx-syscall-smoke: maps a page writable and executable at once, puts
 * "mov eax, 42; ret" in it and calls it. Built twice, as wx-needed (linked with
 * -z wxneeded: PT_OXIDEBSD_WXNEEDED) and wx-plain (not). Exit status 0: the
 * mapping was allowed and ran; 1: refused with ENOTSUP; 2: refused otherwise;
 * 3: it ran but returned the wrong value.
 */
#include <errno.h>
#include <sys/mman.h>

int main(void)
{
	static const unsigned char code[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
	unsigned char *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_PRIVATE | MAP_ANON, -1, 0);

	if (p == MAP_FAILED)
		return errno == ENOTSUP ? 1 : 2;
	for (unsigned i = 0; i < sizeof(code); i++)
		p[i] = code[i];
	return ((int (*)(void))p)() == 42 ? 0 : 3;
}
