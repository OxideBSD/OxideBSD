/* A minimal test of a real, unmodified-above-the-syscall-layer musl static binary running under
 * OxideBSD's own native ABI (see the OxideBSD tree's sys/syscall.rs / external/mit/musl's
 * "oxidebsd" branch). printf() exercises musl's TLS setup (SYS_SET_FS_BASE), its allocator
 * (SYS_MMAP/SYS_BRK), and stdio's own isatty-style probing (SYS_ioctl, expected to fail cleanly
 * until implemented) -- not just a bare write()+exit() the way regress/ring3-smoke/ already
 * proves the syscall mechanism itself works. Returning 0 from main() (rather than calling _exit()
 * directly) exercises musl's real teardown path through exit()/_Exit(), not a shortcut around it. */
#include <stdio.h>

int main(void) {
	printf("musl-smoke: hello from a real musl binary on OxideBSD\n");
	return 0;
}
