/* A dynamically linked PIE main binary: ET_DYN *with* a PT_INTERP, the shape every ordinary
 * dynamically linked program has (OpenSSL's `openssl`, for one). Run by
 * regress/dynlink-syscall-smoke, next to the fixed-address /dynlink-smoke.elf.
 *
 * Checks that the kernel gave this image a real load bias in the PIE ASLR window
 * (sys/process/aslr.rs) rather than loading it at its link address 0, that libc.so came in at the
 * interpreter base (INTERP_LOAD_BASE, sys/process/lifecycle.rs), and that stdio through the
 * shared libc works. Exit status 0 on success. */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define PIE_ASLR_BASE 0x300000000000ull
#define PIE_ASLR_CEILING 0x400000000000ull
#define INTERP_LOAD_BASE 0x10000000ull

int main(void) {
    uintptr_t self = (uintptr_t)&main;
    uintptr_t libc = (uintptr_t)&write;
    printf("dynlink-pie-smoke: main at %#lx, write at %#lx\n", (unsigned long)self,
           (unsigned long)libc);
    if (self < PIE_ASLR_BASE || self >= PIE_ASLR_CEILING) {
        printf("dynlink-pie-smoke: main is outside the PIE ASLR window\n");
        return 1;
    }
    if (libc < INTERP_LOAD_BASE || libc >= INTERP_LOAD_BASE + 0x1000000) {
        printf("dynlink-pie-smoke: write is not in libc.so at the interpreter base\n");
        return 1;
    }
    return 0;
}
