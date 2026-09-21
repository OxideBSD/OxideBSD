/* Load base 0xfa00000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (socketpair 0xf000000, ping 0xf100000, udp 0xf200000, poll 0xf300000, tcp
 * 0xf400000, proc 0xf500000, itimer 0xf600000, uid 0xf700000, oxfs-persistence 0xf800000, mount
 * 0xf900000 -- see regress/socketpair-syscall-smoke/linker.ld's own comment for the full "why
 * this address" story). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1
 * LOAD` before trusting this if the kernel image has grown meaningfully since this was picked. */
ENTRY(_start)

SECTIONS
{
    . = 0xfa00000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note*)
    }
}
