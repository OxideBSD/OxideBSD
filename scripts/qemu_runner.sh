#!/bin/sh
# Cargo's own `runner` for the `x86_64-oxidebsd` target (see `.cargo/config.toml`) -- replaces the
# retired `bootimage runner` now that OxideBSD boots via the Limine protocol instead of the
# `bootloader` crate (see CLAUDE.md's boot section). Cargo invokes this with the just-built
# kernel/test ELF's path as $1 and treats this script's own exit code as the `cargo run`/
# `cargo test` result.
#
# What it does, end to end: stages a fresh hybrid BIOS+UEFI ISO from `target/limine-stage/`
# (populated by build.rs's `build_limine_deploy_tool`) plus the just-built ELF, then boots it under
# QEMU with the same accel/serial/RAM/NIC/real-ATA-disk flags this project's old
# `[package.metadata.bootimage]` `run-args`/`test-args` used, and (for a test binary) translates
# the real `isa-debug-exit` exit code into this script's own pass/fail exit status.
#
# The QEMU-driving parts common to any boot path (firmware/OVMF selection, the fixed IDE topology,
# the isa-debug-exit wedge-guard/exit-code translation) live in `scripts/qemu_common.sh`, shared
# with `scripts/run_multiboot2_smoke.sh` -- see that file's own doc comment. This script's own
# behavior is unchanged by that extraction; only the ISO staging above (Limine-specific) and the
# interactive `cargo run` vs `cargo test` split below stay here.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

KERNEL_ELF="$1"
STAGE_DIR="target/limine-stage"
ISO_ROOT="target/iso_root"
ISO_PATH="target/oxidebsd.iso"

if [ ! -d "$STAGE_DIR" ]; then
    echo "qemu_runner.sh: $STAGE_DIR is missing -- did build.rs's build_limine_deploy_tool run?" >&2
    exit 1
fi

# Test-vs-run discrimination: a `cargo test` binary is named <name>-<16 hex digit hash> (under
# deps/ before nightly-2026-09, build/oxidebsd/<hash>/out/ since); the main kernel binary is plain
# target/x86_64-oxidebsd/debug/oxidebsd. Matching only `*/deps/*` stopped working with the newer
# layout and silently ran every test as an interactive `cargo run`: a QEMU window per test, the
# persistent dev disk, no timeout, and no exit-code translation, so failing tests reported success.
case "${KERNEL_ELF##*/}" in
    *-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
        IS_TEST=1 ;;
    *) IS_TEST=0 ;;
esac

# Per-test QEMU settings, by the test's name (the binary's, less its hash).
TEST_NAME=""
if [ "$IS_TEST" = 1 ]; then
    TEST_NAME=$(basename "$KERNEL_ELF" | sed 's/-[0-9a-f]\{16\}$//')
fi
# A test with a tests/<name>.serial file gets its bytes typed on the serial console, once the
# guest prints "serial input: ready" (any earlier and the firmware or the boot loader could read
# them): headless input without the QEMU monitor's sendkey.
if [ -n "$TEST_NAME" ] && [ -f "$REPO_ROOT/tests/$TEST_NAME.serial" ]; then
    QEMU_SERIAL_INPUT="$REPO_ROOT/tests/$TEST_NAME.serial"
    QEMU_SERIAL_INPUT_AFTER="serial input: ready"
fi
case "$TEST_NAME" in
    ram_floor_boot)
        # The real system must boot to a login prompt in 64 MB, under UEFI as under BIOS -- never
        # more, forever (CLAUDE.md) -- and nothing on the way may run out of memory.
        OXIDEBSD_QEMU_MEM="${OXIDEBSD_QEMU_MEM:-64}"
        export OXIDEBSD_QEMU_MEM
        QEMU_PASS_PATTERN="login:"
        # A service rc couldn't start, or any user process faulting, is a failure too.
        QEMU_FAIL_PATTERN="panicked at|PANIC|[Oo]ut of memory|ENOMEM|rc: failed services|\[fault\]"
        ;;
    disk_boot|disk_boot_bios)
        # The bootable disk image alone, no ISO (RAM_FLOOR.md §4.4.4): built below by
        # scripts/mkbootimg.sh from what the ISO gets, and booted through to a login prompt.
        DISK_BOOT=1
        if [ "$TEST_NAME" = disk_boot_bios ]; then
            OXIDEBSD_FIRMWARE=bios
            export OXIDEBSD_FIRMWARE
        fi
        QEMU_PASS_PATTERN="login:"
        QEMU_FAIL_PATTERN="panicked at|PANIC|rc: failed services|\[fault\]"
        ;;
    reroot_boot)
        # The root switch (RAM_FLOOR.md §5.1): two roots (scripts/mkreroottestimg.sh, below); the
        # second's /etc/rc reports.
        REROOT_TEST=1
        QEMU_PASS_PATTERN="reroot-smoke: PASS"
        QEMU_FAIL_PATTERN="reroot-smoke: FAIL|panicked at|PANIC|\[fault\]"
        ;;
    msdosfs_syscall_smoke)
        # FAT12, FAT16 and FAT32 volumes beside the root (scripts/mkmsdostestimg.sh, below).
        MSDOSFS_TEST=1
        ;;
    cd9660_syscall_smoke)
        # ISO 9660 discs in IDE CD drives (scripts/mkcd9660testimg.sh, below): all four positions
        # are CD drives, so the system's disk is virtio-blk; and virtio-scsi disks and a CD.
        CD9660_TEST=1
        QEMU_DISK_DEFAULT=virtio
        ;;
    devfs_syscall_smoke)
        # The disk registry (INSTALLER.md §5.1): more disks than the system's, below.
        DISK_REGISTRY_TEST=1
        ;;
    install_boot|install_boot_bios)
        # The install medium alone (INSTALLER.md step 6), made from this kernel below: at 64 MB,
        # with a blank disk to install on, it boots into its mfsroot and the installer's first
        # screen, where tests/install_boot.serial chooses Shell and checks the mfsroot.
        INSTALL_BOOT=1
        if [ "$TEST_NAME" = install_boot_bios ]; then
            OXIDEBSD_FIRMWARE=bios
            export OXIDEBSD_FIRMWARE
        fi
        OXIDEBSD_QEMU_MEM="${OXIDEBSD_QEMU_MEM:-64}"
        export OXIDEBSD_QEMU_MEM
        QEMU_SERIAL_INPUT="$REPO_ROOT/tests/install_boot.serial"
        QEMU_SERIAL_INPUT_AFTER="Up and down choose, Enter goes."
        QEMU_PASS_PATTERN="mfsroot-shell: 42"
        QEMU_FAIL_PATTERN="panicked at|PANIC|[Oo]ut of memory|ENOMEM|\[fault\]|repeating too quickly"
        ;;
    oom_syscall_smoke)
        # Runs out of memory on purpose (COW.md §6): small, so filling it is quick.
        OXIDEBSD_QEMU_MEM="${OXIDEBSD_QEMU_MEM:-128}"
        export OXIDEBSD_QEMU_MEM
        ;;
esac

# --- Stage a fresh ISO root and build the hybrid image ---
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"
cp "$STAGE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
cp "$STAGE_DIR/BOOTIA32.EFI" "$ISO_ROOT/EFI/BOOT/"
# The kernel without its debug sections (FreeBSD ships `kernel` and keeps `kernel.debug`): the
# bootloader reads the whole file into memory first, and the ~29 MiB of DWARF alone kept Limine
# from loading it in 128 MB (RAM_FLOOR.md). gdb still uses the full ELF in target/.
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy"
"$OBJCOPY" --strip-debug "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"
# /etc/fstab compiled by build.rs (fsconf_mkdb), for the kernel to find the root by.
if [ -f target/boot/fsconf ]; then
    cp target/boot/fsconf "$ISO_ROOT/boot/fsconf"
fi

# `no-ata` on `kernel_cmdline:` (see `oxidebsd::boot::ata_disabled`'s own doc comment) skips the
# real ATA disk probe entirely -- a deliberate safety gate for a first real-hardware boot attempt
# (oxfs's mount-or-format logic will genuinely *format* whatever real disk it finds on the legacy
# IDE ports it probes). Off by default (this project's own QEMU dev/test workflow relies on the
# real ATA-backed disk), on whenever OXIDEBSD_REAL_HARDWARE is set -- run
# `OXIDEBSD_REAL_HARDWARE=1 cargo run` (this script only ever runs as cargo's own `runner`, so a
# plain `cargo build` alone never regenerates the ISO -- `cargo run` is required to reach this
# code at all, even though the resulting target/oxidebsd.iso, not this script's own subsequent
# QEMU launch, is the actual real-hardware artifact; safe to Ctrl-C the QEMU window once it's
# produced) to get an ISO with this gate genuinely on, rather than hand-editing this file before
# every real-hardware attempt.
#
# OXIDEBSD_KERNEL_CMDLINE appends further tokens, e.g. `-s` to boot init single-user
# (`oxidebsd::boot::parse_cmdline`), and so do the arguments after `--` on `cargo run`, which
# cargo hands this script after the ELF: `cargo run -- -s init_path=/bin/sh`. A test binary's
# arguments are libtest-style filters, not kernel tokens, so they're ignored.
KERNEL_CMDLINE=""
if [ -n "${OXIDEBSD_REAL_HARDWARE:-}" ]; then
    KERNEL_CMDLINE="no-ata"
fi
if [ -n "${OXIDEBSD_KERNEL_CMDLINE:-}" ]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE:+$KERNEL_CMDLINE }$OXIDEBSD_KERNEL_CMDLINE"
fi
shift
if [ "$IS_TEST" = 0 ] && [ $# -gt 0 ]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE:+$KERNEL_CMDLINE }$*"
fi
# The console goes to the screen only unless booted with -D (dual console: screen and COM1, as in
# FreeBSD). Tests and headless runs read the console through the serial log, so they get -D.
if [ "$IS_TEST" = 1 ] || [ "${OXIDEBSD_QEMU_DISPLAY:-}" = none ]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE:+$KERNEL_CMDLINE }-D"
fi

# Deliberately no `resolution:` override here: `console::vga`'s text grid sizes itself
# dynamically at boot from whatever real framebuffer resolution Limine/the firmware's own GOP/VBE
# mode reports (see `console::vga::real_grid_size`'s own doc comment) -- a bigger real display
# shows genuinely more rows/columns of native, unscaled text, not a forced-down resolution or
# stretched characters. (Two earlier, wrong attempts: a fixed 640x400 window centered inside a
# larger real resolution left visible letterboxing; forcing the resolution itself down to
# 640x400 via this exact config key looked fine but defeated the whole point.)
{
    echo "timeout: 0"
    echo "serial: yes"
    echo "/OxideBSD"
    echo "protocol: limine"
    echo "kernel_path: boot():/boot/kernel"
    if [ -f "$ISO_ROOT/boot/fsconf" ]; then
        echo "module_path: boot():/boot/fsconf"
    fi
    if [ -n "$KERNEL_CMDLINE" ]; then
        echo "kernel_cmdline: $KERNEL_CMDLINE"
    fi
} > "$ISO_ROOT/boot/limine/limine.conf"

xorriso -as mkisofs -R -r -J \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_ROOT" -o "$ISO_PATH" > /dev/null

"$STAGE_DIR/limine" bios-install "$ISO_PATH" > /dev/null

# The install medium (INSTALLER.md §3), from this kernel: at every `cargo run`, and for the
# install tests; not with OXIDEBSD_NO_INSTALLER, which also keeps build.rs from making its pieces.
INSTALL_ISO=""
if [ -z "${OXIDEBSD_NO_INSTALLER:-}" ] && { [ "$IS_TEST" = 0 ] || [ "${INSTALL_BOOT:-0}" = 1 ]; }; then
    if [ -f target/images/mfsroot.uz ]; then
        INSTALL_ISO="target/images/install.iso"
        if [ "$IS_TEST" = 1 ]; then
            INSTALL_ISO="target/images/install-test.iso"
        fi
        # shellcheck disable=SC2086 # the command line's words, one argument each
        scripts/mkinstalliso.sh "$KERNEL_ELF" "$INSTALL_ISO" $KERNEL_CMDLINE
    else
        echo "qemu_runner.sh: no target/images/mfsroot.uz (built with OXIDEBSD_NO_INSTALLER?): no install.iso" >&2
    fi
fi

if [ "${DISK_BOOT:-0}" = 1 ]; then
    QEMU_DISK_SOURCE="target/images/boot-test.img"
    rm -f "$QEMU_DISK_SOURCE"
    scripts/mkbootimg.sh "$ISO_ROOT/boot" "$QEMU_DISK_SOURCE"
    QEMU_NO_ISO=1
fi

if [ "${REROOT_TEST:-0}" = 1 ]; then
    QEMU_DISK_SOURCE="target/images/reroot-test.img"
    scripts/mkreroottestimg.sh "$QEMU_DISK_SOURCE"
fi
if [ "${MSDOSFS_TEST:-0}" = 1 ]; then
    QEMU_DISK_SOURCE="target/images/msdosfs-test.img"
    scripts/mkmsdostestimg.sh "$QEMU_DISK_SOURCE"
fi

if [ "${CD9660_TEST:-0}" = 1 ]; then
    # ide0: Rock Ridge + Joliet (with an MBR partition 2), ide1: plain ISO 9660, ide2: Joliet
    # only, ide3: an empty drive (regress/cd9660-syscall-smoke/run.sh).
    scripts/mkcd9660testimg.sh target/images/cd9660 > /dev/null 2>&1
    QEMU_EXTRA_ARGS="-drive if=none,id=cd0,media=cdrom,readonly=on,file=target/images/cd9660/rr.iso"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=cd0,bus=ide.0,unit=0"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=cd1,media=cdrom,readonly=on,file=target/images/cd9660/plain.iso"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=cd1,bus=ide.0,unit=1"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=cd2,media=cdrom,readonly=on,file=target/images/cd9660/joliet.iso"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=cd2,bus=ide.1,unit=0"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=cd3,media=cdrom"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=cd3,bus=ide.1,unit=1"
    # On the boot medium's virtio-scsi controller (target 0, scsi0): rr.iso again (scsi1), a disk
    # of 4096-byte sectors with a GPT in them, partition `k4` starting with a marker (scsi2), and
    # a blank disk of 512-byte ones (scsi3).
    printf 'PART4K-MARKER' > target/images/cd9660/k4.part
    truncate -s 1M target/images/cd9660/k4.part
    rm -f target/images/cd9660/4kn.img target/images/cd9660/512.img
    target/host-tools/x86_64-unknown-linux-gnu/release/mkimg -s gpt -S 4096 -o target/images/cd9660/4kn.img \
        -p "fat32lba/k4:=target/images/cd9660/k4.part"
    truncate -s 64M target/images/cd9660/512.img
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=scd1,media=cdrom,readonly=on,file=target/images/cd9660/rr.iso"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device scsi-cd,drive=scd1,bus=scsi0.0,scsi-id=1"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=sd4k,format=raw,file=target/images/cd9660/4kn.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device scsi-hd,drive=sd4k,bus=scsi0.0,scsi-id=2,logical_block_size=4096,physical_block_size=4096"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=sd512,format=raw,file=target/images/cd9660/512.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device scsi-hd,drive=sd512,bus=scsi0.0,scsi-id=3"
    # Two AHCI controllers (INSTALLER.md step 4): on the first, port 0 a 64 MiB disk with a GPT
    # partition `satatest`, port 1 empty, port 2 rr.iso, port 4 a 130 GiB sparse disk (LBA48); on
    # the second, port 5 an empty CD drive. Names by port: sata0.0 sata0.2 sata0.4 sata1.5.
    rm -f target/images/cd9660/sata.img target/images/cd9660/satabig.img
    truncate -s 32M target/images/cd9660/sata.part
    target/host-tools/x86_64-unknown-linux-gnu/release/mkimg -s gpt -o target/images/cd9660/sata.img \
        -p "fat32lba/satatest:=target/images/cd9660/sata.part"
    truncate -s 64M target/images/cd9660/sata.img
    truncate -s 130G target/images/cd9660/satabig.img
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ich9-ahci,id=ahci0 -device ich9-ahci,id=ahci1"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=sata0,format=raw,file=target/images/cd9660/sata.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-hd,drive=sata0,bus=ahci0.0"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=satacd,media=cdrom,readonly=on,file=target/images/cd9660/rr.iso"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=satacd,bus=ahci0.2"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=satabig,format=raw,file=target/images/cd9660/satabig.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-hd,drive=satabig,bus=ahci0.4"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=sataempty,media=cdrom"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-cd,drive=sataempty,bus=ahci1.5"
fi
if [ "${DISK_REGISTRY_TEST:-0}" = 1 ]; then
    # Two virtio-blk disks (virt0: a GPT with one partition labelled `extra`; virt1: blank) and,
    # on the primary IDE master, a blank 130 GiB disk past LBA28's reach (sparse: it costs no
    # space), beside the system's disk on the secondary master: the kernel names them virt0,
    # virt1, ide0 (the big one) and ide1 (regress/devfs-syscall-smoke/run.sh).
    mkdir -p target/images/registry
    head -c 1048576 /dev/zero > target/images/registry/extra.part
    rm -f target/images/registry/virt0.img target/images/registry/virt1.img target/images/registry/ide.img
    target/host-tools/x86_64-unknown-linux-gnu/release/mkimg -s gpt -o target/images/registry/virt0.img \
        -p "fat32lba/extra:=target/images/registry/extra.part"
    truncate -s 32M target/images/registry/virt1.img
    truncate -s 130G target/images/registry/ide.img
    QEMU_EXTRA_ARGS="-drive if=none,id=regv0,format=raw,file=target/images/registry/virt0.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device virtio-blk-pci,drive=regv0,disable-legacy=on"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=regv1,format=raw,file=target/images/registry/virt1.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device virtio-blk-pci,drive=regv1,disable-legacy=on"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,id=regide,format=raw,file=target/images/registry/ide.img"
    QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -device ide-hd,drive=regide,bus=ide.0,unit=0"
fi

if [ "$IS_TEST" = 1 ]; then
    QEMU_DISK_IMAGE="target/oxfs_test_disk.img"
    QEMU_DISK_FRESH=1
else
    # OXIDEBSD_DISK_IMAGE boots `cargo run` against another image (copied from the system image
    # if missing, never replaced), leaving the persistent dev disk alone.
    QEMU_DISK_IMAGE="${OXIDEBSD_DISK_IMAGE:-target/oxfs_disk.img}"
    if [ -z "${OXIDEBSD_DISK_IMAGE:-}" ]; then
        QEMU_DISK_MANAGED=1
    fi
    # Tests keep IDE (tests/ata_smoke.rs drives it directly); `cargo run` gets the fast disk.
    QEMU_DISK_DEFAULT=virtio
fi
# Booting the install medium (the install tests, or OXIDEBSD_BOOT_INSTALLER=1 for `cargo run`):
# the disk to install on starts blank, and is never the dev disk.
if [ "${INSTALL_BOOT:-0}" = 1 ] || [ -n "${OXIDEBSD_BOOT_INSTALLER:-}" ]; then
    if [ -z "$INSTALL_ISO" ]; then
        echo "qemu_runner.sh: no install.iso to boot" >&2
        exit 1
    fi
    ISO_PATH="$INSTALL_ISO"
    QEMU_DISK_SOURCE="target/images/blank.img"
    [ -f "$QEMU_DISK_SOURCE" ] || truncate -s 4G "$QEMU_DISK_SOURCE"
    if [ "$IS_TEST" = 0 ]; then
        QEMU_DISK_IMAGE="${OXIDEBSD_DISK_IMAGE:-target/install_target.img}"
        QEMU_DISK_MANAGED=0
    fi
fi
QEMU_ISO_PATH="$ISO_PATH"
QEMU_HEADLESS_TEST="$IS_TEST"
# shellcheck source=./qemu_common.sh
. "$REPO_ROOT/scripts/qemu_common.sh"

# A `cargo run` invocation gets a real display by default (this kernel has a real VGA console);
# a `cargo test` binary always forces `-display none` above regardless. This override gives a
# headless `cargo run`-shaped boot (scripted runs, a machine without a display), separately from
# the test/run split above.
if [ -n "${OXIDEBSD_QEMU_DISPLAY:-}" ]; then
    set -- "$@" -display "$OXIDEBSD_QEMU_DISPLAY"
fi

if [ "$IS_TEST" = 0 ]; then
    # Real PID (exec keeps it) -- lets a host-side script (or a human) find and kill this exact
    # QEMU instance without pattern-matching its argv.
    echo "$$" > target/qemu_runner.pid
    exec qemu-system-x86_64 "$@"
fi

# Test mode: see qemu_common.sh's own doc comment for the wedge-guard/exit-code-translation logic
# this delegates to.
TIMEOUT_SECS="${OXIDEBSD_TEST_TIMEOUT_SECS:-28800}"
qemu_common_run_test_and_translate_exit "$TIMEOUT_SECS" "$@"
