#!/bin/sh
# NOT executable on its own -- sourced (`. scripts/qemu_common.sh`) by both scripts/qemu_runner.sh
# (Limine, cargo's own `runner=`) and scripts/run_multiboot2_smoke.sh (a real Multiboot2 boot, via
# either Limine's own multiboot2 protocol or real GRUB). Extracted so the loader-agnostic parts of
# driving QEMU for this kernel live in exactly one place -- see CLAUDE.md's Multiboot2 section.
#
# What's shared here, and why: the never-`-M q35` constraint and the fixed IDE topology (real ATA
# disk on ide.1/unit0, boot medium on ide.0/unit0) are properties of *this kernel's own driver*
# (src/drivers/ata.rs), not of any one bootloader -- every boot path needs the identical topology.
# Firmware/OVMF selection and the isa-debug-exit wedge-guard/exit-code translation are QEMU/host
# concerns, equally loader-agnostic. Deliberately NOT here: ISO staging (Limine's own ISO layout
# and GRUB's are unrelated) and any bootloader-specific config-file content -- those stay in each
# caller, along with `qemu_runner.sh`'s own interactive `cargo run` vs `cargo test` split
# (`run_multiboot2_smoke.sh` is always test-shaped, so it never needs that split at all).
#
# Caller contract: set $QEMU_DISK_IMAGE, $QEMU_ISO_PATH, and $QEMU_HEADLESS_TEST (1 to add
# `-device isa-debug-exit` + `-display none` up front, 0/unset for an interactive display) *before*
# sourcing this file. After sourcing, "$@" holds the complete, ready-to-exec QEMU argv; a caller
# either `exec`s it directly (interactive mode) or passes it to
# `qemu_common_run_test_and_translate_exit` below (headless mode).
#
# Building "$@" via top-level `set --` statements here (rather than a function the caller calls) is
# deliberate, not incidental: POSIX sh functions get their own private positional parameters, so a
# function can't mutate its caller's "$@" the way sourcing a plain script body can.

: "${QEMU_DISK_IMAGE:?qemu_common.sh: QEMU_DISK_IMAGE must be set before sourcing}"
: "${QEMU_ISO_PATH:?qemu_common.sh: QEMU_ISO_PATH must be set before sourcing}"

set -- -accel kvm -accel tcg -serial stdio -m 8192 -nic user,model=rtl8139

# Opt-in QEMU monitor on a plain TCP port -- see qemu_runner.sh's git history/CLAUDE.md's test-
# architecture section for the real, non-interactive use this unlocks (scripted `sendkey`).
if [ -n "${OXIDEBSD_QEMU_MONITOR:-}" ]; then
    set -- "$@" -monitor "tcp:127.0.0.1:${OXIDEBSD_QEMU_MONITOR},server,nowait"
fi

# Real emulated xHCI controller + USB keyboard, opt-in only -- see src/drivers/usb's own module
# doc comment. Off by default: QEMU's default i440fx machine already wires up a PS/2 keyboard, so
# an always-on USB one would double-push every keystroke.
if [ "${OXIDEBSD_QEMU_USB:-0}" = 1 ]; then
    set -- "$@" -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
fi

if [ "${QEMU_HEADLESS_TEST:-0}" = 1 ]; then
    set -- "$@" -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none
fi

# Real ATA data disk pinned explicitly to the secondary channel's master (ide.1, unit 0), boot
# medium on the primary channel's master (ide.0, unit 0) -- see CLAUDE.md's "Real disk persistence"
# section for why a bare `-cdrom` collides with this. Deliberately never `-M q35`: q35 drops the
# legacy PIIX IDE controller the real ATA disk-persistence device below depends on -- staying on
# the default (unstated) i440fx machine type keeps this working under both BIOS and UEFI, since
# OVMF loads fine there via a single combined `-bios` image with no `-M` change needed.
set -- "$@" \
    -drive "if=none,id=oxfsdisk,format=raw,file=$QEMU_DISK_IMAGE" \
    -device ide-hd,drive=oxfsdisk,bus=ide.1,unit=0 \
    -drive "if=none,id=isocd,media=cdrom,file=$QEMU_ISO_PATH" \
    -device ide-cd,drive=isocd,bus=ide.0,unit=0

qemu_common_find_ovmf() {
    if [ -n "${OXIDEBSD_OVMF_PATH:-}" ]; then
        printf '%s\n' "$OXIDEBSD_OVMF_PATH"
        return 0
    fi
    for p in \
        /usr/share/edk2/x64/OVMF.4m.fd \
        /usr/share/edk2-ovmf/x64/OVMF.fd \
        /usr/share/OVMF/OVMF.fd \
        /usr/share/ovmf/x64/OVMF.fd \
        /usr/share/qemu/OVMF.fd
    do
        if [ -e "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

# Firmware selection: UEFI by default (this project's own choice -- real hardware today is
# UEFI-first), BIOS via OXIDEBSD_FIRMWARE=bios. OVMF itself is a host QEMU prerequisite, like
# qemu-system-x86_64 already is -- not vendored.
FIRMWARE="${OXIDEBSD_FIRMWARE:-uefi}"
if [ "$FIRMWARE" = "bios" ]; then
    set -- "$@" -boot order=d
elif [ "$FIRMWARE" = "uefi" ]; then
    OVMF_PATH="$(qemu_common_find_ovmf)" || {
        echo "qemu_common.sh: no OVMF firmware found for UEFI boot (the default)." >&2
        echo "  Install a package providing it (e.g. edk2-ovmf), or set OXIDEBSD_OVMF_PATH." >&2
        echo "  Set OXIDEBSD_FIRMWARE=bios to boot via BIOS instead." >&2
        exit 1
    }
    set -- "$@" -bios "$OVMF_PATH"
else
    echo "qemu_common.sh: unknown OXIDEBSD_FIRMWARE '$FIRMWARE' (expected 'uefi' or 'bios')" >&2
    exit 1
fi

# Real, wedge-safe headless boot-and-check: launches QEMU with "$@" appended after $1 (the
# timeout, in seconds), waits for it to exit on its own -- killing it and exiting 124 if it doesn't
# (the same "kill QEMU from the host, since nothing inside a genuinely stuck guest can rescue
# itself" idiom scripts/run_posix_pilot_supervised.sh already uses) -- then translates the real
# isa-debug-exit code (src/qemu.rs's QemuExitCode) into a plain pass/fail exit status.
qemu_common_run_test_and_translate_exit() {
    timeout_secs="$1"
    shift

    qemu-system-x86_64 "$@" &
    qemu_pid=$!
    # Lets a host-side script (e.g. scripts/test_busybox.sh, or a human) find and kill this exact
    # QEMU instance without pattern-matching its argv.
    echo "$qemu_pid" > target/qemu_runner.pid

    elapsed=0
    while kill -0 "$qemu_pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$timeout_secs" ]; then
            echo "qemu_common.sh: timed out after ${timeout_secs}s, killing QEMU (pid $qemu_pid)" >&2
            kill "$qemu_pid" 2>/dev/null || true
            wait "$qemu_pid" 2>/dev/null || true
            exit 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    exit_code=0
    wait "$qemu_pid" || exit_code=$?

    # QemuExitCode::Success (0x10) -> real QEMU exit code (0x10<<1)|1 = 33; anything else is a
    # failure (QemuExitCode::Failed = 0x11 -> 35, or a genuine crash/signal exit).
    if [ "$exit_code" -eq 33 ]; then
        exit 0
    else
        exit "$exit_code"
    fi
}
