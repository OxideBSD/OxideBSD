#!/bin/sh
# mkbootimg.sh BOOTDIR OUT: a disk image that boots by itself, on BIOS and on UEFI
# (OxideBSD-doc RAM_FLOOR.md §4.4.4), for a USB stick or a test.
#
# BOOTDIR holds what the boot loader loads, as the QEMU runner stages it for the ISO
# (target/iso_root/boot after a `cargo run`): `kernel`, `limine/limine.conf`, and `fsconf` if the
# kernel is to find the root by it. The image is a GPT disk:
#
#   1. bios    64 KiB  Limine's BIOS stage 2 (mkimg -b; the boot sector gets stage 1)
#   2. efi     64 MiB  FAT32 (makefs -t msdos): EFI/BOOT/BOOT{X64,IA32}.EFI for UEFI,
#                      boot/limine/limine-bios.sys for BIOS, the config, the kernel
#   3. oxfs    rootfs  target/images/root.img, the system build.rs made
#
# The host makefs and mkimg are build.rs's (target/host-tools), as are Limine's files
# (target/limine-stage).
set -eu

if [ $# -ne 2 ]; then
    echo "usage: mkbootimg.sh bootdir out.img" >&2
    exit 1
fi
BOOTDIR="$1"
OUT="$2"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO_ROOT/target/host-tools/x86_64-unknown-linux-gnu/release"
STAGE="$REPO_ROOT/target/limine-stage"
ROOT_IMG="$REPO_ROOT/target/images/root.img"

for f in "$TOOLS/makefs" "$TOOLS/mkimg" "$STAGE/limine-bios-hdd.bin" "$ROOT_IMG" \
    "$BOOTDIR/kernel" "$BOOTDIR/limine/limine.conf"; do
    if [ ! -e "$f" ]; then
        echo "mkbootimg.sh: $f is missing (cargo build, and for BOOTDIR a cargo run, make it)" >&2
        exit 1
    fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkbootimg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT" "$ESP/boot/limine"
cp "$STAGE/BOOTX64.EFI" "$STAGE/BOOTIA32.EFI" "$ESP/EFI/BOOT/"
cp "$STAGE/limine-bios.sys" "$BOOTDIR/limine/limine.conf" "$ESP/boot/limine/"
cp "$BOOTDIR/kernel" "$ESP/boot/"
if [ -f "$BOOTDIR/fsconf" ]; then
    cp "$BOOTDIR/fsconf" "$ESP/boot/"
fi

"$TOOLS/makefs" -t msdos -o volume_label=EFISYS -s 64m "$WORK/esp.img" "$ESP" > /dev/null
"$TOOLS/mkimg" -s gpt -o "$OUT" -b "$STAGE/limine-bios-hdd.bin" \
    -p bios::64k -p "efi/efi:=$WORK/esp.img" -p "oxfs/rootfs:=$ROOT_IMG"
