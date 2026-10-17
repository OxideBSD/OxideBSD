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
#   3. oxfs    rootfs  the system build.rs made (target/images/root.img), made again from the
#                      same sets with /etc/fstab mounting the ESP on /boot/efi, and the ESP's
#                      /boot/fsconf compiled from that fstab (fsconf_mkdb)
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
SETS="$REPO_ROOT/target/sets"
FSCONF_MKDB="$REPO_ROOT/target/fsconf-host/x86_64-unknown-linux-gnu/release/fsconf_mkdb"

for f in "$TOOLS/makefs" "$TOOLS/mkimg" "$STAGE/limine-bios-hdd.bin" "$ROOT_IMG" \
    "$BOOTDIR/kernel" "$BOOTDIR/limine/limine.conf" "$SETS/base.makefs" "$FSCONF_MKDB" \
    "$REPO_ROOT/target/destdir/etc/fstab"; do
    if [ ! -e "$f" ]; then
        echo "mkbootimg.sh: $f is missing (cargo build, and for BOOTDIR a cargo run, make it)" >&2
        exit 1
    fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkbootimg.XXXXXX")"
# The base set's makefs spec, edited, beside the original: its contents paths are relative to it.
SPEC="$SETS/.mkbootimg.$$.makefs"
trap 'rm -rf "$WORK" "$SPEC"' EXIT

# /etc/fstab with the ESP's line, the root image made again with it, and its fsconf for the ESP.
FSTAB="$WORK/fstab"
cp "$REPO_ROOT/target/destdir/etc/fstab" "$FSTAB"
printf '/dev/gpt/efi\t/boot/efi\tmsdosfs\trw\t\t2\t2\n' >> "$FSTAB"
DIGEST=$(sha256sum "$FSTAB" | cut -d' ' -f1)
SIZE=$(wc -c < "$FSTAB" | tr -d ' ')
awk -v f="$FSTAB" -v d="$DIGEST" -v s="$SIZE" '
    $1 == "./etc/fstab" {
        for (i = 2; i <= NF; i++) {
            if ($i ~ /^contents=/) $i = "contents=" f
            else if ($i ~ /^sha256digest=/) $i = "sha256digest=" d
            else if ($i ~ /^size=/) $i = "size=" s
        }
    }
    { print }' "$SETS/base.makefs" > "$SPEC"
OTHER_SETS=""
for set in "$SETS"/*.makefs; do
    case "$set" in
    "$SETS/base.makefs" | "$SETS"/.mkbootimg.*) ;;
    *) OTHER_SETS="$OTHER_SETS $set" ;;
    esac
done
ROOT_SIZE=$(wc -c < "$ROOT_IMG" | tr -d ' ')
# shellcheck disable=SC2086 # one word per set spec
"$TOOLS/makefs" -t oxfs -o label=rootfs -s "$ROOT_SIZE" "$WORK/root.img" "$SPEC" $OTHER_SETS > /dev/null
ROOT_IMG="$WORK/root.img"
ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT" "$ESP/boot/limine"
cp "$STAGE/BOOTX64.EFI" "$STAGE/BOOTIA32.EFI" "$ESP/EFI/BOOT/"
cp "$STAGE/limine-bios.sys" "$BOOTDIR/limine/limine.conf" "$ESP/boot/limine/"
cp "$BOOTDIR/kernel" "$ESP/boot/"
"$FSCONF_MKDB" -f "$FSTAB" -o "$ESP/boot/fsconf"

"$TOOLS/makefs" -t msdos -o volume_label=EFISYS -s 64m "$WORK/esp.img" "$ESP" > /dev/null
"$TOOLS/mkimg" -s gpt -o "$OUT" -b "$STAGE/limine-bios-hdd.bin" \
    -p bios::64k -p "efi/efi:=$WORK/esp.img" -p "oxfs/rootfs:=$ROOT_IMG"
