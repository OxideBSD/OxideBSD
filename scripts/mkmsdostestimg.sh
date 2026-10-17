#!/bin/sh
# mkmsdostestimg.sh OUT: the disk tests/msdosfs_syscall_smoke.rs boots: the system's root
# (target/images/root.img, partition `rootfs`, which the kernel finds through fsconf) and three
# FAT volumes made by the host makefs from one tree, as GPT partitions `fat12`, `fat16` and
# `fat32` (/dev/gpt/fat12 ...). regress/msdosfs-syscall-smoke/run.sh knows the tree: keep the two
# in step.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: mkmsdostestimg.sh out.img" >&2
    exit 1
fi
OUT="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO_ROOT/target/host-tools/x86_64-unknown-linux-gnu/release"
ROOT_IMG="$REPO_ROOT/target/images/root.img"
for f in "$TOOLS/makefs" "$TOOLS/mkimg" "$ROOT_IMG"; do
    if [ ! -e "$f" ]; then
        echo "mkmsdostestimg.sh: $f is missing (cargo build makes it)" >&2
        exit 1
    fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkmsdostestimg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
T="$WORK/tree"
mkdir -p "$T/sub/deeper" "$T/many"
printf 'hello, FAT\n' > "$T/README.TXT"
printf 'long\n' > "$T/a long file name.text"
printf 'mixed\n' > "$T/Mixed Case.Txt"
printf 'lower\n' > "$T/lower.txt"
printf 'caf\303\251\n' > "$T/caf$(printf '\303\251').txt"
printf 'nihongo\n' > "$T/$(printf '\346\227\245\346\234\254\350\252\236').txt"
printf 'read only\n' > "$T/readonly.txt"
chmod 0444 "$T/readonly.txt"
: > "$T/empty"
printf 'kernel\n' > "$T/sub/deeper/kernel"
seq 1 50000 > "$T/sub/big.bin"
i=0
while [ $i -lt 300 ]; do
    printf '%d\n' $i > "$T/many/file$i"
    i=$((i + 1))
done

# A fixed time, so the volumes are the same every build and run.sh can check it.
STAMP=1760000000
"$TOOLS/makefs" -t msdos -T $STAMP -o fat_type=12,volume_label=FAT12 -s 4m "$WORK/f12.img" "$T" > /dev/null
"$TOOLS/makefs" -t msdos -T $STAMP -o fat_type=16,volume_label=FAT16 -s 24m "$WORK/f16.img" "$T" > /dev/null
"$TOOLS/makefs" -t msdos -T $STAMP -o fat_type=32,volume_label=FAT32 -s 40m "$WORK/f32.img" "$T" > /dev/null
rm -f "$OUT"
"$TOOLS/mkimg" -s gpt -o "$OUT" -p "oxfs/rootfs:=$ROOT_IMG" \
    -p "fat16b/fat12:=$WORK/f12.img" -p "fat16b/fat16:=$WORK/f16.img" -p "fat32lba/fat32:=$WORK/f32.img"
