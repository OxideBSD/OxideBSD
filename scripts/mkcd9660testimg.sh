#!/bin/sh
# mkcd9660testimg.sh OUTDIR: the discs tests/cd9660_syscall_smoke.rs puts in its IDE CD drives,
# made by the host xorriso from one tree:
#   rr.iso      Rock Ridge and Joliet, volume CDTEST, with a FAT image appended as MBR partition 2
#               (as a hybrid install image carries its ESP)
#   joliet.iso  Joliet only
#   plain.iso   neither: 8.3 names only
# regress/cd9660-syscall-smoke/run.sh knows the tree: keep the two in step.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: mkcd9660testimg.sh outdir" >&2
    exit 1
fi
OUT="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO_ROOT/target/host-tools/x86_64-unknown-linux-gnu/release"
for f in "$TOOLS/makefs" xorriso; do
    if ! command -v "$f" > /dev/null 2>&1; then
        echo "mkcd9660testimg.sh: $f is missing" >&2
        exit 1
    fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkcd9660testimg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
T="$WORK/tree"
mkdir -p "$T/SUB/DEEPER" "$T/MANY" "$T/D1/D2/D3/D4/D5/D6/D7/D8/D9"
printf 'hello, ISO 9660\n' > "$T/README.TXT"
seq 1 400000 > "$T/BIG.BIN"
sha256sum "$T/BIG.BIN" | cut -d' ' -f1 > "$T/BIG.SHA"
printf 'kernel\n' > "$T/SUB/DEEPER/KERNEL.TXT"
printf 'deep\n' > "$T/D1/D2/D3/D4/D5/D6/D7/D8/D9/DEEP.TXT"
: > "$T/EMPTY.TXT"
printf 'noext\n' > "$T/NOEXT"
i=0
while [ $i -lt 300 ]; do
    printf '%d\n' $i > "$T/MANY/F$i.TXT"
    i=$((i + 1))
done
# Rock Ridge and Joliet only:
printf 'mixed\n' > "$T/Mixed Case Long Name.text"
printf 'mode\n' > "$T/mode640.txt"
chmod 0640 "$T/mode640.txt"
ln -s README.TXT "$T/link"
ln -s ../../README.TXT "$T/SUB/DEEPER/uplink"
id -u > "$T/OWNER.TXT"
# Fixed times, so run.sh can check them.
find "$T" -exec touch -h -d @1760000000 {} +

# The FAT partition: one file.
mkdir -p "$WORK/fat"
printf 'esp\n' > "$WORK/fat/HELLO.TXT"
"$TOOLS/makefs" -t msdos -T 1760000000 -o fat_type=12,volume_label=ESP -s 2m "$WORK/fat.img" "$WORK/fat" > /dev/null

mkdir -p "$OUT"
rm -f "$OUT/rr.iso" "$OUT/joliet.iso" "$OUT/plain.iso"
q="-quiet"
xorriso -as mkisofs $q -R -J -V CDTEST -o "$OUT/rr.iso" -append_partition 2 0xef "$WORK/fat.img" "$T"
# xorriso writes Rock Ridge unless told not to.
xorriso -as mkisofs $q --norock -J -V CDTEST -o "$OUT/joliet.iso" "$T"
xorriso -as mkisofs $q --norock -V CDTEST -o "$OUT/plain.iso" "$T"
