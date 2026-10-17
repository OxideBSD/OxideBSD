#!/sbin/init_sh
#
# On-target check for msdosfs (VFS.md §9), seeded as /usr/tests/msdosfs/run.sh. The test disk
# (scripts/mkmsdostestimg.sh) has the same tree on three FAT volumes: /dev/gpt/fat12, fat16 and
# fat32. Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "msdosfs-smoke: ok: $_desc"
	else
		echo "msdosfs-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
is() { [ "$1" = "$2" ] || { echo "  got '$1', want '$2'"; return 1; }; }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
# stat(1) here is BusyBox's without -c: its terse line's fields (name size blocks mode(hex) uid
# gid dev ino nlink major minor atime mtime ctime ...). Names without spaces only.
field() { stat -t "$1" | awk -v f="$2" '{print $f}'; }
perm() { printf '%o' $(( 0x$(field "$1" 4) & 0777 )); }
owner() { echo "$(field "$1" 5):$(field "$1" 6)"; }
mtime() { field "$1" 13; }
links() { field "$1" 9; }
# OVMF (UEFI) keeps its variables in NvVars on the first FAT volume it finds: not ours to count.
count_tree() {
	_n=$(find "$1" | grep -v '/NvVars$' | wc -l | tr -d ' ')
	[ "$_n" = "$2" ] && return 0
	echo "  got $_n entries, want $2:"
	find "$1" | sort | uniq -c | sort -rn | head -n 5
	find "$1" | grep -v /many/ | sort
	return 1
}
# The makefs time of every file (-T): 2025-10-09 08:53:20 local, here UTC.
STAMP=1760000000

seq 1 50000 > /tmp/big.expected

# --- Each type, the same tree ------------------------------------------------------------------
for t in 12 16 32; do
	D=/tmp/fat$t
	mkdir -p $D
	check "FAT$t: fsck_msdosfs -n finds it clean" fsck_msdosfs -n /dev/gpt/fat$t
	check "FAT$t: mounts read-only" mount -t msdosfs -o ro /dev/gpt/fat$t $D
	check "FAT$t: listed by mount" eval "mount | grep -q 'on $D (msdosfs'"
	check "FAT$t: an 8.3 name" is "$(cat $D/README.TXT)" "hello, FAT"
	check "FAT$t: a long name" is "$(cat "$D/a long file name.text")" "long"
	check "FAT$t: case preserved" eval "ls $D | grep -qx 'Mixed Case.Txt'"
	check "FAT$t: a lower-case 8.3 name shows lower case" eval "ls $D | grep -qx lower.txt"
	check "FAT$t: lookups ignore case" is "$(cat $D/readme.txt)" "hello, FAT"
	check "FAT$t: ... long names too" is "$(cat "$D/MIXED CASE.TXT")" "mixed"
	check "FAT$t: ... and the short alias" is "$(cat $D/ALONGF~1.TEX)" "long"
	check "FAT$t: a UTF-8 long name" is "$(cat "$D/café.txt")" "café"
	check "FAT$t: a CJK long name" is "$(cat $D/日本語.txt)" "nihongo"
	check "FAT$t: a file over many clusters" cmp $D/sub/big.bin /tmp/big.expected
	check "FAT$t: an empty file" eval "[ -f $D/empty ] && [ ! -s $D/empty ]"
	check "FAT$t: nested directories" is "$(cat $D/sub/deeper/kernel)" "kernel"
	check "FAT$t: a directory of 300 names" is "$(ls $D/many | wc -l | tr -d ' ')" 300
	check "FAT$t: ... each readable" is "$(cat $D/many/file299)" 299
	check "FAT$t: find walks the tree" count_tree $D 314
	check "FAT$t: the read-only attribute clears the write bits" is "$(perm $D/readonly.txt)" 555
	check "FAT$t: modes from the mount point (0755)" is "$(perm $D/README.TXT)" 755
	check "FAT$t: owner root" is "$(owner $D/README.TXT)" 0:0
	check "FAT$t: the stored time" is "$(mtime $D/README.TXT)" $STAMP
	check "FAT$t: no hard links" is "$(links $D/README.TXT)" 1
	check "FAT$t: .. leads back up" is "$(cd $D/sub/deeper/.. && pwd)" "$D/sub"
	check "FAT$t: getcwd inside it" is "$(cd $D/sub/deeper && /bin/pwd)" "$D/sub/deeper"
	check "FAT$t: ... from the root's .. too" is "$(cd $D/sub/.. && ls README.TXT)" README.TXT
	check "FAT$t: df knows it" eval "df $D | grep -q fat$t"
	check "FAT$t: unmounts" umount $D
done

# --- Options and errors ------------------------------------------------------------------------
D=/tmp/fat16
check "read-write is refused (read-only support only)" not mount -t msdosfs /dev/gpt/fat16 $D
check "uid, gid, mask and dirmask options" mount -t msdosfs -o ro,uid=5,gid=6,mask=640,dirmask=750 /dev/gpt/fat16 $D
check "... owner" is "$(owner $D/README.TXT)" 5:6
check "... file mode" is "$(perm $D/README.TXT)" 640
check "... directory mode" is "$(perm $D/sub)" 750
check "... the read-only attribute still clears write" is "$(perm $D/readonly.txt)" 440
umount $D
check "shortnames shows 8.3 names" mount -t msdosfs -o ro,shortnames /dev/gpt/fat16 $D
check "... the alias" eval "ls $D | grep -qx 'ALONGF~1.TEX'"
check "... not the long name" not eval "ls $D | grep -q 'a long file name'"
umount $D
check "an unknown option is refused" not mount -t msdosfs -o ro,bogus=1 /dev/gpt/fat16 $D
check "a device that isn't FAT is refused" not mount -t msdosfs -o ro /dev/gpt/rootfs $D
check "a missing device is refused" not mount -t msdosfs -o ro /dev/gpt/nosuch $D
mount -t msdosfs -o ro /dev/gpt/fat16 $D
check "the same device twice is refused" not mount -t msdosfs -o ro /dev/gpt/fat16 /tmp/fat12
check "kern.utc_offset moves the times (+60 min)" sysctl kern.utc_offset=60
check "... an hour earlier in UTC" is "$(mtime $D/README.TXT)" $((STAMP - 3600))
sysctl kern.utc_offset=0 > /dev/null
check "statfs counts clusters" eval "df -k $D | tail -1 | awk '{exit !(\$2 > 20000)}'"
umount $D

# --- newfs_msdos -------------------------------------------------------------------------------
check "newfs_msdos FAT12 into a file" newfs_msdos -F 12 -C 2m /tmp/n12.img
check "newfs_msdos FAT16" newfs_msdos -F 16 -C 20m -L DATA /tmp/n16.img
check "newfs_msdos FAT32" newfs_msdos -F 32 -C 40m /tmp/n32.img
check "... fsck_msdosfs agrees" eval "fsck_msdosfs -n /tmp/n12.img && fsck_msdosfs -n /tmp/n16.img && fsck_msdosfs -n /tmp/n32.img"

echo "msdosfs-smoke: $fail failed"
[ $fail -eq 0 ]
