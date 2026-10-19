#!/sbin/init_sh
#
# On-target check for devfs (DEVFS.md §6.1), seeded as /usr/tests/devfs/run.sh. Runs as root;
# prints one line per check and exits 0 if all pass. (That a removed node is back after a reboot
# is checked by hand: a test boots once.)

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "devfs-smoke: ok: $_desc"
	else
		echo "devfs-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
# $1's listing shows mode $2, owner $3 and group $4.
node_is() {
	set -- "$1" "$2" "$3" "$4" $(entry "$1")
	[ "$5" = "$2" ] && [ "$7" = "$3" ] && [ "$8" = "$4" ]
}
entry() { ls -ld "$1" 2>&1; }
mode_is() {
	_l=$(entry "$1")
	case "$_l" in "$2 "*) return 0 ;; esac
	echo "devfs-smoke: $1: $_l"
	return 1
}
gone() { [ ! -e "$1" ] && ! ls /dev | grep -qx "${1#/dev/}"; }
# Reads $2 bytes from device $1 (dd: this BusyBox's head has no -c).
bytes() { dd if="$1" bs="$2" count=1 2>/dev/null; }
zeros() { [ "$(bytes /dev/zero 4 | wc -c | tr -d ' ')" = 4 ] && [ -z "$(bytes /dev/zero 4 | tr -d '\000')" ]; }
random16() { [ "$(bytes /dev/urandom 16 | wc -c | tr -d ' ')" = 16 ]; }
has_mount() { grep -q "^devfs /dev devfs " /proc/mounts; }

# --- The registry's nodes ----------------------------------------------------------------------
check "devfs is mounted on /dev" has_mount
check "/dev/null is crw-rw-rw- root root" node_is /dev/null crw-rw-rw- root root
check "/dev/zero is crw-rw-rw-" mode_is /dev/zero crw-rw-rw-
check "/dev/random is crw-rw-rw-" mode_is /dev/random crw-rw-rw-
check "/dev/urandom is crw-rw-rw-" mode_is /dev/urandom crw-rw-rw-
check "/dev/ttyv0 is crw------- root tty" node_is /dev/ttyv0 crw------- root tty
check "/dev/tty is crw-rw-rw-" mode_is /dev/tty crw-rw-rw-
check "/dev/console is crw-------" mode_is /dev/console crw-------
check "/dev/klog is crw-------" mode_is /dev/klog crw-------
check "/dev/shm is drwxrwxrwt" mode_is /dev/shm drwxrwxrwt
check "/dev/zero reads zeros" zeros
check "/dev/null takes writes" sh -c 'echo discarded > /dev/null'
check "/dev/urandom reads" random16

# --- Changes last until reboot ----------------------------------------------------------------
chmod 600 /dev/null
check "chmod of a node sticks" mode_is /dev/null crw-------
chmod 666 /dev/null
mkdir /dev/stickytest
chmod 1777 /dev/stickytest
check "chmod keeps the sticky bit" mode_is /dev/stickytest drwxrwxrwt
rm -f /dev/zero
check "rm removes a node" gone /dev/zero
ls /dev > /dev/null
check "... and it stays removed" gone /dev/zero
check "mknod of a device in /dev is refused" not mknod /dev/mynull c 1 3
check "... and makes nothing" [ ! -e /dev/mynull ]
check "a symbolic link can be made in /dev" ln -s null /dev/mylink
check "... and used" sh -c 'echo x > /dev/mylink'
check "a directory can be made in /dev" mkdir /dev/mydir
check "... and removed" rmdir /dev/mydir
check "a regular file can't be made in /dev (FreeBSD's)" not sh -c ': > /dev/myfile' 2>/dev/null
check "... nor a hard link" not ln /dev/null /dev/hardnull 2>/dev/null
check "... nor a rename" not mv /dev/mylink /dev/mylink2 2>/dev/null
chown 1:1 /dev/null
check "chown of a node sticks" sh -c 'ls -ln /dev/null | grep -q " 1 *1 "'
chown 0:0 /dev/null
check "/dev/shm is a tmpfs" grep -q " /dev/shm tmpfs " /proc/mounts
check "a file can be made under /dev/shm" sh -c 'echo shm > /dev/shm/myfile'
check "... and read back" [ "$(cat /dev/shm/myfile)" = shm ]

# --- Other views --------------------------------------------------------------------------------
mkdir -p /tmp/devfs/view
check "devfs mounts elsewhere too" mount -t devfs devfs /tmp/devfs/view
check "... with the registry's nodes" [ -c /tmp/devfs/view/null ]
check "... including one removed from /dev" [ -c /tmp/devfs/view/zero ]
rm /tmp/devfs/view/random
check "removing a node there leaves /dev's" [ -c /dev/random ]
check "... and the empty shm directory" [ -d /tmp/devfs/view/shm ]
check "the view unmounts" umount /tmp/devfs/view

# --- A node made on disk opens through the registry --------------------------------------------
mkdir -p /tmp/devfs
check "mknod works outside /dev" mknod /tmp/devfs/null c 1 3
check "... and the node opens as /dev/null" sh -c 'echo x > /tmp/devfs/null && [ -z "$(cat /tmp/devfs/null)" ]'
check "a node with no driver fails to open" sh -c 'mknod /tmp/devfs/none c 250 0 && ! cat /tmp/devfs/none 2>/dev/null'

# --- rc.d/devfs applies /etc/devfs.conf ---------------------------------------------------------
cp /etc/devfs.conf /tmp/devfs/devfs.conf.orig
printf '%s\n' '# test' 'perm	klog	0640' 'own	tty	root:tty' 'link	null	nothing' 'perm	nosuch*	0600' > /etc/devfs.conf
/etc/rc.d/devfs onestart > /dev/null 2>&1
check "perm applies" mode_is /dev/klog crw-r-----
check "own applies" node_is /dev/tty crw-rw-rw- root tty
check "link applies" [ -L /dev/nothing ]
cp /tmp/devfs/devfs.conf.orig /etc/devfs.conf

# --- The disk registry (INSTALLER.md §5) --------------------------------------------------------
# The runner attaches virt0 (GPT, one partition labelled `extra`), virt1 (blank), ide0 (blank,
# 130 GiB, on the primary master) beside the system's disk, ide1 (the secondary master); scsi0 is
# the boot medium.
disk_sysctl() { sysctl -n "kern.disk.$1.$2" 2>&1; }
# Writes $2 at 512-byte sector $3 of device $1 and reads it back.
sector_round_trip() {
	printf '%s' "$2" | dd of="$1" bs=512 seek="$3" conv=notrunc,sync 2>/dev/null &&
		[ "$(dd if="$1" bs=512 skip="$3" count=1 2>/dev/null | tr -d '\000')" = "$2" ]
}
check "kern.disks lists every disk" [ "$(sysctl -n kern.disks)" = "virt0 virt1 ide0 ide1 scsi0" ]
for d in virt0 virt0p1 gpt/extra virt1 ide0 ide1 ide1p1; do
	check "/dev/$d is crw-------" mode_is /dev/$d crw-------
done
check "virt1 has no partitions" sh -c '[ ! -e /dev/virt1p1 ] && [ ! -e /dev/virt1s1 ]'
check "a second unit's minor is unit << 8" sh -c 'ls -l /dev/virt1 | grep -q " 252, *256 "'
check "... and its partitions' unit << 8 | N" sh -c 'ls -l /dev/ide1p1 | grep -q " 3, *257 "'
check "kern.disk.ide0.size is 130 GiB" [ "$(disk_sysctl ide0 size)" = 139586437120 ]
check "kern.disk.virt1.size is 32 MiB" [ "$(disk_sysctl virt1 size)" = 33554432 ]
check "kern.disk.virt0.kind is disk" [ "$(disk_sysctl virt0 kind)" = disk ]
check "kern.disk.ide1.sectorsize is 512" [ "$(disk_sysctl ide1 sectorsize)" = 512 ]
check "kern.disk.ide1.model is the drive's" [ "$(disk_sysctl ide1 model)" = "QEMU HARDDISK" ]
check "virt1 reads and writes" sector_round_trip /dev/virt1 virt1-data 100
check "virt0's partition does too" sector_round_trip /dev/gpt/extra extra-data 10
check "... the same sectors as through virt0p1" [ "$(dd if=/dev/virt0p1 bs=512 skip=10 count=1 2>/dev/null | tr -d '\000')" = extra-data ]
check "ide0 reads and writes below 128 GiB (LBA28)" sector_round_trip /dev/ide0 low-data 1000
check "... and above it (LBA48)" sector_round_trip /dev/ide0 high-data 268435500
check "... at its last sector" sector_round_trip /dev/ide0 last-data 272629759
check "... and not past its end" not sh -c 'printf x | dd of=/dev/ide0 bs=512 seek=272629760 conv=notrunc,sync 2>/dev/null'
check "the root's disk can't be written while mounted" not sh -c 'printf x | dd of=/dev/ide1 bs=512 seek=1 conv=notrunc,sync 2>/dev/null'

echo "devfs-smoke: $fail failed"
[ $fail -eq 0 ]
