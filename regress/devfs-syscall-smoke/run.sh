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
# The listing of $1 from its directory (this BusyBox's ls has no -d).
entry() { ls -l "${1%/*}/" 2>&1 | grep -E " ${1##*/}( -> .*)?\$"; }
mode_is() {
	_l=$(entry "$1")
	case "$_l" in "$2 "*) return 0 ;; esac
	echo "devfs-smoke: $1: $_l"
	return 1
}
# The raw st_mode of $1, in hex (stat -t's fourth field): this BusyBox's ls doesn't show the
# sticky bit.
raw_mode_is() { set -- "$2" $(stat -t "$1" 2>/dev/null); [ "$5" = "$1" ]; }
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
check "/dev/shm is a sticky, world-writable directory" raw_mode_is /dev/shm 43ff
check "/dev/zero reads zeros" zeros
check "/dev/null takes writes" sh -c 'echo discarded > /dev/null'
check "/dev/urandom reads" random16

# --- Changes last until reboot ----------------------------------------------------------------
chmod 600 /dev/null
check "chmod of a node sticks" mode_is /dev/null crw-------
chmod 666 /dev/null
mkdir /dev/stickytest
chmod 1777 /dev/stickytest
check "chmod keeps the sticky bit" raw_mode_is /dev/stickytest 43ff
rm -f /dev/zero
check "rm removes a node" gone /dev/zero
ls /dev > /dev/null
check "... and it stays removed" gone /dev/zero
check "mknod of a device in /dev is refused" not mknod /dev/mynull c 1 3
check "... and makes nothing" [ ! -e /dev/mynull ]
check "a symbolic link can be made in /dev" ln -s null /dev/mylink
check "... and used" sh -c 'echo x > /dev/mylink'
check "a directory can be made in /dev" mkdir /dev/mydir
check "a file can be made under /dev/shm" sh -c 'echo shm > /dev/shm/myfile'
check "... and read back" [ "$(cat /dev/shm/myfile)" = shm ]

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

echo "devfs-smoke: $fail failed"
[ $fail -eq 0 ]
