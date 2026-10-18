#!/sbin/init_sh
#
# On-target check for the /bin and /sbin utilities rewritten in Rust std (and nmount(2) through
# mount), seeded as /usr/tests/bin/run.sh.
# Runs as root; prints one line per check and exits 0 if all pass. test, [ and kill are named
# by path: the shell has built-ins of its own by those names.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin-smoke: ok: $_desc"
	else
		echo "bin-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
perms() { ls -ld "$1" | cut -c1-10; }
T=/tmp/bin-smoke
rm -rf $T
mkdir -p $T
cd $T

# --- sleep, sync ---------------------------------------------------------------------------
t1=$(date +%s)
sleep 0.5 0.5s
t2=$(date +%s)
check "sleep adds up its arguments" [ $((t2 - t1)) -ge 1 ]
check "sleep refuses a bad interval" status_is 1 sleep 1x
check "sync" sync

# --- link, unlink ----------------------------------------------------------------------------
echo data > a
check "link makes a hard link" link a b
check "to the same file" /bin/test a -ef b
check "link refuses an existing name" not link a b
check "unlink removes a name" unlink b
check "leaving the other" /bin/test -f a
mkdir d
check "unlink refuses a directory" not unlink d

# --- rmdir -----------------------------------------------------------------------------------
mkdir -p x/y/z
check "rmdir -p removes the parents too" rmdir -p x/y/z
check "all of them" not /bin/test -e x
mkdir full && touch full/f
check "rmdir refuses a directory that isn't empty" not rmdir full
check "rmdir -v names what it removed" [ "$(rmdir -v d)" = d ]

# --- nproc -----------------------------------------------------------------------------------
check "nproc counts one processor" [ "$(nproc)" = 1 ]
check "and never fewer than one" [ "$(nproc --ignore=5)" = 1 ]
check "nproc --all" [ "$(nproc --all)" -ge 1 ]

# --- kill ------------------------------------------------------------------------------------
sleep 30 &
pid=$!
check "kill -0 sees a process" /bin/kill -0 $pid
check "kill sends TERM" /bin/kill $pid
wait $pid
check "which ended it" [ $? -eq 143 ]
check "kill -l names a status" [ "$(/bin/kill -l 143)" = TERM ]
check "kill -l lists the signals" sh -c '/bin/kill -l | grep -q "HUP INT QUIT"'
sleep 30 &
pid=$!
check "kill -s KILL" /bin/kill -s KILL $pid
wait $pid
check "which ended it" [ $? -eq 137 ]
check "kill refuses an unknown signal" status_is 2 /bin/kill -BOGUS 1

# --- test and [ ------------------------------------------------------------------------------
check "test -d" /bin/test -d /
check "[ -f ]" /bin/[ -f a ]
check "[ without ] is an error" status_is 2 /bin/[ -f a
check "a false test is 1" status_is 1 /bin/test -d a
check "an expression with -a, -o and parentheses" /bin/test \( 1 -eq 2 -o a = a \) -a -n x
check "a bad number is an error" status_is 2 /bin/test x -lt 1

# --- chmod -----------------------------------------------------------------------------------
touch f
chmod 640 f
check "chmod with an octal mode" [ "$(perms f)" = -rw-r----- ]
chmod u+x,g=u f
check "chmod with a symbolic mode" [ "$(perms f)" = -rwxrwx--- ]
chmod a+X f
check "X gives execute to all when someone has it" [ "$(perms f)" = -rwxrwx--x ]
chmod 644 f
chmod +w f
check "no who: the umask (022) holds" [ "$(perms f)" = -rw-r--r-- ]
mkdir -p tree/sub && touch tree/sub/g
chmod -R go-rwx tree
check "chmod -R" [ "$(perms tree/sub/g)" = -rw------- ]
check "on directories too" [ "$(perms tree/sub)" = drwx------ ]
check "chmod -v names the file" [ "$(chmod -v 600 f)" = f ]
check "chmod refuses a bad mode" status_is 1 chmod u+q f

# touch(1): POSIX's -a -m -c -r -t -d (CLEANUP.md: it took only -c). `date -r` reads the
# modification time (BusyBox stat has no -c here).
mtime() { date -u -r "$1" +%s; }
check "touch -t sets the time" env TZ=UTC0 touch -t 202001021530.45 tt
check "to that local time" [ "$(mtime tt)" = 1577979045 ]
check "touch -a -t changes only the access time" env TZ=UTC0 touch -a -t 199901010000 tt
check "leaving the modification time" [ "$(mtime tt)" = 1577979045 ]
check "touch -d in UTC" touch -m -d 2021-03-04T05:06:07Z tt
check "sets the modification time" [ "$(mtime tt)" = 1614834367 ]
check "touch -r copies another file's times" touch -r tt tt2
check "the modification time too" [ "$(mtime tt2)" = 1614834367 ]
check "touch -c doesn't create" touch -c tt-none
check "nothing made" not /bin/test -e tt-none
check "touch refuses an unknown flag" status_is 1 touch -x tt3
check "and makes no file named after it" not /bin/test -e tt3
check "touch refuses an impossible date" status_is 1 touch -t 202002300000 tt
check "touch -- creates a file named like a flag" touch -- -dash
check "named so" /bin/test -f ./-dash

# --- mount, umount (nmount(2)) and /etc/fstab ------------------------------------------------
mkdir -p $T/m1 $T/m2 $T/src
echo seen > $T/src/f
check "mount -t tmpfs" mount -t tmpfs tmpfs $T/m1
check "a fresh, empty file system" [ -z "$(ls $T/m1)" ]
check "listed by mount" sh -c "mount | grep -q 'tmpfs on $T/m1 (tmpfs, local)'"
check "mount -t nullfs shows a directory again" mount -t nullfs $T/src $T/m2
check "with its contents" [ "$(cat $T/m2/f)" = seen ]
check "umount by node" umount $T/m2
check "after which the contents are gone" not /bin/test -e $T/m2/f
check "mount --bind is nullfs" mount --bind $T/src $T/m2
check "umount by special" umount $T/src
check "umount -v" [ "$(umount -v $T/m1)" = "$T/m1: unmounted" ]
check "an unknown type is refused" status_is 1 mount -t nosuchfs x $T/m1
check "with the kernel's reason" sh -c "mount -t nosuchfs x $T/m1 2>&1 | grep -q 'unknown file system type'"
check "an unsupported option is refused" sh -c "mount -t tmpfs -o nosuchopt tmpfs $T/m1 2>&1 | grep -q 'an option this file system doesn'"
check "a read-only mount" mount -t tmpfs -o ro tmpfs $T/m1
check "refuses writes (EROFS)" not sh -c ": > $T/m1/f" 2>/dev/null
check "mount -u -w makes it read-write" mount -u -w $T/m1
check "and writable" sh -c ": > $T/m1/f"
check "umount the read-only one" umount $T/m1
check "nosuid is accepted" mount -t tmpfs -o nosuid tmpfs $T/m1
check "and shown in /proc/mounts" grep -q "$T/m1 tmpfs rw,nosuid" /proc/mounts
check "umount the nosuid tmpfs" umount $T/m1
cp /etc/fstab $T/fstab.saved
printf 'tmpfs %s tmpfs rw 0 0\n%s %s nullfs rw,noauto 0 0\n' $T/m1 $T/src $T/m2 >> /etc/fstab
check "mount -a mounts fstab's entries" mount -a
check "but not noauto ones" not sh -c "mount | grep -q ' on $T/m2 '"
check "mount node uses its fstab line" mount $T/m2
check "umount -a unmounts them" umount -a
check "all of them" not sh -c "mount | grep -q ' on $T/m[12] '"
cp $T/fstab.saved /etc/fstab

# The VFS (OxideBSD-doc VFS.md §10): what oxfs's own lookup got wrong before the kernel's namei.
V=$T/vfs
mkdir -p $V/src/a/b $V/mnt $V/tm $V/root/bin
check "nullfs: mount a directory from elsewhere" mount -t nullfs $V/src/a $V/mnt
check "nullfs: .. at its root is the mount point's parent" [ "$(cd -P $V/mnt/.. && /bin/pwd)" = "$V" ]
check "nullfs: getcwd inside it" [ "$(cd -P $V/mnt/b && /bin/pwd)" = "$V/mnt/b" ]
check "nullfs: unmount" umount $V/mnt
check "tmpfs: mount" mount -t tmpfs tmpfs $V/tm
mkdir -p $V/tm/x
check "tmpfs: getcwd inside it" [ "$(cd -P $V/tm/x && /bin/pwd)" = "$V/tm/x" ]
check "unmount refused while a cwd is on it" not sh -c "cd $V/tm/x && umount $V/tm 2>/dev/null"
echo z > $V/tm/z
check "a hard link across mounts is refused" not ln $V/tm/z $V/z 2>/dev/null
check "tmpfs: unmount" umount $V/tm
check "/./proc is /proc" /bin/test -e /./proc/meminfo
ln -s /proc $V/p
check "a link to /proc reaches it" /bin/test -e $V/p/meminfo
cp /bin/test $V/root/bin/test
check "chroot runs a program inside" chroot $V/root /bin/test -e /bin/test
check "chroot hides /proc" not chroot $V/root /bin/test -e /proc/meminfo
long=
i=0
while [ $i -lt 200 ]; do long="$long./"; i=$((i + 1)); done
long="${long}f"
echo hi > $V/f
ln -s "$long" $V/ll
check "a link's 401-byte target is kept whole" [ "$(readlink $V/ll)" = "$long" ]
check "and followed" [ "$(cat $V/ll)" = hi ]
cp /bin/sleep $V/sl
$V/sl 3 &
sl=$!
/bin/sleep 1
check "a running program can't be opened for writing" not sh -c ": > $V/sl" 2>/dev/null
kill $sl
wait $sl 2>/dev/null
cp /bin/true $V/tr
check "a program open for writing can't run" not sh -c "exec 3>>$V/tr; $V/tr" 2>/dev/null
check "and can once it's closed" $V/tr
mkdir -p $V/tf
mount -t tmpfs tmpfs $V/tf
echo kept > $V/tf/f
(cd $V/tf && exec 3<$V/tf/f && /bin/sleep 3) &
busy=$!
/bin/sleep 1
check "umount of a busy file system is refused" not umount $V/tf 2>/dev/null
check "umount -f takes it anyway" umount -f $V/tf
check "and what was under it shows again" not /bin/test -e $V/tf/f
wait $busy 2>/dev/null
check "mount lists through getvfsstat" sh -c "mount | grep -q ' on /proc '"

# nullfs (nullfs(5), its own module over any type since VFS step 3d).
N=$T/nullx
mkdir -p $N/t $N/n $N/d $N/p $N/ro
mount -t tmpfs tmpfs $N/t
mkdir $N/t/sub
echo below > $N/t/sub/f
check "nullfs over a tmpfs" mount -t nullfs $N/t $N/n
check "nullfs: shows its files" [ "$(cat $N/n/sub/f)" = below ]
echo above > $N/n/sub/g
check "nullfs: a file made through it is below" [ "$(cat $N/t/sub/g)" = above ]
check "nullfs: has its own st_dev" [ "$(stat -t $N/n/sub/f | cut -d" " -f7)" != "$(stat -t $N/t/sub/f | cut -d" " -f7)" ]
check "nullfs: keeps the file's serial number" sh -c "a=\$(stat -t $N/n/sub/f | cut -d' ' -f8); b=\$(stat -t $N/t/sub/f | cut -d' ' -f8); [ \"\$a\" = \"\$b\" ] || { echo \"ino \$a vs \$b\"; false; }"
check "nullfs: a hard link to the lower path is EXDEV" not ln $N/n/sub/f $N/t/sub/h 2>/dev/null
rm $N/n/sub/g
check "nullfs: removing through it removes below" [ ! -e $N/t/sub/g ]
check "nullfs: the lower file system is busy" not umount $N/t 2>/dev/null
cp /bin/true $N/n/tr
check "nullfs: runs programs" $N/n/tr
check "nullfs: flock through it conflicts with the lower path" flock -n $N/t/sub/f sh -c "! flock -n $N/n/sub/f true"
check "nullfs: unmount" umount $N/n
check "nullfs: then the tmpfs" umount $N/t
check "nullfs over devfs" mount -t nullfs /dev $N/d
check "nullfs: devices open through it" sh -c "echo x > $N/d/null"
check "nullfs: unmount the devfs one" umount $N/d
check "nullfs over procfs" mount -t nullfs /proc $N/p
check "nullfs: /proc through it" [ -e $N/p/meminfo ]
check "nullfs: unmount the procfs one" umount $N/p
mkdir -p $N/src
echo ro > $N/src/f
check "nullfs: ro" mount -t nullfs -o ro $N/src $N/ro
check "nullfs: refuses writes through it" not sh -c ": > $N/ro/g" 2>/dev/null
check "nullfs: while the lower path takes them" sh -c ": > $N/src/g"
check "nullfs: unmount the ro one" umount $N/ro

# tmpfs (tmpfs(5), its own module since VFS step 3b).
X=$T/tmpx
mkdir -p $X/a $X/b
chmod 0750 $X/a
check "tmpfs: unknown options are refused" not mount -t tmpfs -o bogus=1 tmpfs $X/a 2>/dev/null
check "tmpfs: mount with a size" mount -t tmpfs -o size=1m tmpfs $X/a
check "tmpfs: the root takes the covered directory's mode" [ "$(perms $X/a)" = drwxr-x--- ]
check "tmpfs: mount_tmpfs, with mode=" /sbin/mount_tmpfs -o mode=1777 tmpfs $X/b
check "tmpfs: mode= sets the root's mode" [ "$(perms $X/b)" = drwxrwxrwt ]
check "tmpfs: each mount has its own st_dev" [ "$(stat -t $X/a | cut -d" " -f7)" != "$(stat -t $X/b | cut -d" " -f7)" ]
check "tmpfs: df shows it" sh -c "df $X/a | grep -q '^tmpfs'"
check "tmpfs: a write past size= fails" not dd if=/dev/zero of=$X/a/big bs=4096 count=512 2>/dev/null
rm -f $X/a/big
check "tmpfs: and the space comes back" dd if=/dev/zero of=$X/a/big bs=4096 count=128 2>/dev/null
rm -f $X/a/big
check "tmpfs: mount -u -o size= grows it" mount -u -o size=4m $X/a
check "tmpfs: to the new size" dd if=/dev/zero of=$X/a/big bs=4096 count=512 2>/dev/null
check "tmpfs: and won't shrink below what's in use" not mount -u -o size=1m $X/a 2>/dev/null
rm -f $X/a/big
printf abc > $X/a/sparse
truncate -s 20000 $X/a/sparse
check "tmpfs: a hole reads as zeros" [ "$(dd if=$X/a/sparse bs=1 skip=3 count=4 2>/dev/null | tr -d '\000' | wc -c)" -eq 0 ]
check "tmpfs: and its size is kept" [ "$(wc -c < $X/a/sparse)" -eq 20000 ]
truncate -s 1 $X/a/sparse
truncate -s 3 $X/a/sparse
check "tmpfs: shrinking then growing reads zeros" [ "$(tr -d '\000' < $X/a/sparse)" = a ]
echo still > $X/a/open
(exec 3<$X/a/open; rm $X/a/open; /bin/sleep 1; cat <&3 > $X/a/read) 
check "tmpfs: an unlinked file stays readable while open" [ "$(cat $X/a/read)" = still ]
mkdir $X/a/d1 $X/a/d1/d2
check "tmpfs: a directory's link count counts subdirectories" [ "$(stat -t $X/a/d1 | cut -d" " -f9)" = 3 ]
for i in 1 2 3 4 5 6 7 8 9 10; do : > $X/a/d1/f$i; done
rm $X/a/d1/f3 $X/a/d1/f7
check "tmpfs: readdir after removals" [ "$(ls $X/a/d1 | wc -l)" = 9 ]
check "tmpfs: rmdir of a full directory is refused" not rmdir $X/a/d1 2>/dev/null
cp /bin/true $X/a/tr
check "tmpfs: programs run from it" $X/a/tr
check "tmpfs: noexec stops them" mount -t tmpfs -o noexec tmpfs $X/b
cp /bin/true $X/b/tr
check "tmpfs: as on the BSDs" not $X/b/tr 2>/dev/null
check "tmpfs: unmount the noexec one" umount $X/b
check "tmpfs: unmount the mode= one" umount $X/b
check "tmpfs: unmount, after running a program from it" umount $X/a
check "tmpfs: vfs.tmpfs.memory_reserved" [ "$(/sbin/sysctl -n vfs.tmpfs.memory_reserved)" -gt 0 ]

cd /
rm -rf $T

# The native /bin rewrites' own checks (each prints its lines and a count).
check "bin1: echo true false pwd mkdir rm ln realpath hostname timeout mknod" sh /usr/tests/bin/bin1.sh
check "bin2: cat ls cp mv dd df date stty" sh /usr/tests/bin/bin2.sh
check "bin3: grep sed ed expr" sh /usr/tests/bin/bin3.sh
check "bin4: gzip tar" sh /usr/tests/bin/bin4.sh </dev/null
check "bin5: ps pgrep pkill ping" sh /usr/tests/bin/bin5.sh
check "net: ifconfig route dhclient" sh /usr/tests/bin/net.sh </dev/null

echo "bin-smoke: $fail failed"
[ $fail -eq 0 ]
