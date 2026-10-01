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
check "an unsupported option is refused" sh -c "mount -t tmpfs -o ro tmpfs $T/m1 2>&1 | grep -q 'options and flags'"
cp /etc/fstab $T/fstab.saved
printf 'tmpfs %s tmpfs rw 0 0\n%s %s nullfs rw,noauto 0 0\n' $T/m1 $T/src $T/m2 >> /etc/fstab
check "mount -a mounts fstab's entries" mount -a
check "but not noauto ones" not sh -c "mount | grep -q ' on $T/m2 '"
check "mount node uses its fstab line" mount $T/m2
check "umount -a unmounts them" umount -a
check "all of them" not sh -c "mount | grep -q ' on $T/m[12] '"
cp $T/fstab.saved /etc/fstab

cd /
rm -rf $T
echo "bin-smoke: $fail failed"
[ $fail -eq 0 ]
