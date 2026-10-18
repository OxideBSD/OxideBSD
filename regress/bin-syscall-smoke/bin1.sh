#!/bin/sh
#
# On-target check for echo, true, false, pwd, mkdir, rm, ln, realpath, hostname, timeout and
# mknod, rewritten in Rust std. Runs as root under /bin/sh; prints one line per check and exits 0
# if all pass. The programs under test are named by path ($BIN, $SBIN; /bin and /sbin by
# default), since the shell has built-ins called echo, pwd, true and false.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022
BIN=${BIN:-/bin}
SBIN=${SBIN:-/sbin}

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin1: ok: $_desc"
	else
		echo "bin1: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
perms() { ls -ld "$1" | cut -c1-10; }
T=${T:-/tmp/bin1}
rm -rf $T
mkdir -p $T
cd $T

# --- true, false -----------------------------------------------------------------------------
check "true" $BIN/true
check "true ignores its arguments" $BIN/true --bogus -x
check "false" status_is 1 $BIN/false
check "false ignores its arguments" status_is 1 $BIN/false --help

# --- echo ------------------------------------------------------------------------------------
check "echo joins with spaces" [ "$($BIN/echo a  b c)" = "a b c" ]
check "echo -n leaves the newline off" [ "$($BIN/echo -n x; $BIN/echo y)" = xy ]
check "echo takes only one -n" [ "$($BIN/echo -n -n x)" = "-n x" ]
check "echo -e is no option" [ "$($BIN/echo -e 'a\tb')" = '-e a\tb' ]
check "echo -- is written" [ "$($BIN/echo -- x)" = "-- x" ]
check "echo with no arguments writes a newline" [ "$($BIN/echo | wc -c | tr -d ' ')" = 1 ]
check "a last \\c drops the newline" [ "$($BIN/echo a 'b\c'; $BIN/echo z)" = "a bz" ]
check "\\c elsewhere is kept" [ "$($BIN/echo 'a\c' b)" = 'a\c b' ]

# --- pwd ------------------------------------------------------------------------------------
mkdir -p $T/real
ln -s real $T/sym
cd $T/sym
check "pwd -L writes \$PWD" [ "$(PWD=$T/sym $BIN/pwd -L)" = $T/sym ]
check "pwd defaults to -L" [ "$(PWD=$T/sym $BIN/pwd)" = $T/sym ]
check "pwd -P resolves links" [ "$(PWD=$T/sym $BIN/pwd -P)" = $T/real ]
check "the last of -L and -P counts" [ "$(PWD=$T/sym $BIN/pwd -L -P)" = $T/real ]
check "pwd ignores a wrong \$PWD" [ "$(PWD=/ $BIN/pwd)" = $T/real ]
check "pwd ignores a \$PWD with .." [ "$(PWD=$T/real/../sym $BIN/pwd)" = $T/real ]
check "pwd ignores a relative \$PWD" [ "$(PWD=sym $BIN/pwd)" = $T/real ]
check "pwd refuses operands" status_is 1 $BIN/pwd x
cd $T

# --- mkdir ----------------------------------------------------------------------------------
check "mkdir" $BIN/mkdir m1
check "mkdir gives 0777 less the umask" [ "$(perms m1)" = drwxr-xr-x ]
check "mkdir refuses an existing directory" status_is 1 $BIN/mkdir m1
check "mkdir -p accepts one" $BIN/mkdir -p m1
check "mkdir without -p needs the parent" status_is 1 $BIN/mkdir m2/a
check "mkdir -p makes the parents" $BIN/mkdir -p m2/a/b
check "mkdir -v names what it makes" [ "$($BIN/mkdir -pv m3/a/b | tr '\n' ' ')" = "m3 m3/a m3/a/b " ]
check "mkdir -m sets the mode exactly" $BIN/mkdir -m 1750 m4
check "with the sticky bit" [ "$(perms m4)" = drwxr-x--T ]
check "mkdir -m takes symbolic modes" $BIN/mkdir -m go-rwx m5
check "from a=rwx" [ "$(perms m5)" = drwx------ ]
check "mkdir refuses a bad mode" status_is 1 $BIN/mkdir -m 999 m6
check "and makes nothing" not test -e m6
check "mkdir -p -m applies to the last" $BIN/mkdir -p -m 700 m7/a
check "parents get the umask's mode" [ "$(perms m7)" = drwxr-xr-x ]
check "the last the mode" [ "$(perms m7/a)" = drwx------ ]
check "-p parents keep u+wx under a strict umask" sh -c "umask 0377; $BIN/mkdir -p m8/a"
check "the parent" [ "$(perms m8)" = drwx------ ]
check "the last" [ "$(perms m8/a)" = dr-------- ]
chmod 700 m8/a
: > file
check "mkdir -p refuses a file in the way" status_is 1 $BIN/mkdir -p file/a
check "mkdir -p refuses a file as the last" status_is 1 $BIN/mkdir -p file
check "mkdir: prog: path: strerror" [ "$($BIN/mkdir m1 2>&1)" = "mkdir: m1: File exists" ]
check "mkdir with no operand is a usage error" status_is 1 $BIN/mkdir
check "mkdir -- -dash" $BIN/mkdir -- -dash
check "made" test -d ./-dash

# --- rm -------------------------------------------------------------------------------------
mkdir r && cd r
: > a
check "rm removes a file" $BIN/rm a
check "gone" not test -e a
check "rm complains about a missing file" status_is 1 $BIN/rm a
check "rm: prog: path: strerror" [ "$($BIN/rm a 2>&1)" = "rm: a: No such file or directory" ]
check "rm -f doesn't" $BIN/rm -f a
check "rm -f with no operand" $BIN/rm -f
check "rm with no operand is a usage error" status_is 1 $BIN/rm
mkdir d
check "rm refuses a directory" status_is 1 $BIN/rm d
check "rm: is a directory" [ "$($BIN/rm d 2>&1)" = "rm: d: is a directory" ]
check "rm -d removes an empty one" $BIN/rm -d d
mkdir -p t/u/v && : > t/f && : > t/u/g && ln -s /etc t/link
check "rm -d refuses a full one" status_is 1 $BIN/rm -d t
check "rm -rv removes a tree, depth first" [ "$($BIN/rm -rv t | tr '\n' ' ')" = "t/f t/link t/u/g t/u/v t/u t " ]
check "without following links" test -f /etc/passwd
mkdir -p t2/x && : > t2/x/y
check "rm -R" $BIN/rm -R t2
check "gone" not test -e t2
mkdir dots
check "rm refuses ." status_is 1 $BIN/rm -rf .
check "rm refuses dots/.." status_is 1 $BIN/rm -rf dots/..
check "rm refuses dots/./" status_is 1 $BIN/rm -rf dots/./
check "rm refuses /" status_is 1 $BIN/rm -rf /
check "rm refuses //" status_is 1 $BIN/rm -rf //
check "with a diagnostic" [ "$($BIN/rm -rf . 2>&1)" = 'rm: "." and ".." may not be removed' ]
check "everything still there" test -d dots -a -d /etc
: > keep && : > go
check "rm -i asks, and n keeps" sh -c "echo n | $BIN/rm -i keep 2>/dev/null"
check "kept" test -e keep
check "the question" [ "$(echo n | $BIN/rm -i keep 2>&1)" = "remove keep? " ]
check "rm -i asks, and y removes" sh -c "echo y | $BIN/rm -i go 2>/dev/null"
check "removed" not test -e go
check "rm -f cancels -i" sh -c "$BIN/rm -if keep < /dev/null"
check "removed" not test -e keep
: > a1 && : > a2 && : > a3 && : > a4
check "rm -I asks before four files" sh -c "echo n | $BIN/rm -I a1 a2 a3 a4 2>/dev/null; [ \$? -eq 1 ]"
check "all kept" test -e a1 -a -e a4
check "the question" [ "$(echo n | $BIN/rm -I a1 a2 a3 a4 2>&1)" = "remove 4 files? " ]
check "rm -I doesn't ask for three" sh -c "$BIN/rm -I a1 a2 a3 < /dev/null"
mkdir -p q/r && : > q/s
check "rm -rI asks about a tree" [ "$(echo n | $BIN/rm -rI q a4 2>&1)" = "recursively remove q and 1 file? " ]
check "rm -rI, y" sh -c "echo y | $BIN/rm -rI q a4 2>/dev/null"
check "gone" not test -e q -o -e a4
mkdir -p ri/sub && : > ri/sub/f
check "rm -ri, n at the top keeps the tree" sh -c "echo n | $BIN/rm -ri ri 2>/dev/null"
check "kept" test -e ri/sub/f
check "rm -P is accepted" sh -c ": > p; $BIN/rm -P p && ! test -e p"
check "rm -- -file" sh -c ": > ./-file; $BIN/rm -- -file && ! test -e ./-file"
mkdir -p nr/w && : > nr/w/z && chmod 0 nr/w
# (Root reads a mode-0 directory anyway: then there is nothing to check.)
if ls nr/w > /dev/null 2>&1; then
	echo "bin1: ok: rm on an unreadable directory skipped (privileged)"
else
	check "rm -rf fails on what it can't read" status_is 1 $BIN/rm -rf nr
fi
chmod 700 nr/w
mkdir nr/e && chmod 0 nr/e
check "an unreadable empty directory goes" $BIN/rm -rf nr
check "rm -z is a usage error" status_is 1 $BIN/rm -z x
if mkdir -p xd/mnt && mount -t tmpfs tmpfs xd/mnt 2>/dev/null; then
	: > xd/mnt/inside && : > xd/outside
	check "rm -rx doesn't cross a mount point" status_is 1 $BIN/rm -rfx xd
	check "the mounted file system is untouched" test -e xd/mnt/inside
	check "the rest went" not test -e xd/outside
	umount xd/mnt
else
	echo "bin1: ok: rm -x skipped (no tmpfs mount)"
fi
cd $T

# --- ln -------------------------------------------------------------------------------------
mkdir l && cd l
echo data > a
check "ln makes a hard link" $BIN/ln a b
check "to the same file" test a -ef b
check "ln refuses an existing target" status_is 1 $BIN/ln a b
check "ln: prog: path: strerror" [ "$($BIN/ln a b 2>&1)" = "ln: b: File exists" ]
check "ln -f replaces it" $BIN/ln -f a b
check "ln refuses linking a name to itself" status_is 1 $BIN/ln -f a a
check "a is still there" test -f a
check "ln -s" $BIN/ln -s a s
check "a symbolic link" [ "$(readlink s)" = a ]
check "ln -sf replaces it" $BIN/ln -sf b s
check "pointing at b" [ "$(readlink s)" = b ]
check "ln -v" [ "$($BIN/ln -v a c)" = "c => a" ]
check "ln -sv" [ "$($BIN/ln -sv a sv)" = "sv -> a" ]
mkdir d
check "ln into a directory" $BIN/ln a b d
check "both there" test d/a -ef a -a d/b -ef a
check "ln src... with a file last is a usage error" status_is 1 $BIN/ln a b c
check "ln refuses a hard link to a directory" status_is 1 $BIN/ln d dlink
mkdir e && ln -s e el
check "ln -s into a link to a directory" $BIN/ln -s /x el
check "goes inside" [ "$(readlink e/x)" = /x ]
check "ln -sfh replaces the link instead" $BIN/ln -sfh a el
check "el now names a" [ "$(readlink el)" = a ]
ln -s e el2
check "ln -sfn is the same" $BIN/ln -sfn a el2
check "el2 now names a" [ "$(readlink el2)" = a ]
check "ln with one operand links into ." sh -c "cd d && $BIN/ln -s ../c && [ \"\$(readlink c)\" = ../c ]"
ln -s a sa
check "ln -P links the symbolic link" $BIN/ln -P sa hp
check "a link" test -h hp
check "ln -L (default) what it names" $BIN/ln sa hl
check "a file" not test -h hl
check "ln -i asks, n keeps" sh -c "echo n | $BIN/ln -i b c 2>/dev/null; [ \$? -eq 1 ]"
check "the question" [ "$(echo n | $BIN/ln -i b c 2>&1)" = "replace c? not replaced" ]
check "ln -i, y replaces" sh -c "echo y | $BIN/ln -i b c 2>/dev/null"
check "ln -sw warns of a missing source" [ "$($BIN/ln -sw nothere w 2>&1)" = "ln: warning: nothere: No such file or directory" ]
check "but makes the link" test -h w
check "ln -sw is quiet for one that exists" [ -z "$($BIN/ln -sw a w2 2>&1)" ]
mkdir emptydir
check "ln -sF replaces an empty directory" $BIN/ln -sF a emptydir
check "with the link" test -h emptydir
check "ln -z is a usage error" status_is 1 $BIN/ln -z a z
cd $T

# --- realpath -------------------------------------------------------------------------------
check "realpath resolves links and dots" [ "$($BIN/realpath sym/../real/.)" = $T/real ]
check "realpath with no operand" [ "$(cd real && $BIN/realpath)" = $T/real ]
check "realpath several" [ "$($BIN/realpath / real | tr '\n' ' ')" = "/ $T/real " ]
check "realpath fails on a missing path" status_is 1 $BIN/realpath nothere
check "realpath: prog: path: strerror" [ "$($BIN/realpath nothere 2>&1)" = "realpath: nothere: No such file or directory" ]
check "realpath -q is quiet" [ -z "$($BIN/realpath -q nothere 2>&1)" ]
check "realpath -q still fails" status_is 1 $BIN/realpath -q nothere
check "realpath goes on after a failure" [ "$($BIN/realpath -q nothere / 2>&1)" = / ]

# --- hostname -------------------------------------------------------------------------------
old=$($BIN/hostname)
check "hostname sets the name" $BIN/hostname bin1.example.org
check "hostname" [ "$($BIN/hostname)" = bin1.example.org ]
check "hostname -s" [ "$($BIN/hostname -s)" = bin1 ]
check "hostname -d" [ "$($BIN/hostname -d)" = example.org ]
check "hostname -f is accepted" [ "$($BIN/hostname -f)" = bin1.example.org ]
check "hostname -s -d is a usage error" status_is 1 $BIN/hostname -s -d
check "hostname a b is a usage error" status_is 1 $BIN/hostname a b
$BIN/hostname nodot
check "hostname -d without a dot is the name" [ "$($BIN/hostname -d)" = nodot ]
$BIN/hostname "$old"
check "hostname restored" [ "$($BIN/hostname)" = "$old" ]

# --- timeout --------------------------------------------------------------------------------
check "timeout runs a command" status_is 0 $BIN/timeout 5 $BIN/true
check "and gives its status" status_is 7 $BIN/timeout 5 sh -c 'exit 7'
check "timeout ends a slow one: 124" status_is 124 $BIN/timeout 0.2 sleep 10
check "with a suffix" status_is 124 $BIN/timeout 0.005m sleep 10
check "timeout 0 is no limit" status_is 0 $BIN/timeout 0 sleep 0.2
check "timeout -p keeps the status: 128+TERM" status_is 143 $BIN/timeout -p 0.2 sleep 10
check "timeout -s KILL -p" status_is 137 $BIN/timeout -s KILL -p 0.2 sleep 10
check "timeout --signal=INT -p" status_is 130 $BIN/timeout --signal=INT --preserve-status 0.2 sleep 10
check "timeout -k kills what ignores TERM" status_is 124 $BIN/timeout -k 0.3 0.2 sh -c 'trap "" TERM; sleep 10'
check "a command killed by a signal kills timeout alike" status_is 138 $BIN/timeout 5 sh -c 'kill -USR1 $$'
check "timeout -f" status_is 124 $BIN/timeout -f 0.2 sleep 10
check "timeout -v reports" sh -c "$BIN/timeout -v 0.2 sleep 10 2>&1 | grep -q 'sending signal TERM(15)'"
check "a missing command: 127" status_is 127 $BIN/timeout 5 /nonexistent
check "one that can't run: 126" status_is 126 $BIN/timeout 5 /etc
check "a bad duration: 125" status_is 125 $BIN/timeout 1x sleep 1
check "a bad signal: 125" status_is 125 $BIN/timeout -s BOGUS 1 sleep 1
check "a missing command operand: 125" status_is 125 $BIN/timeout 1
check "timeout passes TERM on" sh -c "$BIN/timeout 10 sleep 10 & p=\$!; sleep 0.3; kill \$p; wait \$p; [ \$? -eq 143 ]"

# --- mknod ----------------------------------------------------------------------------------
check "mknod c" $SBIN/mknod $T/cdev c 1 3
check "a character device" test -c $T/cdev
check "mode 0666 less the umask" [ "$(perms $T/cdev)" = crw-r--r-- ]
check "mknod b with an owner" $SBIN/mknod $T/bdev b 0x2 010 0:0
check "a block device" test -b $T/bdev
check "mknod refuses another type" status_is 1 $SBIN/mknod $T/x p 1 2
check "mknod refuses a bad number" status_is 1 $SBIN/mknod $T/x c 1 zz
check "mknod needs the group with the owner" status_is 1 $SBIN/mknod $T/x c 1 2 root:
check "mknod with three operands is a usage error" status_is 1 $SBIN/mknod $T/x c 1
check "mknod refuses an existing name" status_is 1 $SBIN/mknod $T/cdev c 1 3

cd /
rm -rf $T
echo "bin1: $fail failed"
[ $fail -eq 0 ]
