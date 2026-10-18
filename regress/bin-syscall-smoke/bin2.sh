#!/bin/sh
#
# On-target check for the second batch of /bin utilities rewritten in Rust std: cat, ls, cp, mv,
# dd, df, date and stty. Prints one line per check and exits 0 if all pass. Runs as root on
# OxideBSD; it also runs as an ordinary user elsewhere (BIN2_PATH names a directory of the
# binaries under test, put ahead of the system's).

PATH=${BIN2_PATH:+$BIN2_PATH:}/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin2: ok: $_desc"
	else
		echo "bin2: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
skip() { echo "bin2: skip: $1"; }
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
same() { [ "$1" = "$2" ]; }
perms() { ls -ld "$1" | cut -c1-10; }
# Modification time in seconds (BusyBox stat has no -c here; date -r is checked against a
# known time below).
mtime() { date -r "$1" +%s; }
T=/tmp/bin2
rm -rf $T
mkdir -p $T
cd $T || exit 1

# --- cat -------------------------------------------------------------------------------------
printf 'a\n\n\n\nb\tc\001\n' > c1
printf 'x\n' > c2
check "cat copies files in order" same "$(cat c2 c2)" "$(printf 'x\nx')"
check "cat - reads stdin" same "$(echo in | cat c2 - c2)" "$(printf 'x\nin\nx')"
check "cat with no file reads stdin" same "$(echo in | cat)" in
check "cat -n numbers lines" same "$(cat -n c2 c2)" "$(printf '     1\tx\n     2\tx')"
check "cat -b skips empty lines" same "$(cat -b c1 | head -n 2)" "$(printf '     1\ta\n')"
check "cat -s squeezes empty lines" same "$(cat -s c1 | wc -l | tr -d ' ')" 3
check "cat -e marks line ends" same "$(cat -e c2)" 'x$'
check "cat -t shows tabs and control characters" same "$(cat -t c1 | tail -n 1)" 'b^Ic^A'
check "cat -v shows the high bit as M-" same "$(printf '\351\177' | cat -v)" 'M-i^?'
check "cat -u passes data through" same "$(cat -u c2)" x
check "cat reports a missing file" same "$(cat nope 2>&1)" "cat: nope: No such file or directory"
check "and fails" status_is 1 cat nope
check "but still copies the rest" same "$(cat nope c2 2>/dev/null)" x
check "cat refuses an unknown option" status_is 1 cat -x c2

# --- ls --------------------------------------------------------------------------------------
mkdir L
cd L
printf 1 > a
printf 12345 > b
printf 123 > c
mkdir d
touch d/inner
ln -s a l
cd $T
check "ls lists one per line off a terminal" same "$(ls L)" "$(printf 'a\nb\nc\nd\nl')"
check "ls -r reverses" same "$(ls -r L | head -n 1)" l
check "ls -S sorts by size" same "$(ls -S L/a L/b L/c | tr '\n' ' ')" "L/b L/c L/a "
TZ=UTC0 touch -t 202001010000 L/c
TZ=UTC0 touch -t 202101010000 L/a
TZ=UTC0 touch -t 202201010000 L/b
check "ls -t sorts by time, newest first" same "$(ls -t L | tail -n 3 | tr '\n' ' ')" "b a c "
check "ls -tr reverses that" same "$(ls -tr L | head -n 1)" c
touch L/.hidden
check "ls -a shows dot files, . and .." same "$(ls -a L | head -n 3 | tr '\n' ' ')" ". .. .hidden "
check "ls -A shows dot files without . and .." same "$(ls -A L | head -n 2 | tr '\n' ' ')" ".hidden a "
check "ls -f doesn't sort, but shows all" sh -c 'ls -f L | grep -q "^\.\.$"'
rm L/.hidden
check "ls -d lists the directory itself" same "$(ls -d L)" L
check "ls -F marks types" same "$(ls -F L | tr '\n' ' ')" "a b c d/ l@ "
chmod 755 L/c
check "and executables" same "$(ls -F L/c)" "L/c*"
chmod 644 L/c
check "ls -p marks directories" same "$(ls -p L | tr '\n' ' ')" "a b c d/ l "
check "ls -m makes a comma list" same "$(ls -m L)" "a, b, c, d, l"
check "ls -C makes columns down" same "$(COLUMNS=20 ls -C L)" "$(printf 'a\td\nb\tl\nc')"
check "ls -x makes columns across" same "$(COLUMNS=20 ls -x L)" "$(printf 'a\tb\nc\td\nl')"
check "ls -1 overrides -C" same "$(ls -C1 L | wc -l | tr -d ' ')" 5
chmod 640 L/a
check "ls -l shows the mode" same "$(ls -l L/a | cut -c1-10)" -rw-r-----
check "and the size" same "$(ls -l L/b | awk '{print $5}')" 5
check "and a link's target" sh -c 'ls -l L/l | grep -q " L/l -> a$"'
check "ls -l totals a directory" sh -c 'ls -l L | head -n 1 | grep -q "^total [0-9]"'
check "ls -n shows numeric ids" same "$(ls -n L/a | awk '{print $3}')" "$(id -u)"
check "ls -g leaves out the owner" same "$(ls -lg L/a | wc -w | tr -d ' ')" 8
check "ls -o leaves out the group" same "$(ls -lo L/a | wc -w | tr -d ' ')" 8
check "ls -l writes an old date with its year" same "$(TZ=UTC0 ls -l L/c | awk '{print $6, $7, $8}')" "Jan 1 2020"
check "ls -T writes the time in full" same "$(TZ=UTC0 ls -lT L/b | awk '{print $6, $7, $8, $9}')" "Jan 1 00:00:00 2022"
check "ls -i shows inode numbers" sh -c 'ls -i L/a | grep -q "^ *[0-9][0-9]* L/a$"'
check "ls -s shows block counts" sh -c 'ls -s L/b | grep -q "^ *[0-9][0-9]* L/b$"'
dd if=/dev/zero of=L/k bs=1024 count=2 2>/dev/null
check "ls -lh writes sizes with units" same "$(ls -lh L/k | awk '{print $5}')" 2.0K
rm L/k
check "ls -L follows links" same "$(ls -lL L/l | cut -c1)" -
check "ls follows a link named on the command line" same "$(ls L/l)" L/l
ln -s d L/dl
check "into a directory" same "$(ls L/dl)" inner
check "but not with -l" sh -c 'ls -l L/dl | grep -q "^l"'
check "ls -R goes into subdirectories" sh -c 'ls -R L | grep -qx "L/d:"'
check "ls heads each of several directories" sh -c 'ls L/d L/d | grep -qx "L/d:"'
check "ls -q writes ? for control characters" sh -c "touch \"L/\$(printf 'x\\001y')\"; ls -q L | grep -qx 'x?y'"
check "ls -w writes them raw" sh -c "ls -w L | grep -q \"^x\$(printf '\\001')y\$\""
check "ls --color=always colours" sh -c "ls --color=always -d L | grep -q \"\$(printf '\\033')\""
check "ls doesn't colour unasked" sh -c "! ls -d L | grep -q \"\$(printf '\\033')\""
check "ls -c, -u and -U run" sh -c 'ls -lc L >/dev/null && ls -lu L >/dev/null && ls -lU L >/dev/null'
check "ls reports a missing file" same "$(ls L/nope 2>&1)" "ls: L/nope: No such file or directory"
check "and fails" status_is 1 ls L/nope
check "ls refuses an unknown option" status_is 1 ls -Z

# --- cp --------------------------------------------------------------------------------------
mkdir C
cd C
echo one > a
chmod 4755 a
cp a b
check "cp copies" cmp -s a b
check "a new copy loses set-user-ID" same "$(perms b)" -rwxr-xr-x
echo two > e
chmod 600 e
cp a e
check "an existing target keeps its mode" same "$(perms e)" -rw-------
check "but gets the contents" cmp -s a e
touch -t 200102030405.06 a
cp -p a p
check "cp -p keeps the times" same "$(mtime p)" "$(mtime a)"
check "and the mode" same "$(perms p)" -rwsr-xr-x
mkdir s s/sub
echo deep > s/sub/f
ln -s f s/sub/l
mkfifo s/fifo
check "cp refuses a directory without -R" same "$(cp s t 2>&1)" "cp: s is a directory (not copied)."
check "cp -R copies a tree" cp -R s t
check "its files" cmp -s s/sub/f t/sub/f
check "links as links" test -L t/sub/l
check "FIFOs as FIFOs" test -p t/fifo
cp -R s t
check "cp -R into an existing directory goes inside it" test -f t/s/sub/f
check "cp -RL copies what links point to" sh -c 'cp -RL s u && test -f u/sub/l && ! test -L u/sub/l'
check "cp -a keeps times and links" sh -c 'cp -a s v && test -L v/sub/l'
mkdir into
cp a b into
check "cp into a directory" sh -c 'test -f into/a && test -f into/b'
check "cp refuses several files onto a non-directory" status_is 1 cp a b e
echo new > n1
echo old > n2
cp -n n1 n2
check "cp -n leaves an existing file" same "$(cat n2)" old
echo n | cp -i n1 n2 2>/dev/null
check "cp -i leaves it when told no" same "$(cat n2)" old
echo y | cp -i n1 n2 2>/dev/null
check "and replaces it when told yes" same "$(cat n2)" new
check "cp -v names the copies" same "$(cp -v n1 n3)" "n1 -> n3"
check "cp -l makes a hard link" sh -c 'cp -l n1 h1 && test n1 -ef h1'
check "cp -s makes a symbolic link" sh -c 'cp -s n1 s1 && test -L s1'
check "cp won't copy a file onto itself" same "$(cp n1 n1 2>&1)" "cp: n1 and n1 are identical (not copied)."
check "cp -R of a directory into itself ends" status_is 1 cp -R s s/sub
check "cp reports a missing file" same "$(cp nope x 2>&1)" "cp: nope: No such file or directory"
cd $T

# --- mv --------------------------------------------------------------------------------------
mkdir M
cd M
echo a > a
mv a b
check "mv renames" sh -c 'test -f b && ! test -e a'
mkdir dir
echo c > c
mv b c dir
check "mv into a directory" sh -c 'test -f dir/b && test -f dir/c && ! test -e c'
check "mv refuses several files onto a non-directory" sh -c 'touch x y z; ! mv x y z 2>/dev/null'
echo new > m1
echo old > m2
mv -n m1 m2
check "mv -n leaves an existing file" sh -c 'test "$(cat m2)" = old && test -e m1'
echo n | mv -i m1 m2 2>/dev/null
check "mv -i leaves it when told no" same "$(cat m2)" old
echo y | mv -i m1 m2 2>/dev/null
check "and moves when told yes" sh -c 'test "$(cat m2)" = new && ! test -e m1'
check "mv -v names the moves" same "$(mv -v m2 m3)" "m2 -> m3"
mkdir td
ln -s td tl
touch hf
mv -h hf tl
check "mv -h replaces a link to a directory" sh -c 'test -f tl && ! test -L tl && ! test -e td/hf'
check "mv reports a missing file" same "$(mv nope x 2>&1)" "mv: nope: No such file or directory"
check "mv refuses a directory into itself" status_is 1 mv dir dir/sub
# Between file systems: a tmpfs of its own, when mount(8) can make one (as root).
mkdir -p $T/other
if mount -t tmpfs tmpfs $T/other 2>/dev/null; then
	X=$T/other/bin2.$$
	mkdir -p tree/sub
	echo deep > tree/sub/f
	ln -s f tree/sub/l
	chmod 700 tree/sub
	touch -t 200501020304 tree/sub/f
	mv tree $X
	check "mv between file systems copies a tree" same "$(cat $X/sub/f)" deep
	check "keeping links" test -L $X/sub/l
	check "modes" same "$(perms $X/sub)" drwx------
	check "and times" same "$(TZ=UTC0 ls -lT $X/sub/f | awk '{print $9}')" 2005
	check "and removes the source" not test -e tree
	echo file > xf
	chmod 640 xf
	mv xf $X/xf
	check "a file between file systems keeps its mode" same "$(perms $X/xf)" -rw-r-----
	check "and goes" not test -e xf
	mv $X/xf back
	check "and comes back" same "$(cat back)" file
	rm -rf $X
	umount $T/other
else
	skip "mv between file systems (no tmpfs could be mounted)"
fi
cd $T

# --- dd --------------------------------------------------------------------------------------
printf 'hello world\n' > d1
check "dd copies" same "$(dd < d1 2>/dev/null)" "hello world"
check "dd if= of=" sh -c 'dd if=d1 of=d2 2>/dev/null && cmp -s d1 d2'
check "dd bs= count=" same "$(dd if=d1 bs=4 count=2 2>/dev/null)" "hello wo"
check "dd skip=" same "$(dd if=d1 bs=6 skip=1 2>/dev/null)" "world"
printf 'abcdefgh' > d3
printf 'XY' | dd of=d3 bs=2 seek=1 conv=notrunc 2>/dev/null
check "dd seek= conv=notrunc" same "$(cat d3)" abXYefgh
printf 'abcdefgh' > d3
printf 'XY' | dd of=d3 bs=2 seek=1 2>/dev/null
check "dd seek= cuts the file there" same "$(cat d3)" abXY
check "dd conv=ucase" same "$(dd if=d1 conv=ucase 2>/dev/null)" "HELLO WORLD"
check "dd conv=lcase" same "$(echo ABC | dd conv=lcase 2>/dev/null)" abc
check "dd conv=swab" same "$(printf 'badc' | dd conv=swab 2>/dev/null)" abcd
printf 'ab\ncdefghijk\n' > d4
dd if=d4 of=d5 cbs=4 conv=block 2>/dev/null
check "dd conv=block pads and cuts records" same "$(cat d5)" "ab  cdef"
check "dd conv=unblock undoes it" same "$(dd if=d5 cbs=4 conv=unblock 2>/dev/null)" "$(printf 'ab\ncdef')"
check "dd conv=sync pads input blocks" same "$(dd if=d1 ibs=8 conv=sync 2>/dev/null | wc -c | tr -d ' ')" 16
check "dd counts records" same "$(dd if=d1 of=/dev/null bs=5 2>&1 | head -n 2 | tr '\n' ' ')" "2+1 records in 2+1 records out "
check "dd writes the bytes transferred" sh -c 'dd if=d1 of=/dev/null 2>&1 | grep -q "^12 bytes transferred in .* secs (.* bytes/sec)$"'
check "dd status=noxfer leaves that out" same "$(dd if=d1 of=/dev/null status=noxfer 2>&1 | wc -l | tr -d ' ')" 2
check "dd status=none is quiet" same "$(dd if=d1 of=/dev/null status=none 2>&1)" ""
check "dd count=0 copies nothing" same "$(dd if=d1 count=0 2>/dev/null)" ""
check "dd sizes take suffixes" same "$(dd if=/dev/zero bs=1k count=2 2>/dev/null | wc -c | tr -d ' ')" 2048
check "and products" same "$(dd if=/dev/zero bs=2x512 count=1 2>/dev/null | wc -c | tr -d ' ')" 1024
dd if=/dev/zero of=d6 bs=4k count=4 conv=sparse 2>/dev/null
check "dd conv=sparse still makes the whole file" same "$(wc -c < d6 | tr -d ' ')" 16384
check "of NULs" sh -c 'dd if=/dev/zero bs=4k count=4 2>/dev/null | cmp -s - d6'
check "dd refuses an unknown operand" status_is 1 dd foo=bar
check "dd refuses a bad number" same "$(dd bs=1q 2>&1)" "dd: 1q: illegal numeric value"
check "dd needs cbs for block" status_is 1 dd conv=block
check "dd reports a missing input" status_is 1 dd if=nope

# --- df --------------------------------------------------------------------------------------
check "df lists file systems" sh -c 'df | head -n 1 | grep -q "^Filesystem  *[0-9]*[KMG]*-blocks  *Used  *Avail Capacity  Mounted on$"'
check "df / names /" sh -c 'df / | tail -n 1 | grep -q " /$"'
check "df -P has POSIX's header" same "$(df -P / | head -n 1 | awk '{print $2, $4, $5}')" "512-blocks Available Capacity"
check "df -Pk counts kilobytes" same "$(df -Pk / | head -n 1 | awk '{print $2}')" 1024-blocks
check "df -k" same "$(df -k / | head -n 1 | awk '{print $2}')" 1K-blocks
check "df -m" same "$(df -m / | head -n 1 | awk '{print $2}')" 1M-blocks
check "df -h" same "$(df -h / | head -n 1 | awk '{print $2}')" Size
check "df -i shows inodes" sh -c 'df -i / | head -n 1 | grep -q "iused  *ifree %iused"'
check "df -T shows the type" sh -c 'test -n "$(df -T / | tail -n 1 | awk "{print \$2}")"'
check "df -c adds a total" sh -c 'df -c | tail -n 1 | grep -q "^total "'
check "df -t keeps only that type" sh -c 't=$(df -T / | tail -n 1 | awk "{print \$2}"); test "$(df -T -t $t | tail -n +2 | awk "{print \$2}" | sort -u)" = "$t"'
check "df -t no... leaves it out" sh -c 't=$(df -T / | tail -n 1 | awk "{print \$2}"); ! df -T -t no$t | tail -n +2 | awk "{print \$2}" | grep -qx "$t"'
check "df capacity is a percentage" sh -c 'df / | tail -n 1 | grep -q " [0-9]*% "'
check "df reports a missing file" same "$(df /nonexistent 2>&1)" "df: /nonexistent: No such file or directory"
check "and fails" status_is 1 df /nonexistent

# --- date ------------------------------------------------------------------------------------
check "date +%s is a number" sh -c 'date +%s | grep -qx "[0-9][0-9]*"'
check "date writes the time" sh -c 'date | grep -q " [0-9][0-9]:[0-9][0-9]:[0-9][0-9] "'
check "date -u -r 0" same "$(date -u -r 0)" "Thu Jan  1 00:00:00 UTC 1970"
check "date -r with a format" same "$(date -u -r 1577979045 '+%F %T')" "2020-01-02 15:30:45"
check "date -R" same "$(date -u -r 0 -R)" "Thu, 01 Jan 1970 00:00:00 +0000"
check "date -I" same "$(date -u -r 0 -I)" 1970-01-01
check "date -Iseconds" same "$(date -u -r 0 -Iseconds)" 1970-01-01T00:00:00+00:00
check "date -j reads [[cc]yy]mmddHHMM[.SS]" same "$(date -u -j 202001021530.45 +%s)" 1577979045
check "with a two-digit year" same "$(date -u -j 2001021530 +%F)" 2020-01-02
check "date -j -f reads with strptime" same "$(date -u -j -f %Y-%m-%d 2021-03-04 +%F)" 2021-03-04
check "date -v+1m stays in the month" same "$(date -u -r 1580428800 -v+1m +%F)" 2020-02-29
check "date -v-1d" same "$(date -u -r 1577979045 -v-1d +%F)" 2020-01-01
check "date -v+fri" same "$(date -u -r 1577979045 -v+fri '+%a %F')" "Fri 2020-01-03"
check "date -v sets a field" same "$(date -u -r 1577979045 -v1d -v0H +%F%H)" 2020-01-0100
check "date -v+9H crosses midnight" same "$(date -u -r 1577979045 -v+9H +%F)" 2020-01-03
TZ=UTC0 touch -t 202001021530.45 dt
check "date -r file uses its time" same "$(date -r dt +%s)" 1577979045
check "date refuses an impossible time" status_is 1 date -j 2513
check "date refuses a bad adjustment" status_is 1 date -v+3x
if [ "$(id -u)" = 0 ]; then
	now=$(date +%Y%m%d%H%M.%S)
	check "date sets the clock" sh -c "date $now > /dev/null"
else
	skip "setting the clock (not root)"
fi

# --- stty ------------------------------------------------------------------------------------
check "stty refuses what isn't a terminal" sh -c 'stty < /dev/null 2>&1 | grep -q "isn.t a terminal"'
check "stty -f refuses one too" status_is 1 stty -f /dev/null
if [ -t 0 ]; then
	g=$(stty -g)
	check "stty -g writes gfmt1" sh -c "echo '$g' | grep -q '^gfmt1:'"
	stty -echo
	check "stty -echo shows" sh -c 'stty | grep -q -- "-echo"'
	stty "$g"
	check "stty gfmt1 restores" same "$(stty -g)" "$g"
elif command -v script > /dev/null 2>&1 && script -q -c true /dev/null > /dev/null 2>&1; then
	# A pseudo-terminal of our own, through script(1).
	pty() { script -q -c "$1" /dev/null 2>&1 | tr -d '\r'; }
	check "stty writes the speed" sh -c "$(command -v script) -q -c stty /dev/null | grep -q '^speed [0-9]* baud;'"
	check "stty -g writes gfmt1" sh -c "$(command -v script) -q -c 'stty -g' /dev/null | grep -q '^gfmt1:cflag='"
	check "stty -echo shows" same "$(pty 'stty -echo; stty | grep -c -- -echo')" 1
	check "stty -e writes every flag" same "$(pty 'stty -e | grep -c "^lflags:"')" 1
	check "stty -a writes cchars" same "$(pty 'stty -a | grep -c "^cchars: "')" 1
	check "stty sets rows and columns" same "$(pty 'stty rows 30 cols 100; stty size')" "30 100"
	check "stty sets control characters" same "$(pty 'stty intr ^X; stty -a | grep -c "intr = ^X;"')" 1
	check "stty raw and sane" same "$(pty 'stty raw; stty -g > /dev/null; stty sane; stty | grep -c -- -icanon')" 0
	check "stty gfmt1 restores" same "$(pty 's=$(stty -g); stty raw -echo intr ^X; stty "$s"; test "$(stty -g)" = "$s" && echo same')" same
	check "stty sets the speed" same "$(pty 'stty 9600; stty speed')" 9600
	check "stty refuses an unknown setting" same "$(pty 'stty bogus > /dev/null 2>&1; echo $?')" 1
else
	skip "stty on a terminal (no terminal and no script(1))"
fi

cd /
rm -rf $T
echo "bin2: $fail failed"
[ $fail -eq 0 ]
