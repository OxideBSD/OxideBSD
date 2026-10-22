#!/bin/sh
#
# On-target check for the process and network tools rewritten in Rust std: ps, pgrep, pkill and
# ping. Prints one line per check and exits 0 if all pass. Runs as root on OxideBSD (ping's
# -i below a second needs it); BIN and SBIN name where the programs under test are (/bin and
# /sbin by default).

BIN=${BIN:-/bin}
SBIN=${SBIN:-/sbin}
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin5: ok: $_desc"
	else
		echo "bin5: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
skip() { echo "bin5: skip: $1"; }
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
same() { [ "$1" = "$2" ]; }
has() { case $1 in *"$2"*) return 0 ;; esac; return 1; }
matches() { echo "$1" | grep -Eq "$2"; }
# The words of a line, blanks squeezed: ps's columns are as wide as their contents.
words() { echo $*; }
T=/tmp/bin5
rm -rf $T
mkdir -p $T
cd $T || exit 1

PS=$BIN/ps
PGREP=$BIN/pgrep
PKILL=$BIN/pkill
PING=$SBIN/ping

# --- ps --------------------------------------------------------------------------------------
sleep 1234 &
s=$!
sleep 1235 &
t=$!
check "ps -ax has FreeBSD's default columns" same "$(words $($PS -ax | head -n 1))" "PID TT STAT TIME COMMAND"
check "ps -ax shows init" matches "$($PS -ax)" '^ *1 '
check "ps -ax shows several processes" [ "$($PS -ax -o pid= | wc -l)" -gt 3 ]
check "ps -p selects a pid" same "$(words $($PS -p 1 -o pid=))" 1
check "ps -p takes a list" same "$($PS -p 1,$s -o pid= | wc -l | tr -d ' ')" 2
check "ps takes an old-style pid operand" same "$(words $($PS -o pid= $s))" "$s"
check "ps -o pid= is the caller" same "$(words $($PS -o pid= -p $$))" "$$"
check "ps -o ppid" same "$(words $($PS -o ppid= -p $s))" "$$"
check "ps -o comm" same "$(words $($PS -o comm= -p $s))" sleep
check "ps -o args" same "$(words $($PS -o args= -p $s))" "sleep 1234"
check "ps -o command is the arguments" same "$(words $($PS -o command= -p $s))" "sleep 1234"
check "ps -c shows only the name" same "$(words $($PS -c -o command= -p $s))" sleep
check "ps -o stat of a sleeper" matches "$($PS -o stat= -p $s)" '^ *[SI]'
kill -STOP $s
sleep 1
check "ps -o stat of a stopped process" matches "$($PS -o stat= -p $s)" '^ *T'
kill -CONT $s
check "ps -o pgid,sid are the shell's" same "$(words $($PS -o pgid= -o sid= -p $s))" "$(words $($PS -o pgid= -o sid= -p $$))"
check "ps -o user of init" same "$(words $($PS -o user= -p 1))" root
check "ps -o uid,ruid,gid of init" same "$(words $($PS -o uid= -o ruid= -o gid= -p 1))" "0 0 0"
check "ps -o time" matches "$($PS -o time= -p 1)" '^ *[0-9]+:[0-5][0-9]\.[0-9][0-9]$'
check "ps -o etime" matches "$($PS -o etime= -p 1)" '^ *([0-9]+-)?([0-9][0-9]:)?[0-9][0-9]:[0-5][0-9]$'
check "ps -o etimes" matches "$($PS -o etimes= -p 1)" '^ *[0-9]+$'
check "ps -o lstart" matches "$($PS -o lstart= -p 1)" '^[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-9][0-9] [0-9:]{8} [0-9]{4}$'
check "ps -o vsz is not zero" [ "$($PS -o vsz= -p $$)" -gt 0 ]
check "ps -o rss is not zero" [ "$($PS -o rss= -p $$)" -gt 0 ]
check "ps -o %mem" matches "$($PS -o %mem= -p $$)" '^ *[0-9]+\.[0-9]$'
check "ps -o nice of a default process" same "$(words $($PS -o nice= -p $s))" 0
check "ps -o pri of a default process" same "$(words $($PS -o pri= -p $s))" 20
check "ps -o nlwp" same "$(words $($PS -o nlwp= -p $s))" 1
# A process without a controlling terminal: /sbin/init is one, a test harness's pid 1 may not be.
nott=$($PS -ax -o pid= -o tt= | awk '$2 == "-" { print $1; exit }')
if [ -n "$nott" ]; then
	check "ps -o tt,tdev without a terminal" same "$(words $($PS -o tt= -o tdev= -p $nott))" "- -"
	check "ps -t - selects processes without a terminal" matches "$($PS -t - -o pid=)" "^ *$nott\$"
else
	skip "ps -o tt,tdev / ps -t -: every process has a terminal"
fi
check "ps prints what /proc lacks as -" same "$(words $($PS -o jobc= -p 1))" -
check "ps -o keyword=header" same "$($PS -o pid=MYPID -p 1 | head -n 1 | tr -d ' ')" MYPID
check "ps -o header runs to the end" same "$($PS -o 'pid=a, b' -p 1 | head -n 1 | sed 's/^ *//')" "a, b"
check "ps -o header takes the rest of the argument" same "$($PS -o pid=,ppid= -p 1 | head -n 1 | tr -d ' ')" ",ppid="
check "ps -o all-empty headers print none" same "$($PS -o pid= -o comm= -p 1 | wc -l | tr -d ' ')" 1
check "ps -o several times adds up" same "$(words $($PS -o pid -o ppid -p 1 | head -n 1))" "PID PPID"
# The kernel process and its threads (KTHREAD.md §8).
check "ps -ax shows the kernel process" matches "$($PS -ax -o pid= -o command=)" '^ *0 \[kernel\]$'
check "ps -axH shows the taskq kernel thread" matches "$($PS -axH -o pid= -o command=)" '^ *0 \[kernel/taskq\]$'
check "ps -axH has no lone [kernel]" not matches "$($PS -axH -o command=)" '^\[kernel\]$'
check "/proc/0/stat is the kernel's" matches "$(cat /proc/0/stat)" '^0 \(kernel\) [RS] 0 0 0 '
ktid=$(ls /proc/0/task | head -n 1)
check "/proc/0/task lists kernel threads" matches "$ktid" '^[0-9]+$'
check "a kernel thread's stat names it" matches "$(cat /proc/0/task/$ktid/stat 2>&1)" "^$ktid \\("
check "/proc hides a kernel thread's id" not [ -e /proc/$ktid ]
check "/proc doesn't list a kernel thread's id" not matches "$(ls /proc)" "^$ktid\$"
check "pgrep passes the kernel over" status_is 1 $PGREP -x kernel
check "pgrep -S finds the kernel" same "$($PGREP -S -x kernel)" 0
check "ps -O adds after the pid" same "$(words $($PS -O ppid,nice -p 1 | head -n 1))" "PID PPID NI TT STAT TIME COMMAND"
check "ps -j's columns" same "$(words $($PS -j -p 1 | head -n 1))" "USER PID PPID PGID SID JOBC STAT TT TIME COMMAND"
check "ps -l's columns" same "$(words $($PS -l -p 1 | head -n 1))" "UID PID PPID C PRI NI VSZ RSS MWCHAN STAT TT TIME COMMAND"
check "ps -u's columns" same "$(words $($PS -u -p 1 | head -n 1))" "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND"
check "ps -v's columns" same "$(words $($PS -v -p 1 | head -n 1))" "PID STAT TIME SL RE PAGEIN VSZ RSS LIM TSIZ %CPU %MEM COMMAND"
check "ps aux (old style)" same "$($PS aux | head -n 1 | cut -c1-4)" USER
check "ps -m sorts" status_is 0 $PS -axm
check "ps -r sorts" status_is 0 $PS -axr
check "ps -U root selects init" matches "$($PS -U root -o pid=)" '^ *1$'
check "ps -U takes a number" matches "$($PS -U 0 -o pid=)" '^ *1$'
check "ps -G 0 selects init" matches "$($PS -G 0 -o pid=)" '^ *1$'
if $PS -ax -o tt= | grep -qx 'v0 *'; then
	check "ps -t v0 selects ttyv0's" same "$($PS -t v0 -o tt= | sort -u | tr -d ' ')" v0
	check "ps -t /dev/ttyv0 is the same" same "$($PS -t /dev/ttyv0 -o tt= | sort -u | tr -d ' ')" v0
	check "ps -o tty names it in full" same "$($PS -t v0 -o tty= | sort -u | tr -d ' ')" ttyv0
else
	skip "ps -t v0: nothing on ttyv0"
fi
check "ps -L lists keywords" has "$($PS -L)" lstart
check "ps -p of nothing fails" status_is 1 $PS -p 999999
check "ps reports an unknown keyword" same "$($PS -o nosuch 2>&1)" "ps: nosuch: keyword not found"
check "and fails" status_is 1 $PS -o nosuch
check "ps refuses an unknown option" status_is 1 $PS -Q
check "ps reports an unknown user" status_is 1 $PS -U nosuchuser

# --- pgrep -----------------------------------------------------------------------------------
check "pgrep -f finds the arguments" same "$($PGREP -f 'sleep 1234')" "$s"
check "pgrep finds the name" has "$($PGREP -x sleep)" "$s"
check "pgrep matches a regular expression" same "$($PGREP -f 'sleep 123[45]' | tr '\n' ' ')" "$s $t "
check "pgrep -x needs the whole name" status_is 1 $PGREP -x slee
check "pgrep -f -x needs the whole line" same "$($PGREP -f -x 'sleep 1234')" "$s"
check "pgrep -f -x refuses part of it" status_is 1 $PGREP -f -x 'sleep 123'
check "pgrep -l shows the name" has "$($PGREP -l -x sleep)" "$s sleep"
check "pgrep -l -f shows the arguments" same "$($PGREP -l -f 'sleep 1234')" "$s sleep 1234"
check "pgrep -d sets the separator" same "$($PGREP -d, -f 'sleep 123[45]')" "$s,$t"
check "pgrep -n is the newest" same "$($PGREP -n -f 'sleep 123[45]')" "$t"
check "pgrep -o is the oldest" same "$($PGREP -o -f 'sleep 123[45]')" "$s"
check "pgrep -q prints nothing" same "$($PGREP -q -f 'sleep 1234')" ""
check "pgrep -q still succeeds" status_is 0 $PGREP -q -f 'sleep 1234'
check "pgrep -i ignores case" same "$($PGREP -i -f 'SLEEP 1234')" "$s"
check "pgrep -P is the parent" same "$($PGREP -P $$ -f 'sleep 123[45]' | wc -l | tr -d ' ')" 2
check "pgrep -u root" same "$($PGREP -u root -f 'sleep 1234')" "$s"
check "pgrep -u of someone else finds none" status_is 1 $PGREP -u 12345 -f 'sleep 1234'
check "pgrep -U 0" same "$($PGREP -U 0 -f 'sleep 1234')" "$s"
check "pgrep -G 0" same "$($PGREP -G 0 -f 'sleep 1234')" "$s"
check "pgrep -g 0 is the shell's process group" same "$($PGREP -g 0 -f 'sleep 1234')" "$s"
check "pgrep -s 0 is the shell's session" same "$($PGREP -s 0 -f 'sleep 1234')" "$s"
check "pgrep with only options" has "$($PGREP -P $$)" "$s"
check "pgrep -v turns it around" not has "$($PGREP -v -f 'sleep 123')" "$s"
check "pgrep -v includes the rest" has " $($PGREP -v -f 'sleep 1234' | tr '\n' ' ') " " $t "
check "pgrep never picks itself" status_is 1 $PGREP -f 'pgrep -f pgrep'
check "pgrep leaves out its ancestors" not has " $($PGREP -s 0 | tr '\n' ' ') " " $$ "
check "pgrep -a keeps them" has " $($PGREP -a -s 0 | tr '\n' ' ') " " $$ "
if same "$(words $($PS -o tt= -p $s))" -; then
	check "pgrep -t - is no terminal" same "$($PGREP -t - -f 'sleep 1234')" "$s"
else
	skip "pgrep -t -: the shell has a terminal"
fi
echo $s > pidfile
check "pgrep -F reads a pid file" same "$($PGREP -F pidfile)" "$s"
check "pgrep -F with a pattern" status_is 1 $PGREP -F pidfile nomatch
check "pgrep -L fails for an unlocked pid file" status_is 3 $PGREP -L -F pidfile
check "pgrep -F of no file fails" status_is 3 $PGREP -F nosuchfile
check "pgrep of nothing" status_is 1 $PGREP nosuchprocessname
check "pgrep without a pattern" status_is 2 $PGREP
check "pgrep with a bad expression" status_is 2 $PGREP '('
check "pgrep refuses an unknown option" status_is 2 $PGREP -Z sleep
check "pgrep refuses -I" status_is 2 $PGREP -I sleep

# --- pkill -----------------------------------------------------------------------------------
check "pkill -0 checks a process" status_is 0 $PKILL -0 -f 'sleep 1234'
$PKILL -STOP -f 'sleep 1234'
sleep 1
check "pkill -STOP stops it" matches "$($PS -o stat= -p $s)" '^ *T'
$PKILL -SIGCONT -f 'sleep 1234'
sleep 1
check "pkill -SIGCONT starts it again" matches "$($PS -o stat= -p $s)" '^ *[SIR]'
check "pkill -l shows the kill" same "$($PKILL -l -f 'sleep 1235')" "kill -15 $t"
wait $t
check "and TERM is the default" [ $? -eq 143 ]
sleep 1236 &
u=$!
check "pkill -I asks, and n spares" same "$(echo n | $PKILL -I -f 'sleep 1236')" "kill $u sleep 1236? "
check "so it lives" status_is 0 kill -0 $u
echo y | $PKILL -I -f 'sleep 1236' > /dev/null
wait $u
check "pkill -I, and y kills" [ $? -eq 143 ]
$PKILL -9 -F pidfile
wait $s
check "pkill -9 -F kills by pid file" [ $? -eq 137 ]
check "pkill of nothing" status_is 1 $PKILL -9 nosuchprocessname
check "pkill refuses -d" status_is 2 $PKILL -d, sleep
check "pkill refuses a bad signal" status_is 2 $PKILL -NOSUCHSIG sleep

# --- ping ------------------------------------------------------------------------------------
$PING -c 2 127.0.0.1 > p1 2>&1
check "ping -c 2 127.0.0.1 succeeds" [ $? -eq 0 ]
check "ping prints FreeBSD's first line" same "$(head -n 1 p1)" "PING 127.0.0.1 (127.0.0.1): 56 data bytes"
check "ping prints a line per reply" matches "$(cat p1)" '^64 bytes from 127\.0\.0\.1: icmp_seq=0 ttl=64 time=[0-9]+\.[0-9]{3} ms$'
check "ping numbers the replies" matches "$(cat p1)" '^64 bytes from 127\.0\.0\.1: icmp_seq=1 '
check "ping's statistics header" has "$(cat p1)" "--- 127.0.0.1 ping statistics ---"
check "ping's counts" has "$(cat p1)" "2 packets transmitted, 2 packets received, 0.0% packet loss"
check "ping's round trip line" matches "$(cat p1)" '^round-trip min/avg/max/stddev = [0-9.]+/[0-9.]+/[0-9.]+/[0-9.]+ ms$'
check "ping sees no duplicates on loopback" not has "$(cat p1)" DUP
check "ping -s sets the size" has "$($PING -c 1 -s 100 127.0.0.1)" "108 bytes from 127.0.0.1"
check "ping -s below 8 doesn't time" not has "$($PING -c 1 -s 4 127.0.0.1)" round-trip
check "ping -p fills with a pattern" status_is 0 $PING -c 1 -p deadbeef 127.0.0.1
check "and the replies carry it" not has "$($PING -c 1 -p deadbeef 127.0.0.1 2>&1)" wrong
check "ping -q prints no replies" not has "$($PING -q -c 2 127.0.0.1)" "bytes from"
check "ping -q still sums up" has "$($PING -q -c 2 127.0.0.1)" "2 packets received"
check "ping -o stops at the first reply" has "$($PING -o 127.0.0.1)" "1 packets transmitted, 1 packets received"
check "ping -i 0.2 as root" status_is 0 $PING -c 3 -i 0.2 127.0.0.1
t1=$(date +%s)
$PING -t 2 127.0.0.1 > p2 2>&1
st=$?
t2=$(date +%s)
check "ping -t stops in time" [ $((t2 - t1)) -le 4 ]
check "and succeeds" [ $st -eq 0 ]
check "ping localhost resolves" has "$($PING -c 1 localhost)" "(127.0.0.1)"
$PING -i 0.2 127.0.0.1 > p3 2>&1 &
p=$!
sleep 2
kill -INT $p
wait $p
st=$?
check "ping sums up on SIGINT" has "$(cat p3)" "ping statistics"
check "and exits 0" [ $st -eq 0 ]
check "ping with no reply exits 2" status_is 2 $PING -c 1 -W 500 192.0.2.1
check "ping without a host" status_is 64 $PING
check "ping -c 0" status_is 64 $PING -c 0 127.0.0.1
check "ping -p needs hex digits" status_is 64 $PING -c 1 -p zz 127.0.0.1
check "ping refuses an unknown option" status_is 64 $PING -Q 127.0.0.1

cd /
rm -rf $T
echo "bin5: $fail failed"
[ $fail -eq 0 ]
