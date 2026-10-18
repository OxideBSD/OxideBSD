#!/bin/sh
#
# On-target check for the third batch of utilities rewritten in Rust std: the text tools grep
# (with egrep and fgrep), sed, ed and expr. Prints one line per check and exits 0 if all pass.
# BIN names the directory holding the binaries under test (default /bin), T the scratch
# directory (default /tmp/bin3). Uses nothing else but the shell and base tools (printf, cat,
# cmp, ln, mkdir, rm, wc, tr).

BIN=${BIN:-/bin}
T=${T:-/tmp/bin3}
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022

GREP=$BIN/grep
SED=$BIN/sed
ED=$BIN/ed
EXPR=$BIN/expr

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin3: ok: $_desc"
	else
		echo "bin3: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
same() {
	[ "$1" = "$2" ] && return 0
	printf '  got:  [%s]\n  want: [%s]\n' "$1" "$2"
	return 1
}
nl='
'

rm -rf $T
mkdir -p $T
cd $T || exit 1
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n' > n
printf 'alpha beta\nGamma delta\nepsilon_zeta eta\n\ntheta\n' > w
printf 'abc\000def\nxyz\n' > bin
printf 'no newline' > nonl

# --- grep ------------------------------------------------------------------------------------
check "grep selects matching lines" same "$($GREP e n | tr '\n' ' ')" "one three five seven eight nine ten "
check "grep -v selects the others" same "$($GREP -v e n | tr '\n' ' ')" "two four six "
check "grep -c counts" same "$($GREP -c e n)" 7
check "grep -vc" same "$($GREP -vc e n)" 3
check "grep -n numbers" same "$($GREP -n '^t' n | tr '\n' ' ')" "2:two 3:three 10:ten "
check "grep -i ignores case" same "$($GREP -i gamma w)" "Gamma delta"
check "grep -y is -i" same "$($GREP -y GAMMA w)" "Gamma delta"
check "grep -x matches whole lines" same "$($GREP -x 't.o' n)" two
check "grep -x refuses a part" status_is 1 $GREP -x tw n
check "grep -w matches whole words" same "$($GREP -w eta w)" "epsilon_zeta eta"
check "grep -w: underscore is part of a word" status_is 1 $GREP -w zeta w
check "grep -w tries a later occurrence" same "$(printf 'xab ab\n' | $GREP -wo ab)" ab
check "grep BRE: + is literal" status_is 1 $GREP 'o+' n
check "grep BRE intervals" same "$($GREP '^.\{5\}$' n | tr '\n' ' ')" "three seven eight "
check "grep BRE back-references" same "$(printf 'abab\nabba\n' | $GREP '\(ab\)\1')" abab
check "grep -E alternation" same "$($GREP -E '^(two|six)$' n | tr '\n' ' ')" "two six "
check "grep -E +" same "$(printf 'aa\nb\n' | $GREP -E 'a+')" aa
check "grep -F takes the pattern literally" same "$(printf 'a.c\nabc\n' | $GREP -F a.c)" a.c
check "grep -F -i" same "$($GREP -Fi THREE n)" three
check "grep -F -x" same "$(printf 'ab\nabc\n' | $GREP -Fx ab)" ab
check "grep -F -w" same "$(printf 'ab_c\nab c\n' | $GREP -Fw ab)" "ab c"
check "grep -e twice is either" same "$($GREP -e two -e six n | tr '\n' ' ')" "two six "
check "grep: a newline in a pattern makes two" same "$($GREP "two${nl}six" n | tr '\n' ' ')" "two six "
printf 'four\nnine\n' > pats
check "grep -f reads patterns" same "$($GREP -f pats n | tr '\n' ' ')" "four nine "
check "grep -f /dev/null matches nothing" status_is 1 $GREP -f /dev/null n
check "grep: an empty pattern matches every line" same "$($GREP -c '' n)" 10
check "grep -l names files" same "$($GREP -l two n w)" n
check "grep -L names the others" same "$($GREP -L two n w)" w
check "grep -q is quiet" same "$($GREP -q two n)" ""
check "grep -q succeeds on a match" status_is 0 $GREP -q two n
check "grep -q fails on none" status_is 1 $GREP -q twelve n
check "grep -q matches despite an error" status_is 0 $GREP -q two nonexistent n
check "grep: no match is status 1" status_is 1 $GREP xyzzy n
check "grep: a missing file is status 2" status_is 2 $GREP two nonexistent
check "and reported" same "$($GREP two nonexistent 2>&1)" "grep: nonexistent: No such file or directory"
check "grep -s keeps quiet about it" same "$($GREP -s two nonexistent 2>&1)" ""
check "grep: an error beats a match" status_is 2 $GREP two n nonexistent
check "grep: a bad pattern is status 2" status_is 2 $GREP 'a\{1' n
check "grep names files when there are several" same "$($GREP two n n)" "n:two${nl}n:two"
check "grep -h doesn't" same "$($GREP -h two n n)" "two${nl}two"
check "grep -H always does" same "$($GREP -H two n)" n:two
check "grep -c with several files" same "$($GREP -c two n w)" "n:1${nl}w:0"
check "grep -m stops early" same "$($GREP -m2 e n | tr '\n' ' ')" "one three "
check "grep -m with -c" same "$($GREP -c -m3 e n)" 3
check "grep -o prints only matches" same "$($GREP -o 'e.' n | tr '\n' ' ')" "ee ev en ei en "
check "grep -o -n" same "$($GREP -on 'v.' n | tr '\n' ' ')" "5:ve 7:ve "
check "grep -b gives byte offsets" same "$($GREP -b three n)" 8:three
check "grep -A context after" same "$($GREP -A1 '^six' n | tr '\n' ' ')" "six seven "
check "grep -B context before" same "$($GREP -B2 '^six' n | tr '\n' ' ')" "four five six "
check "grep -C with separators" same "$($GREP -C1 -e two -e nine n | tr '\n' ' ')" "one two three -- eight nine ten "
check "grep -n context lines use -" same "$($GREP -n -A1 '^two' n | tr '\n' ' ')" "2:two 3-three "
check "grep -num is context" same "$($GREP -1 five n | tr '\n' ' ')" "four five six "
check "grep: adjoining groups need no separator" same "$($GREP -A1 -e two -e four n | tr '\n' ' ')" "two three four five "
check "grep reads the standard input" same "$(echo hi | $GREP h)" hi
check "grep: - is the standard input" same "$(echo hi | $GREP hi - n)" "(standard input):hi"
check "grep adds a missing last newline" same "$($GREP no nonl | wc -l | tr -d ' ')" 1
check "grep reports a binary file" same "$($GREP abc bin)" "Binary file bin matches"
check "grep -a reads it as text" same "$($GREP -a xyz bin)" xyz
check "grep -I passes it over" status_is 1 $GREP -I abc bin
check "grep -c counts a binary file" same "$($GREP -c abc bin)" 1
mkdir -p R/sub
echo needle > R/a.c
echo needle > R/sub/b.h
echo hay > R/c.c
ln -s ../n R/link
check "grep -r searches a tree" same "$($GREP -r needle R | tr '\n' ' ')" "R/a.c:needle R/sub/b.h:needle "
check "grep -R is the same" same "$($GREP -Rl needle R | tr '\n' ' ')" "R/a.c R/sub/b.h "
check "grep -r doesn't follow links inside" status_is 1 $GREP -r three R
check "grep -rS does" same "$($GREP -rS three R)" R/link:three
check "grep --include" same "$($GREP -r --include='*.c' needle R)" R/a.c:needle
check "grep --exclude" same "$($GREP -r --exclude='*.c' needle R)" R/sub/b.h:needle
check "grep --exclude-dir" same "$($GREP -r --exclude-dir=sub needle R)" R/a.c:needle
check "grep -r on no operand searches ." same "$(cd R && $GREP -r hay)" ./c.c:hay
check "grep on a directory fails" status_is 2 $GREP x R
check "grep -d skip passes it over" status_is 1 $GREP -d skip x R
check "grep --color=always marks matches" same "$($GREP --color=always tw n | tr '\033' E)" "E[01;31mE[KtwE[mE[Ko"
check "grep --color=never doesn't" same "$($GREP --color=never tw n)" two
check "grep --color uses GREP_COLOR" same "$(GREP_COLOR=32 $GREP --color=always tw n | tr '\033' E)" "E[32mE[KtwE[mE[Ko"
check "grep takes options after the pattern" same "$($GREP two n -c)" 1
check "grep -- ends options" same "$(printf -- '-x\n' | $GREP -- -x)" -x
check "grep refuses an unknown option" status_is 2 $GREP -Z x n
ln -s "$GREP" egrep
ln -s "$GREP" fgrep
check "egrep is grep -E" same "$(./egrep 'tw|si' n | tr '\n' ' ')" "two six "
check "fgrep is grep -F" same "$(printf 'a*b\naab\n' | ./fgrep 'a*b')" "a*b"

# --- sed -------------------------------------------------------------------------------------
check "sed s replaces the first match" same "$(echo aaa | $SED s/a/b/)" baa
check "sed s///g every match" same "$(echo aaa | $SED s/a/b/g)" bbb
check "sed s///2 the second" same "$(echo aaa | $SED s/a/b/2)" aba
check "sed s///2g the second on" same "$(echo aaaa | $SED s/a/b/2g)" abbb
check "sed & is the match" same "$(echo abc | $SED 's/b/[&]/')" "a[b]c"
check "sed \\& is a literal &" same "$(echo abc | $SED 's/b/\&/')" "a&c"
check "sed \\1 is a group" same "$(echo abcd | $SED 's/\(b\)\(c\)/\2\1/')" acbd
check "sed \\n in a replacement is a newline" same "$(echo ab | $SED 's/a/x\ny/')" "x${nl}yb"
check "sed an escaped newline in a replacement too" same "$(echo ab | $SED 's/a/x\
/')" "x${nl}b"
check "sed \\n in a pattern matches a newline" same "$(printf 'a\nb\n' | $SED 'N;s/a\nb/joined/')" joined
check "sed empty matches: s/x*/-/g" same "$(echo abc | $SED 's/x*/-/g')" -a-b-c-
check "sed empty match after a match: s/b*/x/g" same "$(echo abc | $SED 's/b*/x/g')" xaxcx
check "sed s with another delimiter" same "$(echo /usr/bin | $SED 's|/usr|/opt|')" /opt/bin
check "sed: an escaped delimiter is literal" same "$(echo 'a.b axb' | $SED 's.a\.b.X.g')" "X axb"
check "sed: a delimiter in a bracket expression" same "$(echo a/b | $SED 's/[/]/-/')" a-b
check "sed s///p prints" same "$(printf 'a\nb\n' | $SED -n 's/a/A/p')" A
check "sed s///I ignores case" same "$(echo ABC | $SED 's/b/x/I')" AxC
check "sed s///w writes a file" sh -c "printf 'a\nb\n' | $SED -n 's/a/A/w sw' && [ \"\$(cat sw)\" = A ]"
check "sed -E groups" same "$(echo abc | $SED -E 's/(a)(b)/\2\1/')" bac
check "sed -E alternation" same "$(echo cat dog | $SED -E 's/cat|dog/pet/g')" "pet pet"
check "sed -r is -E" same "$(echo aa | $SED -r 's/a+/b/')" b
check "sed BRE + is literal" same "$(echo 'a+' | $SED 's/a+/b/')" b
check "sed: an empty RE is the last one" same "$(echo abcb | $SED '/b/s//X/g')" aXcX
check "sed -n with p" same "$($SED -n 3p n)" three
check "sed #n is -n" same "$(printf '#n\n3p\n' > sc && $SED -f sc n)" three
check "sed d" same "$($SED '2,9d' n | tr '\n' ' ')" "one ten "
check "sed $ is the last line" same "$($SED -n '$p' n)" ten
check "sed $!d" same "$($SED '$!d' n)" ten
check "sed regex ranges" same "$($SED -n '/two/,/four/p' n | tr '\n' ' ')" "two three four "
check "sed: a range's end is looked for from the next line" same "$($SED -n '/o/,/o/p' n | tr '\n' ' ')" "one two four five six seven eight nine ten "
check "sed: a range ending before it starts is one line" same "$($SED -n '5,2p' n)" five
check "sed addr,+N" same "$($SED -n '/six/,+2p' n | tr '\n' ' ')" "six seven eight "
check "sed ! inverts" same "$($SED -n '2,9!p' n | tr '\n' ' ')" "one ten "
check "sed \\cREc addresses" same "$($SED -n '\,ix,p' n | tr '\n' ' ')" "six "
check "sed address I" same "$($SED -n '/TWO/Ip' n)" two
check "sed { } groups" same "$($SED -n '/^t/{/e/p;}' n | tr '\n' ' ')" "three ten "
check "sed nested blocks" same "$($SED -n '1,5{/o/{/f/p;};}' n)" four
check "sed = writes line numbers" same "$($SED -n '/six/=' n)" 6
check "sed $= counts lines" same "$($SED -n '$=' n)" 10
check "sed y transliterates" same "$(echo hello | $SED 'y/el/ip/')" hippo
check "sed y with \\n" same "$(printf 'a b\n' | $SED 'y/ /\n/')" "a${nl}b"
check "sed y refuses unequal lengths" status_is 1 $SED 'y/ab/c/' n
check "sed a appends" same "$(printf 'x\ny\n' | $SED '1a\
added')" "x${nl}added${nl}y"
check "sed i inserts" same "$(printf 'x\ny\n' | $SED '2i\
ins')" "x${nl}ins${nl}y"
check "sed c changes a range once" same "$($SED '2,9c\
mid' n | tr '\n' ' ')" "one mid ten "
check "sed c with ! changes each line" same "$(printf 'a\nb\n' | $SED '1!c\
X')" "a${nl}X"
check "sed a with text on the same line" same "$(echo x | $SED 'a hello')" "x${nl}hello"
check "sed multi-line a text" same "$(echo x | $SED 'a\
l1\
l2')" "x${nl}l1${nl}l2"
check "sed a text is written even after d" same "$(printf 'x\ny\n' | $SED '1{a\
after
d;}')" "after${nl}y"
check "sed i goes out before the line" same "$(echo x | $SED -n 'i\
before
p')" "before${nl}x"
check "sed r reads a file after the line" same "$(printf 'x\ny\n' | $SED '1r pats')" "x${nl}four${nl}nine${nl}y"
check "sed r of a missing file is nothing" same "$(echo x | $SED 'r nonexistent')" x
check "sed w writes lines" sh -c "$SED -n '/^t/w tw' n && [ \"\$(cat tw | tr '\n' ' ')\" = 'two three ten ' ]"
check "sed h and G" same "$(printf 'a\nb\n' | $SED '1h;2G')" "a${nl}b${nl}a"
check "sed H and x" same "$(printf 'a\nb\n' | $SED -n 'H;${x;p;}')" "${nl}a${nl}b"
check "sed g copies the hold space" same "$(printf 'a\nb\n' | $SED '1h;2g')" "a${nl}a"
check "sed tac" same "$($SED '1!G;h;$!d' n | tr '\n' ' ')" "ten nine eight seven six five four three two one "
check "sed n writes and reads the next" same "$($SED -n 'n;p' n | tr '\n' ' ')" "two four six eight ten "
check "sed n at the end writes once" same "$(printf 'a\n' | $SED 'n;d')" a
check "sed N joins" same "$($SED 'N;s/\n/+/' n | tr '\n' ' ')" "one+two three+four five+six seven+eight nine+ten "
check "sed N at the end quits without printing (POSIX)" same "$(printf 'a\nb\nc\n' | $SED 'N;s/\n/+/')" "a+b"
check "sed $!N keeps the last line" same "$(printf 'a\nb\nc\n' | $SED '$!N;s/\n/+/')" "a+b${nl}c"
check "sed P prints the first line" same "$(printf 'a\nb\n' | $SED -n 'N;P')" a
check "sed D restarts without reading" same "$(printf 'a\nb\nc\n' | $SED -n '$!N;P;D')" "a${nl}b${nl}c"
check "sed N;P;D (sliding window)" same "$($SED '$!N;/^\(.*\)\n\1$/!P;D' n | wc -l | tr -d ' ')" 10
check "sed uniq via N;P;D" same "$(printf 'a\na\nb\nb\nb\nc\n' | $SED '$!N;/^\(.*\)\n\1$/!P;D' | tr '\n' ' ')" "a b c "
check "sed q quits after printing" same "$($SED 3q n | tr '\n' ' ')" "one two three "
check "sed q writes appends" same "$(printf 'x\ny\n' | $SED '1{a\
z
q;}')" "x${nl}z"
check "sed b branches to the end" same "$($SED -n '/o/b
p' n | tr '\n' ' ')" "three five six seven eight nine ten "
check "sed : and b loop" same "$(echo aaaa | $SED ':x
s/a/b/
/a/bx')" bbbb
check "sed t branches after a substitution" same "$(printf 'ax\nbx\n' | $SED 's/a/A/
tdone
s/$/ no/
:done')" "Ax${nl}bx no"
check "sed: labels run to the end of the line" same "$($SED -n ':a;p' n)" ""
check "sed l shows invisible characters" same "$(printf 'a\tb\001\\\n' | $SED -n l)" 'a\tb\001\\$'
check "sed l folds long lines" same "$(printf '%s\n' abcdefghijklmnopqrstuvwxyz | COLUMNS=10 $SED -n l | head -n 1)" 'abcdefghi\'
check "sed keeps a missing last newline" same "$($SED s/no/NO/ nonl | wc -c | tr -d ' ')" 10
check "sed reads files as one stream" same "$($SED -n '$=' n n)" 20
check "sed -s is not an option" status_is 1 $SED -s p n
check "sed -e pieces join with newlines" same "$(echo x | $SED -e 'a\' -e 'y')" "x${nl}y"
cp n ip
check "sed -i '' edits in place" sh -c "$SED -i '' 's/one/ONE/' ip && [ \"\$(head -n 1 ip)\" = ONE ]"
check "sed -i ext keeps a backup" sh -c "$SED -i .bak '1d' ip && [ \"\$(head -n 1 ip.bak)\" = ONE ] && [ \"\$(head -n 1 ip)\" = two ]"
printf '1\n2\n' > i1
printf '3\n4\n' > i2
$SED -i '' '$d' i1 i2
check "sed -i: $ is each file's last line" same "$(cat i1 i2 | tr '\n' ' ')" "1 3 "
printf '1\n2\n' > i1
printf '3\n4\n' > i2
$SED -I '' '$d' i1 i2
check "sed -I: one stream" same "$(cat i1 i2 | tr '\n' ' ')" "1 2 3 "
check "sed -i with no file fails" status_is 1 $SED -i '' p
check "sed reports an unknown command" same "$($SED k n 2>&1)" "sed: 1: \"k\": unknown command: \`k'"
check "sed reports an unterminated s" status_is 1 $SED 's/a/b' n
check "sed reports a bad back-reference" status_is 1 $SED 's/a/\1/' n
check "sed reports an undefined label" status_is 1 $SED 'b nowhere' n
check "sed reports a missing }" status_is 1 $SED '/x/{p' n
check "sed reports a missing file but goes on" same "$($SED -n 1p nonexistent n 2>/dev/null)" one
check "and fails" status_is 1 $SED p nonexistent

# --- ed --------------------------------------------------------------------------------------
cp n e
edo() { printf "$1" | $ED -s e; }
check "ed reads a file and prints" same "$(edo ',p\n' | tr '\n' ' ')" "one two three four five six seven eight nine ten "
check "ed prints a byte count without -s" same "$(printf 'q\n' | $ED e)" 49
check "ed -p prompts" same "$(printf 'P\nq\n' | $ED -s -p '> ' e)" "> "
check "ed . and $ addresses" same "$(edo '3\n.p\n$p\n' | tr '\n' ' ')" "three three ten "
check "ed relative addresses" same "$(edo '5\n-2p\n+3p\n' | tr '\n' ' ')" "five three six "
check "ed ^ is -" same "$(edo '5\n^p\n' | tr '\n' ' ')" "five four "
check "ed , and % are 1,$" same "$(edo ',p\n%%p\n' | wc -l | tr -d ' ')" 20
check "ed ; is .,$" same "$(edo '8\n;p\n' | tr '\n' ' ')" "eight eight nine ten "
check "ed a;b sets . first" same "$(edo '2;+1p\n' | tr '\n' ' ')" "two three "
check "ed /re/ searches forward" same "$(edo '/i/p\n//p\n' | tr '\n' ' ')" "five six "
check "ed ?re? searches backward" same "$(edo '?o?p\n')" four
check "ed searches wrap around" same "$(edo '$\n/o/p\n' | tr '\n' ' ')" "ten one "
check "ed the null command prints the next line" same "$(edo '2\n\n\n' | tr '\n' ' ')" "two three four "
check "ed = prints $ by default" same "$(edo '=\n/six/=\n' | tr '\n' ' ')" "10 6 "
check "ed n numbers" same "$(edo '2n\n')" "2	two"
check "ed l lists" same "$(printf 'a\na\tb\n.\nl\nQ\n' | $ED -s)" 'a\tb$'
check "ed a appends" same "$(edo '2a\nx\ny\n.\n1,5p\nQ\n' | tr '\n' ' ')" "one two x y three "
check "ed 0a goes first" same "$(edo '0a\ntop\n.\n1p\nQ\n')" top
check "ed i inserts" same "$(edo '2i\nx\n.\n.,+1p\nQ\n' | tr '\n' ' ')" "x two "
check "ed c changes" same "$(edo '2,9c\nmid\n.\n,p\nQ\n' | tr '\n' ' ')" "one mid ten "
check "ed d deletes" same "$(edo '2,9d\n,p\nQ\n' | tr '\n' ' ')" "one ten "
check "ed d makes the next line current" same "$(edo '2d\n.p\nQ\n')" three
check "ed j joins" same "$(edo '1,3j\n1p\nQ\n')" onetwothree
check "ed m moves" same "$(edo '1,2m$\n,p\nQ\n' | tr '\n' ' ')" "three four five six seven eight nine ten one two "
check "ed m0 moves to the top" same "$(edo '$m0\n1p\nQ\n')" ten
check "ed m into itself fails" not sh -c "printf '1,3m2\n' | $ED -s e 2>/dev/null"
check "ed t copies" same "$(edo '1t2\n1,4p\nQ\n' | tr '\n' ' ')" "one two one three "
check "ed k and 'x" same "$(edo '3kx\n1\n'"'"'xp\n' | tr '\n' ' ')" "one three "
check "ed marks follow moved lines" same "$(edo '3ka\n3m0\n'"'"'a=\nQ\n')" 1
check "ed s" same "$(edo '1s/o/0/\n1p\nQ\n')" 0ne
check "ed s g" same "$(edo ',s/e/E/g\n3p\nQ\n')" thrEE
check "ed s count" same "$(edo '3s/e/E/2\n3p\nQ\n')" threE
check "ed s & and groups" same "$(edo '1s/\\(o\\)\\(n\\)/[&]\\2\\1/\n1p\nQ\n')" "[on]noe"
check "ed s p suffix" same "$(edo '2s/w/W/p\nQ\n')" tWo
check "ed s splits on an escaped newline" same "$(edo '1s/n/\\\n/\n1,2p\nQ\n' | tr '\n' ' ')" "o e "
check "ed s % is the last replacement" same "$(edo '1s/o/X/\n2s/w/%%/\n2p\nQ\n')" tXo
check "ed s alone repeats" same "$(edo '1s/e/E/\n3s\n3p\nQ\n')" thrEe
check "ed s with no match fails" not sh -c "printf 's/zzz/y/\n' | $ED -s e 2>/dev/null"
check "ed g runs a command on matches" same "$(edo 'g/o/s/$/!/\n,p\nQ\n' | tr '\n' ' ')" "one! two! three four! five six seven eight nine ten "
check "ed g// reuses the pattern in s" same "$(edo 'g/e/s//E/\n1,3p\nQ\n' | tr '\n' ' ')" "onE two thrEe "
check "ed g with no command prints" same "$(edo 'g/^t/\n' | tr '\n' ' ')" "two three ten "
check "ed g with several commands" same "$(edo 'g/^t/s/^/>/\\\ns/$/</\n,p\nQ\n' | head -n 3 | tr '\n' ' ')" "one >two< >three< "
check "ed v inverts g" same "$(edo 'v/e/d\n,p\nQ\n' | tr '\n' ' ')" "one three five seven eight nine ten "
check "ed g d deletes every match" same "$(edo 'g/o/d\n=\nQ\n')" 7
check "ed g m0 reverses" same "$(edo 'g/^/m0\n1p\n$p\nQ\n' | tr '\n' ' ')" "ten one "
check "ed G asks per line" same "$(edo 'G/^t/\np\n&\n\n' | tr '\n' ' ')" "two two three three ten "
check "ed u undoes" same "$(edo '1,5d\nu\n=\nQ\n')" 10
check "ed u twice redoes" same "$(edo '1,5d\nu\nu\n=\nQ\n')" 5
check "ed u undoes a whole g" same "$(edo 'g/e/d\nu\n=\nQ\n')" 10
check "ed w writes" sh -c "printf '1,2w e.out\nq\n' | $ED -s e && [ \"\$(cat e.out | tr '\n' ' ')\" = 'one two ' ]"
check "ed w prints the byte count" same "$(printf '1,2w e.out\nq\n' | $ED -s e; printf '1w e.out\nq\n' | $ED e | tail -n 1)" 4
check "ed W appends" sh -c "printf '1W e.out\nq\n' | $ED -s e && [ \"\$(wc -l < e.out | tr -d ' ')\" = 2 ]"
check "ed wq" sh -c "printf '1d\nwq\n' | $ED -s e && [ \"\$(head -n 1 e)\" = two ] && cp n e"
cp n e
check "ed r reads a file in" same "$(edo '1r pats\n1,4p\nQ\n' | tr '\n' ' ')" "one four nine two "
check "ed r !command" same "$(edo '0r !echo hi\n1p\nQ\n')" hi
check "ed w !command" same "$(edo '1,2w !cat\nQ\n')" "one${nl}two"
check "ed ! runs a command" same "$(printf '!echo hi\nq\n' | $ED -s)" hi
check "ed ! says ! without -s" same "$(printf '!true\nq\n' | $ED)" "!"
check "ed ! expands % to the file name" same "$(edo '!echo %%\nq\n')" "echo e${nl}e"
check "ed f prints the file name" same "$(edo 'f\n')" e
check "ed f sets it" same "$(edo 'f other\nf\n')" "other${nl}other"
check "ed e reads another file" same "$(edo 'e pats\n,p\n' | tr '\n' ' ')" "four nine "
check "ed q refuses unsaved changes" status_is 2 sh -c "printf '1d\nq\n' | $ED -s e"
check "ed Q discards them" status_is 0 sh -c "printf '1d\nQ\n' | $ED -s e"
check "ed: an error writes ?" same "$(printf 'zz\n' | $ED -s e 2>&1)" "?"
check "ed: off a terminal, an error ends it with status 2" status_is 2 sh -c "printf 'zz\n,p\n' | $ED -s e"
check "ed H explains errors" same "$(printf 'H\n100p\n' | $ED -s e 2>&1 | tail -n 1)" "script, line 2: invalid address"
check "ed an unreadable file is an error" status_is 2 sh -c "printf 'q\n' | $ED -s nonexistent"
check "ed z scrolls" same "$(edo '2z3\n' | tr '\n' ' ')" "two three four "
check "ed starts empty with no file" same "$(printf 'a\nx\n.\nw e2\nq\n' | $ED -s; cat e2)" x

# --- expr ------------------------------------------------------------------------------------
check "expr adds" same "$($EXPR 1 + 2)" 3
check "expr precedence" same "$($EXPR 1 + 2 \* 3)" 7
check "expr parentheses" same "$($EXPR \( 1 + 2 \) \* 3)" 9
check "expr subtracts left to right" same "$($EXPR 10 - 3 - 2)" 5
check "expr divides toward zero" same "$($EXPR -7 / 2)" -3
check "expr remainder" same "$($EXPR -7 % 2)" -1
check "expr negative operands" same "$($EXPR -3 \* -4)" 12
check "expr compares integers as numbers" same "$($EXPR 10 \> 9)" 1
check "expr compares strings as strings" same "$($EXPR 10 \> 9a)" 0
check "expr string equality" same "$($EXPR abc = abc)" 1
check "expr 01 = 1 as numbers" same "$($EXPR 01 = 1)" 1
check "expr != and <=" same "$($EXPR 2 != 3 \& 2 \<= 2)" 1
check "expr | gives the first if not null or zero" same "$($EXPR a \| b)" a
check "expr | gives the second otherwise" same "$($EXPR 0 \| b)" b
check "expr | of two nulls is 0" same "$($EXPR '' \| 0)" 0
check "expr & gives the first" same "$($EXPR a \& b)" a
check "expr & with a null is 0" same "$($EXPR a \& '')" 0
check "expr : counts matched bytes" same "$($EXPR abcdef : 'abc')" 3
check "expr : is anchored" same "$($EXPR abcdef : 'bc')" 0
check "expr : with .*" same "$($EXPR abcdef : '.*')" 6
check "expr : returns the group" same "$($EXPR abcdef : 'a\(.*\)e')" bcd
check "expr : group with no match is null" same "$($EXPR abc : 'x\(.*\)')" ""
check "expr : is a BRE" same "$($EXPR 'a+b' : 'a+')" 2
check "expr basename idiom" same "$($EXPR //usr/lib/libc.a : '.*/\(.*\)')" libc.a
check "expr exit 0 for a non-null result" status_is 0 $EXPR 1 + 1
check "expr exit 1 for zero" status_is 1 $EXPR 1 - 1
check "expr exit 1 for null" status_is 1 $EXPR '' : 'a'
check "expr exit 1 for a zero match count" status_is 1 $EXPR abc : x
check "expr exit 2 for a syntax error" status_is 2 $EXPR 1 +
check "expr exit 2 for a missing )" status_is 2 $EXPR \( 1
check "expr exit 2 for extra operands" status_is 2 $EXPR 1 2
check "expr exit 2 for a non-integer" status_is 2 $EXPR a + 1
check "expr exit 2 for division by zero" status_is 2 $EXPR 1 / 0
check "expr reports division by zero" same "$($EXPR 1 / 0 2>&1)" "expr: division by zero"
check "expr exit 2 for overflow" status_is 2 $EXPR 9223372036854775807 + 1
check "expr handles the extremes" same "$($EXPR -9223372036854775807 - 1)" -9223372036854775808
check "expr overflow of the minimum / -1" status_is 2 $EXPR -9223372036854775808 / -1
check "expr a lone operand is itself" same "$($EXPR hello)" hello
check "expr an operator alone is a string" same "$($EXPR =)" "="
check "expr = = = compares strings" same "$($EXPR = = =)" 1
check "expr skips a leading --" same "$($EXPR -- -1 + 1)" 0
check "expr bad regex is an error" status_is 2 $EXPR a : 'a\('

cd /
rm -rf $T
echo "bin3: $fail failed"
[ $fail -eq 0 ]
