#!/bin/sh
# BusyBox applet self-test -- runs INSIDE OxideBSD, not on the host.
#
# Usage, at the hush prompt:
#   sh /test_busybox.sh
#
# A real POSIX-shell test harness now, not a flat sequence of hand-unrolled PASS/FAIL lines.
# `sh`'s own .config (target/busybox-sh/.config after a real build.rs run) used to have only
# CONFIG_HUSH/HUSH_INTERACTIVE/HUSH_JOB set -- HUSH_IF/HUSH_LOOPS/HUSH_CASE/HUSH_FUNCTIONS/
# HUSH_TICK/HUSH_TEST/... were all off (an `allnoconfig` artifact: it writes an explicit
# "not set" line for every symbol in the whole Kconfig tree up front, so the later `make
# oldconfig` pass -- which only fills in symbols with *no* prior answer -- never got a chance to
# apply hush's real `default y` for any of them). Fixed in `build.rs`'s
# `configure_busybox_single_applet` (see its own doc comment) by flipping those lines directly,
# the same way it already did for `HUSH_INTERACTIVE`/`HUSH_JOB`. This script both exercises real
# applets *and* doubles as the regression check for that fix: the "control flow smoke test"
# section below asserts `if`/`for`/`while`/`until`/`case`/functions/`local`/arithmetic/command
# substitution/brace expansion/`$RANDOM` all actually work, not just that they compiled in.
#
# `check`/`check_status`/`report` (below) accumulate into real `PASS`/`FAIL` shell variables via
# real `$((...))` arithmetic -- no longer marker files (`ok_<name>`/`bad_<name>`) tallied with
# `ls | wc -l` at the end, since that workaround existed only because hush had no working
# arithmetic or persistent variables across... itself (it always ran in one process; the marker
# files were purely a stand-in for a counter that didn't work yet). Most checks now capture a
# real applet's output directly via `$(...)` and compare it to an inline expected string, instead
# of writing both sides out to scratch files and running `cmp` -- real command substitution
# strips all trailing newlines on both the actual and hand-written-expected side uniformly, so a
# plain string comparison is exact without needing a byte-for-byte file compare.
#
# Two real, separate kernel bugs this script (or an earlier version of it) found live, both now
# fixed, still worth remembering here since nothing in `cargo test`/`clippy` would have caught
# either:
#
# 1. `oxidebsd_sys_exit` used to store a userland `exit(code)` value as the `wait4()` status
#    *unshifted*, instead of real `wait(2)`'s actual encoding (`WEXITSTATUS` in bits 8-15, low 7
#    bits zero for a normal exit). Any applet exiting normally with a nonzero code -- extremely
#    common -- had that raw low byte misread by hush's real `WIFSIGNALED`/`WTERMSIG` macros as
#    "terminated by signal N" (`exit(1)` decoded as `SIGHUP`), printing a spurious "Hangup" after
#    nearly any failing command and corrupting later commands in the same session. Fixed at the
#    source (see CLAUDE.md's Process/scheduler section) -- this script no longer needs to work
#    around it at all.
# 2. `oxfs_open` used to always return a read-only fd for a path that already existed, regardless
#    of `O_WRONLY`/`O_RDWR`/`O_APPEND`/`O_TRUNC` -- a file could only ever be written once, for
#    its entire lifetime. An earlier version of *this exact script* found it live (accumulating
#    PASS/FAIL lines into one shared results file via repeated `tee -a` started failing on the
#    second line). Fixed in `oxfs_open`/`oxfs_close` (see CLAUDE.md's Permission model section) --
#    the "overwrite an existing file" / "append to an existing file" checks below are the real
#    regression coverage for that fix, something the old file-per-check design could never have
#    exercised even by accident.
#
# `touch` on a path that already exists now succeeds for real too (`utimensat`'s own real
# existence-check semantics -- see CLAUDE.md's musl-port section: no per-inode timestamp fields
# exist to actually update, but a real `ENOENT`-vs-success distinction is enough to satisfy
# `touch.c`'s own fallback logic either way).
#
# --- Pre-v0.1 roster-wide expansion ---
#
# The original ~40 checks below only touched a small slice of the (then ~300, now 256-applet)
# roster. This pass adds real, asserted coverage for the great majority of the curated roster --
# not just "did it crash," but a known expected output/exit status wherever one can be pinned
# down without depending on wall-clock-sensitive or environment-sensitive formatting. It has NOT
# been run against a real boot yet (writing shell scripts blind, without being able to interact
# with a live hush prompt, is inherently a best-effort exercise) -- if a specific check below
# fails, first suspect the check itself (a flag this minimal `allnoconfig`+single-symbol BusyBox
# build didn't compile in, or an output format assumption that's slightly off) before assuming a
# real kernel regression; report back what actually printed and it'll get corrected.
#
# What's deliberately NOT exercised here, and why, is listed in one place near the bottom of this
# file (search for "NOT EXERCISED") rather than scattered as inline apologies -- daemons that
# would hang the script, real interactive-tty flows already documented elsewhere as manual-QEMU-
# only, anything that would mutate persistent on-disk system state (`/etc/passwd` et al.) in a way
# that would outlive this one test run, and applets needing external state this harness can't
# safely fabricate (no on-target compressor for some decompressors' roundtrip, no real hardware).

PASS=0
FAIL=0

# report NAME STATUS -- STATUS is a real 0/nonzero shell exit-status value (typically `$?` from
# the line just above, or 0/1 computed inline). Tallies into PASS/FAIL and prints straight away.
report() {
    name=$1
    status=$2
    if [ "$status" -eq 0 ]; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

# check NAME ACTUAL EXPECTED -- compares two strings directly (captured via $(...) at the call
# site), no scratch files or `cmp` needed.
check() {
    name=$1
    actual=$2
    expected=$3
    if [ "$actual" = "$expected" ]; then
        report "$name" 0
    else
        report "$name" 1
        echo "  actual:   $actual"
        echo "  expected: $expected"
    fi
}

# check_status NAME STATUS -- thin alias of report(), used at call sites that are asserting a
# real command's own exit status rather than comparing two strings.
check_status() {
    report "$1" "$2"
}

rm -rf /test_busybox_scratch
mkdir /test_busybox_scratch
cd /test_busybox_scratch

echo "=== OxideBSD BusyBox applet self-test ==="

echo "--- control flow smoke test (what build.rs's HUSH config fix actually turned on) ---"

# if / elif / else
if [ 1 -eq 2 ]; then
    ctrl_if="wrong branch"
elif [ 2 -eq 2 ]; then
    ctrl_if="elif branch"
else
    ctrl_if="wrong branch"
fi
check "if/elif/else" "$ctrl_if" "elif branch"

# for loop
ctrl_for=""
for word in one two three; do
    ctrl_for="$ctrl_for$word,"
done
check "for loop" "$ctrl_for" "one,two,three,"

# while loop
ctrl_while=0
i=0
while [ "$i" -lt 5 ]; do
    ctrl_while=$((ctrl_while + i))
    i=$((i + 1))
done
check "while loop" "$ctrl_while" "10"

# until loop
ctrl_until=0
until [ "$ctrl_until" -ge 3 ]; do
    ctrl_until=$((ctrl_until + 1))
done
check "until loop" "$ctrl_until" "3"

# case / esac, driven by a for loop over several inputs
ctrl_case=""
for word in apple banana cherry; do
    case "$word" in
        apple) ctrl_case="${ctrl_case}A" ;;
        banana) ctrl_case="${ctrl_case}B" ;;
        *) ctrl_case="${ctrl_case}?" ;;
    esac
done
check "case/esac" "$ctrl_case" "AB?"

# functions, local variables, arithmetic, and a real return value read back via $(...)
add_one() {
    local n=$1
    echo $((n + 1))
}
check "function + local + arithmetic" "$(add_one 41)" "42"

# command substitution -- both real forms
check 'command substitution $(...)' "$(echo nested)" "nested"
check 'command substitution `...`' "`echo nested`" "nested"

# arithmetic expansion on its own
check 'arithmetic $((...))' "$((6 * 7))" "42"

# brace expansion (a bash-compat extension, CONFIG_HUSH_BRACE_EXPANSION)
check "brace expansion" "$(echo {a,b,c})" "a b c"

# $RANDOM -- value is nondeterministic, so only assert it's a real nonempty decimal number
r1=$RANDOM
case "$r1" in
    ''|*[!0-9]*) check_status '$RANDOM produces a decimal number' 1 ;;
    *) check_status '$RANDOM produces a decimal number' 0 ;;
esac

echo "--- individual applets ---"

# --- echo / printf ---
check "echo" "$(echo hello world)" "hello world"
check "printf formatting" "$(printf '%s-%d' foo 7)" "foo-7"

# --- touch / test -f, including touch on an already-existing path ---
touch a.txt
check_status "touch creates a file" $?
[ -f a.txt ]
check_status "the touched file really exists" $?
touch a.txt
check_status "touch on an already-existing path (utimensat)" $?

# --- overwrite / append an existing file (the real regression check for the oxfs write-existing-
#     file fix noted above -- impossible to have exercised under the old one-write-per-file design) ---
echo "first" > overwrite.txt
echo "second" > overwrite.txt
check "overwrite an existing file" "$(cat overwrite.txt)" "second"

echo "first" > append.txt
echo "second" >> append.txt
check "append to an existing file" "$(cat append.txt)" "$(printf 'first\nsecond')"

# --- write/read via redirection + cat ---
echo "line one" > multi.txt
echo "line two" >> multi.txt
check "cat reads back written content" "$(cat multi.txt)" "$(printf 'line one\nline two')"

# --- wc (word-split to strip any column-padding whitespace real wc adds) ---
set -- $(wc -l < multi.txt)
check "wc -l counts lines" "$1" "2"

# --- head / tail ---
check "head -n 1" "$(head -n 1 multi.txt)" "line one"
check "tail -n 1" "$(tail -n 1 multi.txt)" "line two"

# --- cp / mv / rm ---
cp multi.txt copy.txt
[ -f copy.txt ]
check_status "cp created the destination" $?

mv copy.txt moved.txt
[ -f moved.txt ]
check_status "mv created the new name" $?
[ ! -f copy.txt ]
check_status "mv removed the old name" $?

rm moved.txt
[ ! -f moved.txt ]
check_status "rm removed the file" $?

# --- mkdir -p / rmdir (nested) ---
mkdir -p nest/deep
[ -d nest/deep ]
check_status "mkdir -p created nested dirs" $?

rmdir nest/deep
rmdir nest
[ ! -d nest ]
check_status "rmdir removed nested dirs" $?

# --- cut / sort / uniq ---
printf 'b:2\na:1\na:1\nc:3\n' > kv.txt

check "cut -d: -f1" "$(cut -d: -f1 kv.txt)" "$(printf 'b\na\na\nc')"
check "sort" "$(sort kv.txt)" "$(printf 'a:1\na:1\nb:2\nc:3')"
check "sort -u" "$(sort -u kv.txt)" "$(printf 'a:1\nb:2\nc:3')"
check "sort | uniq" "$(sort kv.txt | uniq)" "$(sort -u kv.txt)"

# --- grep ---
check "grep matches" "$(grep 'a:1' kv.txt)" "$(printf 'a:1\na:1')"
if grep -q zzz kv.txt; then
    check_status "grep -q reports no match" 1
else
    check_status "grep -q reports no match" 0
fi

# --- sed ---
echo abc > sed_in.txt
check "sed substitution" "$(sed 's/b/X/' sed_in.txt)" "aXc"

# --- tr ---
check "tr uppercases" "$(tr a-z A-Z < sed_in.txt)" "ABC"

# --- basename / dirname ---
check "basename" "$(basename /a/b/c.txt)" "c.txt"
check "dirname" "$(dirname /a/b/c.txt)" "/a/b"

# --- seq ---
check "seq" "$(seq 1 3)" "$(printf '1\n2\n3')"

# --- xargs ---
check "xargs -n 1 (default echo)" "$(printf 'one\ntwo\n' | xargs -n 1)" "$(printf 'one\ntwo')"

# --- chmod ---
chmod 600 a.txt
check_status "chmod succeeds" $?

# --- whoami (real uid/passwd-db path, see CLAUDE.md's Permission model section) ---
check "whoami reports root" "$(whoami)" "root"

# --- kill -0 on our own pid (real POSIX existence-check convention) ---
kill -0 $$
check_status "kill -0 finds a live process" $?

echo "--- text/data-processing applets (expanded pass) ---"

# --- true / false ---
true
check_status "true exits 0" $?
false
[ $? -ne 0 ]
check_status "false exits nonzero" $?
# `yes | head -n 3`: used to reliably OOM and panic the kernel (`memory allocation of 67239936
# bytes failed`) -- src/pipe.rs's buffer was an unbounded VecDeque<u8>, so a producer with no
# blocking syscall in its write loop (yes) never yielded the CPU on this non-preemptive kernel,
# starving the consumer (head) that would've closed its end and stopped it. Fixed by bounding the
# pipe at 64 KiB (real Linux's own default) with a real blocking writer -- see CLAUDE.md's BusyBox
# section and src/pipe.rs's module doc comment.
check "yes | head -n 3" "$(yes | head -n 3)" "$(printf 'y\ny\ny')"

# --- expr / factor / bc / dc (real arithmetic tools, not the shell's own $(( )) ) ---
check "expr multiplication" "$(expr 6 \* 7)" "42"
check "factor" "$(factor 12)" "12: 2 2 3"
check "bc" "$(echo '6*7' | bc)" "42"
check "dc (RPN)" "$(echo '6 7 * p' | dc)" "42"

# --- env / printenv (PATH=/bin is what process::spawn passes every process, see CLAUDE.md) ---
check "printenv PATH" "$(printenv PATH)" "/bin"
if env | grep -q '^PATH='; then
    check_status "env lists PATH" 0
else
    check_status "env lists PATH" 1
fi

# --- comm / cmp ---
printf 'a\nb\nc\n' > comm1.txt
printf 'b\nc\nd\n' > comm2.txt
check "comm shared lines (-12 -3 suppressed)" "$(comm -12 comm1.txt comm2.txt)" "$(printf 'b\nc')"
cp comm1.txt comm1_copy.txt
cmp comm1.txt comm1_copy.txt
check_status "cmp reports identical files equal" $?
if cmp -s comm1.txt comm2.txt; then
    check_status "cmp reports differing files unequal" 1
else
    check_status "cmp reports differing files unequal" 0
fi

# --- rev / tac / paste / fold / expand ---
check "rev" "$(echo abc | rev)" "cba"
check "tac" "$(printf 'a\nb\nc\n' | tac)" "$(printf 'c\nb\na')"
printf 'a\n' > paste1.txt
printf 'x\n' > paste2.txt
check "paste" "$(paste paste1.txt paste2.txt)" "$(printf 'a\tx')"
check "fold -w3" "$(echo abcdefgh | fold -w3)" "$(printf 'abc\ndef\ngh')"
check "expand -t4" "$(printf '\tx' | expand -t4)" "    x"

# --- tsort (single valid order for a simple linear chain) ---
check "tsort" "$(printf 'a b\nb c\n' | tsort)" "$(printf 'a\nb\nc')"

# --- uuencode / uudecode roundtrip (no fixed encoded constant needed) ---
printf 'roundtrip content\n' > uu_src.txt
uuencode uu_src.txt uu_src.txt > uu_src.uu
uudecode -o uu_dst.txt uu_src.uu
check "uuencode/uudecode roundtrip" "$(cat uu_dst.txt)" "$(cat uu_src.txt)"

# --- base64 / base32 (real, hand-verified RFC 4648 test vectors for "abc") ---
check "base64" "$(printf abc | base64)" "YWJj"
check "base32" "$(printf abc | base32)" "MFRGG==="

# --- md5sum / sha1sum / sha256sum / sha512sum (real NIST test vectors for "abc") ---
#
# The sha1sum/sha512sum expected constants below were WRONG in an earlier version of this
# script -- each one hand-typed one character short of the real digest (`...cd0d89`/`...fa54ca49`
# instead of the real `...cd0d89d`/`...fa54ca49f`), not a kernel/musl/BusyBox bug at all. Found by
# cross-checking against Python's own `hashlib` (ground truth) after BusyBox's real output stayed
# consistent (same "extra" trailing character, same file, every run) while everything else in this
# pass got root-caused and fixed -- a real bug should have been narrowed down by then; a persistent
# mismatch against a fixed, never-independently-verified constant is the classic sign the constant
# itself is the bug. md5sum/sha256sum's constants were re-verified the same way and are correct.
printf abc > hash_in.txt
set -- $(md5sum hash_in.txt)
check "md5sum" "$1" "900150983cd24fb0d6963f7d28e17f72"
set -- $(sha1sum hash_in.txt)
check "sha1sum" "$1" "a9993e364706816aba3e25717850c26c9cd0d89d"
set -- $(sha256sum hash_in.txt)
check "sha256sum" "$1" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
set -- $(sha512sum hash_in.txt)
check "sha512sum" "$1" "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

# --- gzip/gunzip, bzip2/bunzip2, lzop -- real on-target roundtrips (each applet provides both
#     directions, unlike unxz/unlzma/uncompress/unzip, which have no on-target compressor
#     counterpart in this roster -- see NOT EXERCISED below) ---
printf 'compress me\n' > comp_src.txt
gzip -c comp_src.txt > comp_src.gz
check "gzip/gunzip roundtrip" "$(gunzip -c comp_src.gz)" "$(cat comp_src.txt)"
bzip2 -c comp_src.txt > comp_src.bz2
check "bzip2/bunzip2 roundtrip" "$(bunzip2 -c comp_src.bz2)" "$(cat comp_src.txt)"
lzop -c comp_src.txt > comp_src.lzo
check "lzop roundtrip" "$(lzop -dc comp_src.lzo)" "$(cat comp_src.txt)"

# --- tar / cpio / ar -- real on-target archive roundtrips ---
tar cf comp_src.tar comp_src.txt
check "tar lists its own member" "$(tar tf comp_src.tar)" "comp_src.txt"

# -H newc is required for -o in this build (its own usage text says so: "-o Create (requires
# -H newc)") -- found live: a bare `cpio -o` prints usage and creates nothing (0-byte output),
# not a kernel bug, just a wrong invocation on this script's own part.
echo comp_src.txt | cpio -o -H newc > comp_src.cpio
check "cpio lists its own member" "$(cpio -it < comp_src.cpio)" "comp_src.txt"

ar rc comp_src.a comp_src.txt
check "ar lists its own member" "$(ar t comp_src.a)" "comp_src.txt"

# --- strings ---
printf 'hello world\0\1\2\3' > strings_in.bin
check "strings finds a printable run" "$(strings strings_in.bin)" "hello world"

echo "--- symlinks / hard links / raw link+unlink applets ---"

# --- ln -s / readlink (real InodeKind::Symlink, see CLAUDE.md) ---
ln -s a.txt symlink.txt
check "readlink follows a real symlink" "$(readlink symlink.txt)" "a.txt"

# --- ln (hard link) / the raw `link`/`unlink` applets (distinct from `ln`/`rm`) ---
echo hlcontent > hl_src.txt
ln hl_src.txt hl_dst.txt
check "ln hard link shares content" "$(cat hl_dst.txt)" "hlcontent"

link hl_src.txt hl_dst2.txt
check "link(2) applet shares content" "$(cat hl_dst2.txt)" "hlcontent"
unlink hl_dst2.txt
[ ! -f hl_dst2.txt ]
check_status "unlink(2) applet removed it" $?

# --- realpath ---
check "realpath resolves an absolute path" "$(realpath a.txt)" "/test_busybox_scratch/a.txt"

# --- mknod against this kernel's four real synthetic devices (major:minor, not path -- see
#     CLAUDE.md's device-node section: any node with major=1 minor=3 behaves like /dev/null) ---
mknod null_alias.dev c 1 3
echo "discarded" > null_alias.dev
check_status "mknod'd major=1 minor=3 node behaves like /dev/null" $?

# --- chroot (real per-process root-inode containment) ---
mkdir -p chroot_test/bin
cp /bin/true chroot_test/bin/true
chroot chroot_test /bin/true
check_status "chroot + exec a trivial program" $?

echo "--- filesystem misc syscalls (fsync/flock/ftruncate/fallocate/statfs/rlimit/sched) ---"

echo data > fsync_test.txt
fsync fsync_test.txt
check_status "fsync" $?
sync
check_status "sync" $?

truncate -s 100 trunc_test.txt
set -- $(wc -c < trunc_test.txt)
check "truncate -s 100 resizes the file" "$1" "100"

flock trunc_test.txt true
check_status "flock runs a command while holding the lock" $?

chown 0:0 a.txt
check_status "chown" $?
chgrp 0 a.txt
check_status "chgrp" $?

softlimit -m 10000000 true
check_status "softlimit (real SYS_PRLIMIT64, stored not enforced)" $?
nice -n 5 true
check_status "nice" $?

setsid true
check_status "setsid runs a trivial command in a new session" $?

# Short flags only -- this build's start_stop_daemon usage text shows no long-option support
# (CONFIG_LONG_OPTS-gated, off by default here; found live, `--start`/`--exec` were both rejected).
start -S -x /bin/true
check_status "start_stop_daemon starts a trivial program" $?

echo "--- mount table (mount --bind / mount -t tmpfs / umount / mountpoint) ---"

mkdir -p /mnt_tmpfs_test
mount -t tmpfs tmpfs /mnt_tmpfs_test
echo hi > /mnt_tmpfs_test/f.txt
check "tmpfs mount is real and writable" "$(cat /mnt_tmpfs_test/f.txt)" "hi"
umount /mnt_tmpfs_test
if mountpoint -q /mnt_tmpfs_test; then
    check_status "umount actually unmounted the tmpfs" 1
else
    check_status "umount actually unmounted the tmpfs" 0
fi

mkdir -p /bind_src_test /bind_dst_test
echo bound > /bind_src_test/f.txt
mount --bind /bind_src_test /bind_dst_test
check "bind mount is real and shares content" "$(cat /bind_dst_test/f.txt)" "bound"
umount /bind_dst_test

echo "--- /proc-backed applets ---"

check "nproc reports this kernel's single core" "$(nproc)" "1"

case "$(pidof sh)" in
    ''|*[!0-9\ ]*) check_status "pidof finds this script's own interpreter" 1 ;;
    *) check_status "pidof finds this script's own interpreter" 0 ;;
esac

case "$(pgrep sh)" in
    '') check_status "pgrep finds this script's own interpreter" 1 ;;
    *) check_status "pgrep finds this script's own interpreter" 0 ;;
esac

echo "--- clock applets ---"

case "$(date +%Y)" in
    ''|*[!0-9]*) check_status "date +%Y prints a real year" 1 ;;
    *) check_status "date +%Y prints a real year" 0 ;;
esac

t1=$(date +%s)
sleep 1
t2=$(date +%s)
elapsed=$((t2 - t1))
[ "$elapsed" -ge 1 ]
check_status "sleep 1 really elapses at least 1s of wall clock" $?

usleep 100000
check_status "usleep runs" $?

timeout 1 sleep 5
tstatus=$?
[ "$tstatus" -ne 0 ]
check_status "timeout kills a long-running sleep before it finishes" $?

echo "--- networking (real sockets + DNS, see CLAUDE.md's Real networking section) ---"

# ping to QEMU SLIRP's own gateway (10.0.2.2, src/net/ipv4.rs's GATEWAY_IP) is NOT hard-asserted:
# found live to fail even though nslookup/wget below (real DNS + a real TCP conversation) both
# succeed -- more likely a QEMU SLIRP quirk (some builds don't answer ICMP echo aimed at their own
# gateway address specifically, even while answering everything else) than a kernel bug, but not
# yet confirmed either way. Still run so a real crash/hang would be caught.
echo "--- ping -c 1 10.0.2.2 (not hard-asserted, see comment above) ---"
ping -c 1 10.0.2.2

nslookup example.com >/dev/null 2>&1
check_status "nslookup resolves a real hostname" $?

wget -q -O /dev/null http://example.com
check_status "wget fetches a real URL over plain HTTP" $?

echo "--- informational only (output not asserted -- environment/format-sensitive, but still exercised so a real crash or hang would still be caught) ---"

echo "--- find . -name a.txt ---"
find . -name a.txt

echo "--- stat a.txt ---"
stat a.txt

echo "--- du multi.txt ---"
du multi.txt

echo "--- diff on a changed line ---"
printf 'a\nb\n' > d1.txt
printf 'a\nc\n' > d2.txt
diff d1.txt d2.txt

echo "--- df ---"
df

echo "--- free ---"
free

echo "--- uptime ---"
uptime

echo "--- ps-family: pstree / minips ---"
pstree
minips

echo "--- ifconfig / route (real rtl8139 + default-gateway rule) ---"
ifconfig
route

echo "--- mkpasswd (crypt hash generation, doesn't touch /etc/passwd) ---"
mkpasswd -m sha512 testpassword

echo "--- makemime / reformime (MIME encode/decode, format not asserted) ---"
makemime -o mime_out.txt comp_src.txt

# NOT EXERCISED, deliberately, and why:
#
# - daemons that listen/block and would hang this script rather than return: httpd, ftpd, telnetd,
#   inetd, dnsd, tcpsvd, udpsvd, udhcpd, lpd, crond, ntpd.
# - needs a real remote peer or infrastructure this environment doesn't guarantee: nc, netcat,
#   telnet, traceroute, whois, rdate, lpq, lpr, fakeidentd, ssl_client, popmaildir, sendmail,
#   pscan, dhcprelay, dumpleases, dnsdomainname, arping.
# - real interactive-tty flows -- already documented elsewhere in this project as manual-QEMU-only
#   (real Ctrl+C/SIGINT, sulogin/getty tty takeover, password prompts read from /dev/tty directly
#   rather than stdin): login, getty, sulogin, su, cttyhack.
# - would mutate persistent on-disk system files (/etc/passwd, /etc/group, /etc/shadow) in a way
#   that outlives this one test run and could break real su/login testing afterward: adduser,
#   addgroup, delgroup, passwd, chpasswd, remove_shell (out_name `remove`), envuidgid, setuidgid.
# - dangerous to run unscoped (kills processes matching a pattern, could take out this script's own
#   interpreter or other live processes): killall5, pkill.
# - needs a real interactive/full-screen terminal takeover: vi, hexedit, man, watch, top, less
#   (BusyBox's own non-tty-output fallback behavior for `less` isn't reliable enough to assert).
# - decompression tools with no on-target compressor counterpart in this roster to roundtrip
#   against (unlike gzip/bzip2/lzop, which each provide both directions): unxz, xzcat, unlzma,
#   uncompress, unzip.
# - reads real hardware this kernel doesn't model (see CLAUDE.md's BusyBox gap analysis,
#   NEEDS_HARDWARE): volname, resize, ttysize, hwclock, rtcwake, adjtimex.
# - real destructive power state changes -- would kill the whole QEMU session, no test-exit-code
#   ever gets read: halt, poweroff (SYS_REBOOT's RB_AUTOBOOT path too, though not a listed applet).
# - hardware/proc stats with no meaningful assertion and uncertain real backing on this kernel:
#   lsof, fuser, lspci, lsusb, lsscsi, iostat, mpstat, nmeter, powertop, smemcap, taskset, renice,
#   pmap, dmesg, bootchartd, arp.
# - package-management tools with no real package repository or archive present to act on:
#   dpkg, dpkg_deb, rpm, rpm2cpio.

echo "=== summary ==="
echo "pass: $PASS  fail: $FAIL  total: $((PASS + FAIL))"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "$FAIL CHECK(S) FAILED"
    exit 1
fi
