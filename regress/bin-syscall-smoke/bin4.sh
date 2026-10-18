#!/bin/sh
#
# On-target check for gzip (gunzip, zcat) and tar, rewritten in Rust std, including tar's
# defences against hostile archives. Runs under /bin/sh (as root or not); prints one line per
# check and exits 0 if all pass. The programs under test are named by path ($BIN, /bin by
# default); scratch files go in $T (/tmp/bin4).

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022
BIN=${BIN:-/bin}
GZIP=
export GZIP

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "bin4: ok: $_desc"
	else
		echo "bin4: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
same() { cmp -s "$1" "$2"; }
T=${T:-/tmp/bin4}
rm -rf $T
mkdir -p $T
cd $T
gzip=$BIN/gzip
tar=$BIN/tar
# gunzip and zcat are the same program under other names.
ln -s $gzip $T/gunzip
ln -s $gzip $T/zcat

# A file worth compressing: a few hundred lines of repetitive text.
i=0
while [ $i -lt 400 ]; do
	echo "line $i of the test data, the quick brown fox jumps over the lazy dog"
	i=$((i + 1))
done > data
cp data data.orig

# --- gzip ------------------------------------------------------------------------------------
check "gzip replaces a file with file.gz" $gzip data
check "the original is gone" not test -e data
check "and the .gz exists" test -s data.gz
check "it is smaller" [ $(wc -c < data.gz) -lt $(wc -c < data.orig) ]
check "gzip -t accepts it" $gzip -t data.gz
check "gunzip restores it" $T/gunzip data.gz
check "with the same contents" same data data.orig
check "and removes the .gz" not test -e data.gz
check "gzip -k keeps the original" $gzip -k data
check "both exist" test -f data -a -f data.gz
check "gzip skips an existing .gz" status_is 1 $gzip data </dev/null
check "gzip -f replaces it" $gzip -f data
check "zcat writes to stdout" sh -c "$T/zcat data.gz > out && cmp -s out data.orig"
check "zcat keeps the .gz" test -f data.gz
check "gzip -dc is zcat" sh -c "$gzip -dc data.gz | cmp -s - data.orig"
check "gzip -c from a pipe" sh -c "cat data.orig | $gzip -c | $gzip -dc | cmp -s - data.orig"
check "-1 and -9 round trip" sh -c "$gzip -1 -c data.orig | $gzip -dc | cmp -s - data.orig && $gzip -9c data.orig | $gzip -dc | cmp -s - data.orig"
check "gzip -l lists sizes" sh -c "$gzip -l data.gz | grep -q ' data\$'"
check "gzip -S uses another suffix" sh -c "cp data.orig s && $gzip -S .zz s && test -f s.zz && $T/gunzip -S .zz s.zz && cmp -s s data.orig"
check "gunzip refuses an unknown suffix" status_is 1 $T/gunzip data.orig
check "gunzip turns .tgz into .tar" sh -c "$gzip -c data.orig > t.tgz && $T/gunzip t.tgz && cmp -s t.tar data.orig"

echo one > m1
echo two > m2
$gzip -c m1 > m.gz
$gzip -c m2 >> m.gz
check "members are expanded as one" [ "$($T/zcat m.gz)" = "one
two" ]
cp m.gz g.gz
echo junk >> g.gz
check "trailing garbage is a warning (exit 2)" status_is 2 $T/zcat g.gz
check "the data before it is written" [ "$($T/zcat g.gz 2>/dev/null)" = "one
two" ]
check "zcat refuses what is not gzip" status_is 1 $T/zcat data.orig
check "zcat -f passes it through" sh -c "$T/zcat -f data.orig | cmp -s - data.orig"
cp data.gz bad.gz
printf 'XXXXXXXX' | dd of=bad.gz bs=1 seek=200 conv=notrunc 2>/dev/null
check "gzip -t finds corruption" status_is 1 $gzip -t bad.gz
check "a bad file is not replaced" sh -c "$T/gunzip bad.gz 2>/dev/null; test -f bad.gz && ! test -e bad"

# Mode and times carry over; -N restores the stored name, but only inside this directory.
cp data.orig keep
chmod 640 keep
touch -t 200102030405 keep
$gzip keep
check "the .gz keeps the mode" [ "$(ls -l keep.gz | cut -c1-10)" = "-rw-r-----" ]
$T/gunzip keep.gz
check "and the time" [ "$(ls -l keep | cut -c1-10)" = "-rw-r-----" -a keep -ot data.orig ]
mkdir -p nd/sub
$gzip -nc data.orig > plain.gz
{ printf '\037\213\010\010\000\000\000\000\000\003../../evil\000'; tail -c +11 plain.gz; } > nd/sub/h.gz
check "gunzip -N reads a stored name" sh -c "cd nd/sub && $T/gunzip -N h.gz 2>/dev/null; true"
check "and writes it beside the input" sh -c "test -f nd/sub/evil && cmp -s nd/sub/evil data.orig"
check "never where the name points" not test -e $T/../evil -o -e nd/evil

mkdir -p r/s
cp data.orig r/a
cp data.orig r/s/b
check "gzip -r descends" sh -c "$gzip -r r && test -f r/a.gz -a -f r/s/b.gz"
check "gunzip -r too" sh -c "$T/gunzip -r r && cmp -s r/s/b data.orig"

# --- tar: creating and reading ------------------------------------------------------------
mkdir -p src/sub/deep src/empty
cp data.orig src/data
echo hello > src/a
ln src/a src/hard
ln -s a src/sym
chmod 751 src/sub
long=src/sub/deep/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
echo long > $long
check "tar -c" $tar -cf a.tar src
check "the archive is whole records" [ $(($(wc -c < a.tar) % 10240)) -eq 0 ]
check "tar -t lists it" sh -c "$tar -tf a.tar | grep -qx 'src/sub/deep/'"
check "a long name survives" sh -c "$tar -tf a.tar | grep -qx '$long'"
check "tar -tv shows links" sh -c "$tar -tvf a.tar | grep -q 'src/sym -> a' && $tar -tvf a.tar | grep -q 'src/hard link to src/a'"
mkdir x1
check "tar -x" $tar -xf a.tar -C x1
check "contents" sh -c "cmp -s x1/src/data data.orig && cmp -s x1/$long $long"
check "a hard link stays one" /bin/test x1/src/a -ef x1/src/hard
check "a symlink stays one" sh -c "test -h x1/src/sym && grep -qx hello x1/src/sym"
check "a mode survives" [ "$(ls -ld x1/src/sub | cut -c1-10)" = drwxr-x--x ]
check "old-style options" sh -c "cd x1 && $tar xf ../a.tar src/a"
check "tar -O" [ "$($tar -xOf a.tar src/a)" = hello ]
check "a pattern selects a directory" [ "$($tar -tf a.tar src/sub | wc -l | tr -d ' ')" = 3 ]
check "an unmatched pattern fails" status_is 1 $tar -tf a.tar nothere
check "--exclude" sh -c "! $tar -cf - --exclude '*data' src | $tar -tf - | grep -q data"
check "-C among the operands" sh -c "$tar -cf - -C src a -C sub deep | $tar -tf - | grep -qx deep/"
check "-s renames" sh -c "$tar -cf - -s ',^src,dst,' src | $tar -tf - | grep -qx dst/a"
check "--strip-components" sh -c "mkdir x2 && $tar -xf a.tar -C x2 --strip-components 1 && test -f x2/a"
check "tar -r appends" sh -c "cp a.tar r.tar && echo new > newf && $tar -rf r.tar newf && $tar -tf r.tar | tail -n 1 | grep -qx newf"
check "the appended archive still lists" [ $($tar -tf r.tar | wc -l) -eq $(($($tar -tf a.tar | wc -l) + 1)) ]
check "tar -k keeps an existing file" sh -c "echo mine > x1/src/a && $tar -xkf a.tar -C x1 src/a && grep -qx mine x1/src/a"
check "a pipe from tar -c to tar -x" sh -c "mkdir x3 && $tar -cf - src | $tar -xf - -C x3 && cmp -s x3/src/data data.orig"
check "tar -z" sh -c "$tar -czf a.tgz src && $gzip -t a.tgz"
check "reading recognises gzip" sh -c "$tar -tf a.tgz | grep -qx src/a"
check "zcat feeds tar" sh -c "$T/zcat a.tgz | $tar -tf - | grep -qx src/a"
if [ -x /sbin/zstd ]; then
	check "tar --zstd" sh -c "$tar --zstd -cf a.tzst src && $tar -tf a.tzst | grep -qx src/a"
fi
check "tar -j is refused" status_is 1 $tar -cjf a.tbz src
check "garbage is not an archive" sh -c "! $tar -tf data.orig 2>/dev/null"

# --- tar: hostile archives -----------------------------------------------------------------
mkdir -p evil/a evil/b outside victim
echo orig > outside/target
ln -s $T/outside evil/a/lnk
mkdir evil/b/lnk
echo evil > evil/b/lnk/through
ln -s $T/outside/target evil/a/f
echo replaced > evil/b/f
ln -s .. evil/a/up
mkdir evil/b/up
echo evil > evil/b/up/through2
# A link to outside, then a file "through" it; a link to a file, then a file of that name.
$tar -cf sym.tar -C evil/a lnk f up -C ../b lnk/through f up/through2
check "the symlink archive lists" [ $($tar -tf sym.tar | wc -l) -eq 6 ]
check "extracting it reports the attack" status_is 1 $tar -xf sym.tar -C victim
check "nothing went through the directory link" not test -e outside/through
check "nothing went through the .. link" not test -e $T/through2
check "the target file is untouched" grep -qx orig outside/target
check "the link was replaced by the file" sh -c "test -f victim/f && ! test -h victim/f && grep -qx replaced victim/f"
check "-P follows links" sh -c "mkdir victim2 && $tar -xPf sym.tar -C victim2 lnk lnk/through; test -f outside/through"
rm -f outside/through

mkdir -p deep/er
echo dotdot > dd
echo abs > $T/absfile
(cd deep/er && $tar -cPf $T/dd.tar ../../dd $T/absfile)
check "-P keeps .. and / names" sh -c "$tar -tf dd.tar | grep -qx ../../dd && $tar -tf dd.tar | grep -qx $T/absfile"
echo changed > $T/absfile
mkdir -p v3/a/b
check "extracting .. names fails" status_is 1 $tar -xf dd.tar -C v3/a/b
check "nothing landed above" sh -c "grep -qx dotdot dd && ! test -e v3/dd && ! test -e v3/a/dd"
check "the absolute name went inside" sh -c "grep -qx abs v3/a/b$T/absfile"
check "and not to its absolute place" grep -qx changed $T/absfile

mkdir -p hl/out
echo secret > hl/out/a
ln hl/out/a hl/out/b
(cd hl/out && $tar -cPf $T/hl.tar -s ',^\.\./out/b$,hb,' ../out/a ../out/b)
check "a hard link member names ../" sh -c "$tar -tvf hl.tar | grep -q 'hb link to ../out/a'"
mkdir v4
check "extracting it fails" status_is 1 $tar -xf hl.tar -C v4
check "no hard link was made" not test -e v4/hb

echo "bin4: $fail failed"
[ $fail -eq 0 ]
