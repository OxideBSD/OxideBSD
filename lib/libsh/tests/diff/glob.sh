# Pathname expansion.
t=${TMPDIR:-/tmp}/libsh-glob-$$
mkdir -p "$t/d1" "$t/d2" && cd "$t" || exit 1
: > a.c; : > b.c; : > .hidden.c; : > 'c d.c'; : > d1/x.h
echo *.c
echo .*.c
echo */
echo d?/*.h
echo *.nomatch
echo "*.c" '*'.c \*.c
set -f; echo *.c; set +f
echo [ab].c [!a].c
for f in *.c; do printf '<%s>' "$f"; done; echo
cd /; rm -rf "$t"
