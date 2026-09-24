# Built-ins: set, shift, eval, export, readonly, unset, getopts, read, command, type, printf.
set -- a b c d; shift 2; echo "$@"
eval 'x=evaluated; echo $x'
cmd='echo "q u"'; eval "$cmd"
export E1=exported; env | grep '^E1='
readonly R=1; (R=2) 2>/dev/null || echo readonly-ok
unset E1; echo "E1=[${E1-unset}]"
f() { echo func; }; unset -f f; command -v f >/dev/null || echo f-gone
while getopts ab:c opt -a -b arg -c -x rest 2>/dev/null; do echo "opt=$opt arg=${OPTARG-}"; done
echo OPTIND=$OPTIND
OPTIND=1; while getopts :b: opt -b; do echo "silent opt=$opt arg=$OPTARG"; done
printf '%s-%s\n' 1 2 3 4 5
printf '%03d|%+d|% d|%-5s|%5.1s|\n' 7 5 5 ab xyz
printf '%o %X %#x %c %%\n' 8 255 255 hello
printf '%b\n' 'tab\there' 'oct\0101'
printf '%d\n' "'A"
printf '%e %g %g %G\n' 12345.678 0.0001 1234567 1e-10
echo 'a\tb' "c\\nd"; echo -n no-newline; echo
command echo via-command
type cd | sed 's/ is .*//'
v=$(false); echo subst-status=$?
x=1 y=2 command true; echo "x=${x-} y=${y-}"
times >/dev/null && echo times-ok
umask 027; umask; umask -S; umask 022
read a b c <<EOF2
 1  2  3 4 
EOF2
echo "[$a][$b][$c]"
read -r raw <<'EOF2'
back\slash
EOF2
echo "$raw"
read cooked <<'EOF2'
back\slash cont\
inued
EOF2
echo "$cooked"
