# Compound commands, loops, break/continue levels, functions and return.
for i in 1 2 3; do
  for j in a b c; do
    [ $j = b ] && continue 2
    [ $i = 3 ] && break 2
    echo $i$j
  done
done
n=0; while [ $n -lt 3 ]; do n=$((n+1)); done; echo n=$n
until [ $n -eq 0 ]; do n=$((n-1)); done; echo n=$n
case foo.c in *.h) echo h;; *.c|*.cc) echo c;; *) echo other;; esac
case "a*b" in a\*b) echo literal-star;; esac
case x in [!a-c]) echo not-abc;; esac
case '' in '') echo empty;; esac
if false; then echo no; elif true; then echo elif; else echo else; fi
f() { echo "in f: $# $1"; g "$@"; echo "after g: $?"; }
g() { return 4; }
f one two
echo "positional kept: $#"
fact() { if [ $1 -le 1 ]; then echo 1; else echo $(( $1 * $(fact $(( $1 - 1 ))) )); fi; }
fact 6
! false; echo bang=$?
! true; echo bang=$?
true && false || echo andor=$?
{ echo brace; } > /dev/null; echo after-brace
(cd /; pwd); pwd >/dev/null
x=1; (x=2); echo x=$x
for w in $(echo one two); do echo w=$w; done
for p; do echo never; done
set -- p1 p2; for p; do echo p=$p; done
