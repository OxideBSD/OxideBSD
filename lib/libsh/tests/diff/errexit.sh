# set -e: not in conditions, not on the left of && / ||, not under !.
set -e
if false; then :; fi
false || true
! true
false && true
f() { false; echo "not reached in -e"; }
f || echo "f failed as condition"
echo before
(false)
echo not-reached
