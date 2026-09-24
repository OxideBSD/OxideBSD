# On-target check for OxideBSD's shell (INIT_SH.md §8.3), seeded as /sh-smoke/run.sh next to the
# differential scripts and the output dash gave for each on the development host.
#
#   run.sh SHELL   -- runs every *.sh beside run.sh under SHELL; exits 0 if all match.
shell=${1:?usage: run.sh shell}
dir=${0%/*}
fail=0
total=0
for t in "$dir"/*.sh; do
    [ "$t" = "$0" ] && continue
    total=$((total + 1))
    got=$(cd /tmp && "$shell" "$t" 2>/dev/null; echo "rc=$?")
    want=$(cat "${t%.sh}.expected")
    if [ "$got" = "$want" ]; then
        echo "sh-smoke: $shell ${t##*/}: ok"
    else
        fail=$((fail + 1))
        echo "sh-smoke: $shell ${t##*/}: FAIL"
        echo "--- got"
        echo "$got"
        echo "--- want"
        echo "$want"
    fi
done
echo "sh-smoke: $shell: $((total - fail))/$total"
[ "$fail" -eq 0 ]
