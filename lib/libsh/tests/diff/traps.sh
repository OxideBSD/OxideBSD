# EXIT trap, trap listing, signal trap, subshell reset.
trap 'echo exit-trap $?' EXIT
trap 'echo got-usr1' USR1
kill -USR1 $$
echo after-kill
trap
(trap) | wc -l
trap - USR1
exit 3
