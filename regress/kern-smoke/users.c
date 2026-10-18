/*
 * kern-smoke users: the account tools (CLEANUP.md §7: only passwd(1) could change the account
 * database): useradd/usermod/userdel and groupadd (NetBSD/OpenBSD shape), pw(8) (FreeBSD's),
 * and vipw(8), on the test disk's /etc.
 */
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

static int sh(const char *cmd)
{
	int st = system(cmd);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

static int in_group(const char *group, const char *user)
{
	struct group *g = getgrnam(group);
	if (!g)
		return 0;
	for (char **m = g->gr_mem; *m; m++)
		if (strcmp(*m, user) == 0)
			return 1;
	return 0;
}

static int unprivileged_useradd(void)
{
	if (setgid(4247) != 0 || setuid(4247) != 0)
		return 10;
	return sh("/usr/sbin/useradd nobodyelse 2>/dev/null") != 0 ? 0 : 1;
}

static void users_main(void)
{
	check(sh("/usr/sbin/useradd -m -c Tester tester") == 0, "useradd -m");
	struct passwd *pw = getpwnam("tester");
	check(pw && pw->pw_uid >= 1000 && strcmp(pw->pw_dir, "/home/tester") == 0, "makes the account, uid 1000 up, home in /home");
	struct group *g = getgrnam("tester");
	check(pw && g && g->gr_gid == pw->pw_gid, "with a group of its own");
	struct stat st;
	check(pw && stat("/home/tester", &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == pw->pw_uid, "and its home, the user's");
	check(sh("/usr/sbin/useradd tester 2>/dev/null") != 0, "useradd refuses a name in use");

	check(sh("/usr/sbin/groupadd staff2") == 0 && getgrnam("staff2") != NULL, "groupadd");
	check(sh("/usr/sbin/usermod -G staff2 tester") == 0 && in_group("staff2", "tester"), "usermod -G adds a supplementary group");
	check(sh("/usr/sbin/pw usershow tester >/dev/null") == 0, "pw usershow");
	check(sh("/usr/sbin/pw lock tester") == 0 && sh("grep -q '^tester:\\*LOCKED\\*' /etc/master.passwd") == 0, "pw lock");
	check(sh("/usr/sbin/pw unlock tester") == 0 && sh("grep -q '^tester:\\*LOCKED\\*' /etc/master.passwd") != 0, "pw unlock");
	check(sh("/usr/sbin/pw groupmod staff2 -l staff3") == 0 && getgrnam("staff3") && !getgrnam("staff2"), "pw groupmod -l renames");
	check(sh("EDITOR=true /usr/sbin/vipw") == 0, "vipw with no change");
	check(sh("grep -q '^tester:' /etc/passwd") == 0, "leaves the database as it was");

	check(sh("/usr/sbin/userdel -r tester") == 0 && getpwnam("tester") == NULL, "userdel -r");
	check(stat("/home/tester", &st) != 0 && getgrnam("tester") == NULL, "removes the home and the user's group");
	check(sh("/usr/sbin/groupdel staff3") == 0 && getgrnam("staff3") == NULL, "groupdel");
	check(child_exit_ok(unprivileged_useradd), "only root adds users");
}
