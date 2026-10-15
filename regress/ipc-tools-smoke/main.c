/*
 * ipcs(1), ipcrm(1), the kern.ipc tables and security.bsd.see_other_uids (OxideBSD-doc
 * SYSCTL.md §5.2). Run as root by regress/ipc-tools-syscall-smoke as
 * /usr/tests/ipc/ipc-tools-smoke; prints one line per check and exits 0 only if all pass.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(int ok, const char *what)
{
	printf("ipc-tools-smoke: %s: %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		failures++;
}

/* Runs `cmd`, returning its output (static) and storing its exit status. */
static const char *run(const char *cmd, int *status)
{
	static char out[16384];
	size_t n = 0;
	FILE *f = popen(cmd, "r");
	if (!f) {
		*status = -1;
		return "";
	}
	while (n < sizeof out - 1) {
		size_t r = fread(out + n, 1, sizeof out - 1 - n, f);
		if (r == 0)
			break;
		n += r;
	}
	out[n] = 0;
	int st = pclose(f);
	*status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	return out;
}

/* Whether `out` has a line starting with `kind`, then the identifier `id`. */
static int has_row(const char *out, char kind, int id)
{
	char want[32];
	snprintf(want, sizeof want, "%c %12d ", kind, id);
	for (const char *p = out; p; p = strchr(p, '\n')) {
		if (*p == '\n')
			p++;
		if (strncmp(p, want, strlen(want)) == 0)
			return 1;
	}
	return 0;
}

/* The number of records in a kern.ipc table, each {int id; int pad; struct *id_ds}, or -1. */
static int records(const char *name, size_t ds_size)
{
	size_t len = 0;
	if (sysctlbyname(name, 0, &len, 0, 0) != 0)
		return -1;
	if (len % (8 + ds_size) != 0)
		return -1;
	return (int)(len / (8 + ds_size));
}

/* Whether table `name` holds identifier `id`. */
static int table_has(const char *name, size_t ds_size, int id)
{
	char buf[8192];
	size_t len = sizeof buf;
	if (sysctlbyname(name, buf, &len, 0, 0) != 0)
		return 0;
	for (size_t off = 0; off + 8 + ds_size <= len; off += 8 + ds_size) {
		int rid;
		memcpy(&rid, buf + off, sizeof rid);
		if (rid == id)
			return 1;
	}
	return 0;
}

static int set_see_other_uids(int v)
{
	return sysctlbyname("security.bsd.see_other_uids", 0, 0, &v, sizeof v);
}

int main(void)
{
	setvbuf(stdout, 0, _IONBF, 0);
	const key_t shmkey = 0x4f78, semkey = 0x4f79;
	int shmid = shmget(shmkey, 8192, IPC_CREAT | IPC_EXCL | 0640);
	int semid = semget(semkey, 3, IPC_CREAT | IPC_EXCL | 0600);
	int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	check(shmid >= 0 && semid >= 0 && msqid >= 0, "a segment, a semaphore set and a queue");

	/* A segment removed while attached shows D; a queue's bytes show with -o. */
	int doomed = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	void *at = shmat(doomed, 0, 0);
	shmctl(doomed, IPC_RMID, 0);
	struct { long type; char text[5]; } msg = { 1, "hello" };
	msgsnd(msqid, &msg, 5, 0);

	check(records("kern.ipc.shmsegs", sizeof(struct shmid_ds)) >= 2, "kern.ipc.shmsegs holds whole records");
	check(table_has("kern.ipc.sema", sizeof(struct semid_ds), semid), "kern.ipc.sema has the set");
	check(table_has("kern.ipc.msqids", sizeof(struct msqid_ds), msqid), "kern.ipc.msqids has the queue");

	int st;
	const char *out = run("/usr/bin/ipcs", &st);
	check(st == 0, "ipcs exits 0");
	check(strstr(out, "IPC status from <running system> as of ") != 0, "ipcs: the heading");
	check(strstr(out, "Message Queues:") && strstr(out, "Shared Memory:") && strstr(out, "Semaphores:"),
	      "ipcs: all three kinds");
	check(has_row(out, 'm', shmid) && has_row(out, 's', semid) && has_row(out, 'q', msqid),
	      "ipcs: a row per object");
	char want[64];
	snprintf(want, sizeof want, "m %12d %12d --rw-r----- root", shmid, (int)shmkey);
	check(strstr(out, want) != 0, "ipcs: id, key, mode and owner");
	snprintf(want, sizeof want, "m %12d %12d D-rw-------", doomed, 0);
	check(strstr(out, want) != 0, "ipcs: D on a segment removed while attached");

	out = run("/usr/bin/ipcs -qo", &st);
	snprintf(want, sizeof want, "q %12d", msqid);
	const char *row = strstr(out, want);
	check(st == 0 && row && strstr(row, " 5 ") && !strstr(out, "Shared Memory:"),
	      "ipcs -qo: only queues, with their bytes");
	out = run("/usr/bin/ipcs -a", &st);
	check(st == 0 && strstr(out, "NATTCH") && strstr(out, "QBYTES") && strstr(out, "NSEMS") &&
	      strstr(out, "CREATOR") && strstr(out, "CPID") && strstr(out, "OTIME"),
	      "ipcs -a: every column");
	out = run("/usr/bin/ipcs -T", &st);
	check(st == 0 && strstr(out, "shmmax") && strstr(out, "semmni") && strstr(out, "msgmax") &&
	      !strstr(out, "Semaphores:"),
	      "ipcs -T: the limits alone");
	out = run("/usr/bin/ipcs -u user", &st);
	check(st == 0 && !has_row(out, 'm', shmid), "ipcs -u user: not root's objects");
	out = run("/usr/bin/ipcs -u root", &st);
	check(st == 0 && has_row(out, 'm', shmid), "ipcs -u root: root's objects");

	/* musl's x86_64 semid_ds, as IPC_STAT fills it (it used to get the generic, shorter one). */
	struct semid_ds sds0;
	check(semctl(semid, 0, IPC_STAT, &sds0) == 0 && sds0.sem_nsems == 3 && sds0.sem_ctime > 1000000000,
	      "semctl IPC_STAT: sem_nsems 3, a real sem_ctime");

	/* see_other_uids=0: an unprivileged process sees neither root's objects nor processes. */
	check(set_see_other_uids(0) == 0, "security.bsd.see_other_uids=0");
	pid_t pid = fork();
	if (pid == 0) {
		if (setgid(1000) != 0 || setuid(1000) != 0)
			_exit(10);
		if (table_has("kern.ipc.shmsegs", sizeof(struct shmid_ds), shmid))
			_exit(11);
		int mine = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
		if (!table_has("kern.ipc.shmsegs", sizeof(struct shmid_ds), mine))
			_exit(12);
		shmctl(mine, IPC_RMID, 0);
		if (access("/proc/1/status", F_OK) == 0)
			_exit(13);
		char self[32];
		snprintf(self, sizeof self, "/proc/%d/status", (int)getpid());
		if (access(self, F_OK) != 0)
			_exit(14);
		int v = 1;
		if (sysctlbyname("security.bsd.see_other_uids", 0, 0, &v, sizeof v) == 0)
			_exit(15);
		_exit(0);
	}
	int cst;
	waitpid(pid, &cst, 0);
	check(WIFEXITED(cst) && WEXITSTATUS(cst) == 0,
	      "unprivileged: root's IPC and processes hidden, its own seen, the sysctl root-only");
	if (WIFEXITED(cst) && WEXITSTATUS(cst) != 0)
		printf("ipc-tools-smoke: the unprivileged child exited %d\n", WEXITSTATUS(cst));
	check(table_has("kern.ipc.shmsegs", sizeof(struct shmid_ds), shmid) && access("/proc/1/status", F_OK) == 0,
	      "root still sees everything");
	check(set_see_other_uids(1) == 0, "security.bsd.see_other_uids=1 again");

	/* ipcrm, by key and by identifier. */
	char cmd[128];
	snprintf(cmd, sizeof cmd, "/usr/bin/ipcrm -M 0x%x -s %d -q %d", (unsigned)shmkey, semid, msqid);
	run(cmd, &st);
	check(st == 0, "ipcrm -M key -s id -q id exits 0");
	check(shmget(shmkey, 0, 0) == -1 && errno == ENOENT, "ipcrm -M: the key is gone");
	struct semid_ds sds;
	check(semctl(semid, 0, IPC_STAT, &sds) == -1, "ipcrm -s: the set is gone");
	check(!table_has("kern.ipc.msqids", sizeof(struct msqid_ds), msqid), "ipcrm -q: the queue is gone");
	snprintf(cmd, sizeof cmd, "/usr/bin/ipcrm -q %d 2>/dev/null", msqid);
	run(cmd, &st);
	check(st == 1, "ipcrm of a missing queue exits 1");

	/* -W removes everything left; the attached segment goes when detached. */
	int extra = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
	run("/usr/bin/ipcrm -W", &st);
	check(st == 0 && semctl(extra, 0, IPC_STAT, &sds) == -1, "ipcrm -W removes everything");
	shmdt(at);
	check(records("kern.ipc.shmsegs", sizeof(struct shmid_ds)) == 0 &&
	      records("kern.ipc.sema", sizeof(struct semid_ds)) == 0 &&
	      records("kern.ipc.msqids", sizeof(struct msqid_ds)) == 0,
	      "the tables are empty");

	printf("ipc-tools-smoke: %s\n", failures ? "FAILED" : "all passed");
	return failures ? 1 : 0;
}
