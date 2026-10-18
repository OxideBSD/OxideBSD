/*
 * kern-smoke: on-target checks of the kernel's process and descriptor rules, one section per
 * file in this directory, each removing a shortcut from OxideBSD-doc CLEANUP.md. `kern-smoke
 * <section>` runs one section; /usr/tests/kern/run.sh runs them all. Runs as root; prints one
 * line per check and exits 0 if every check of the section passed.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(int ok, const char *what)
{
	printf("kern-smoke: %s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		failures++;
}

/* Runs fn in a child and returns its wait status. */
static int in_child(int (*fn)(void))
{
	pid_t pid = fork();
	if (pid == 0)
		_exit(fn());
	int status = -1;
	waitpid(pid, &status, 0);
	return status;
}

static int child_exit_ok(int (*fn)(void))
{
	int st = in_child(fn);
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

#include "rlimit.c"
#include "flock.c"
#include "orphan.c"

static const struct {
	const char *name;
	void (*run)(void);
} sections[] = {
	{ "rlimit", rlimit_main },
	{ "flock", flock_main },
	{ "orphan", orphan_main },
};

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 2) {
		fprintf(stderr, "usage: kern-smoke section\n");
		return 2;
	}
	for (size_t i = 0; i < sizeof sections / sizeof sections[0]; i++) {
		if (strcmp(argv[1], sections[i].name) == 0) {
			sections[i].run();
			printf("kern-smoke: %s: %d failed\n", argv[1], failures);
			return failures != 0;
		}
	}
	fprintf(stderr, "kern-smoke: no section %s\n", argv[1]);
	return 2;
}
