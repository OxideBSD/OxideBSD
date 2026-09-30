/*
 * tz-smoke: one localtime(3)/mktime(3) check for tests/tz_syscall_smoke.rs (TIMEZONE.md §6.1),
 * run by /usr/tests/tz/run.sh under whatever TZ and /etc/localtime it sets up.
 *
 *     tz-smoke EPOCH YYYY-MM-DDTHH:MM:SS GMTOFF ISDST
 *
 * Converts EPOCH with localtime(3) and compares the local time, UTC offset and daylight-saving
 * flag with the expected ones; then converts the result back with mktime(3), which must give
 * EPOCH again (across a transition, and for the hour that happens twice when clocks go back,
 * that needs the tm_isdst localtime(3) set). Prints what it got on a mismatch; exits 0 or 1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage: tz-smoke epoch local gmtoff isdst\n");
		return 2;
	}
	time_t t = (time_t)strtoll(argv[1], NULL, 10);
	long want_off = strtol(argv[3], NULL, 10);
	int want_dst = atoi(argv[4]);

	struct tm tm;
	if (!localtime_r(&t, &tm)) {
		printf("tz-smoke: localtime_r failed\n");
		return 1;
	}
	char got[32];
	strftime(got, sizeof got, "%Y-%m-%dT%H:%M:%S", &tm);
	int ok = 1;
	if (strcmp(got, argv[2]) != 0 || tm.tm_gmtoff != want_off || (tm.tm_isdst > 0) != want_dst) {
		printf("tz-smoke: %s is %s gmtoff=%ld isdst=%d (%s), expected %s gmtoff=%ld isdst=%d\n",
		       argv[1], got, tm.tm_gmtoff, tm.tm_isdst, tm.tm_zone, argv[2], want_off, want_dst);
		ok = 0;
	}
	time_t back = mktime(&tm);
	if (back != t) {
		printf("tz-smoke: mktime gave %lld for %s, expected %s\n", (long long)back, got, argv[1]);
		ok = 0;
	}
	return ok ? 0 : 1;
}
