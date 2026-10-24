/*
 * kern-smoke wallclock: a CMOS clock keeping local time (machdep.wall_cmos_clock, adjkerntz(8)).
 * The kernel corrects its clock once, by the zone's offset when both the setting and the offset
 * are known, in either order, and never again: a later offset (daylight saving time) or the
 * setting toggled moves nothing. Needs a boot where nothing has set kern.utc_offset yet (this
 * test's pid 1 runs no rc); the clock is put back at the end.
 */
#include <sys/sysctl.h>
#include <time.h>

static int set_int(const char *name, int v)
{
	return sysctlbyname(name, NULL, NULL, &v, sizeof v);
}

/* The clock's move from `before`, less the seconds that passed meanwhile (to within one). */
static long moved(time_t before)
{
	return (long)(time(NULL) - before);
}

static void wallclock_main(void)
{
	time_t t = time(NULL);
	check(set_int("kern.utc_offset", 90) == 0, "kern.utc_offset=90 with a UTC CMOS clock");
	check(labs(moved(t)) <= 1, "the clock didn't move");

	t = time(NULL);
	check(set_int("machdep.wall_cmos_clock", 1) == 0, "machdep.wall_cmos_clock=1");
	long m = moved(t);
	check(m <= -5399 && m >= -5401, "the clock went back by the offset, 90 minutes");

	t = time(NULL);
	check(set_int("kern.utc_offset", 150) == 0, "kern.utc_offset=150 (a later offset)");
	check(labs(moved(t)) <= 1, "the clock didn't move again");
	check(set_int("machdep.wall_cmos_clock", 0) == 0 && set_int("machdep.wall_cmos_clock", 1) == 0,
	    "machdep.wall_cmos_clock toggled");
	check(labs(moved(t)) <= 1, "nor for that");

	int v = -1;
	size_t len = sizeof v;
	check(sysctlbyname("machdep.wall_cmos_clock", &v, &len, NULL, 0) == 0 && v == 1, "reads back 1");
	check(set_int("kern.utc_offset", 0) == 0 && set_int("machdep.wall_cmos_clock", 0) == 0, "settings back");
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	now.tv_sec += 5400;
	check(clock_settime(CLOCK_REALTIME, &now) == 0, "the clock put back");
}
