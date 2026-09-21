/* Derisk check for the fbdoom/doomgeneric port: this target disables SSE/MMX and builds with
 * "rustc-abi": "softfloat" (see x86_64-oxidebsd.json) -- classic Doom's own renderer is entirely
 * fixed-point, but doomgeneric's HUD/menu code or musl's own libc might still touch float
 * arithmetic or printf-style float formatting somewhere in the call graph. Exercise both a plain
 * float divide (compiler-generated soft-float call) and printf("%f", ...) (musl's own float
 * formatting path in stdio) before investing in the full port -- if this silently miscomputes or
 * crashes, that's cheaper to find here than mid-Doom-build.
 */
#include <stdio.h>

int main(void) {
	volatile double a = 355.0;
	volatile double b = 113.0;
	double pi_approx = a / b;
	printf("float-smoke: 355/113 = %f\n", pi_approx);

	volatile float x = 1.5f;
	volatile float y = 2.5f;
	float sum = x + y;
	printf("float-smoke: 1.5+2.5 = %f\n", (double)sum);

	if (pi_approx > 3.14 && pi_approx < 3.15 && sum == 4.0f) {
		printf("float-smoke: OK\n");
		return 0;
	}
	printf("float-smoke: FAIL\n");
	return 1;
}
