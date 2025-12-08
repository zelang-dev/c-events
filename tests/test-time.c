#include <events.h>
#include "assertions.h"

int called = 0;

#define NEVENT	1000

/* Structure to hold the state of our weak random number generator.
 */
struct _weakrand_state {
	uint32_t seed;
};
static struct _weakrand_state weakrand_state;

int32_t _weakrand_(struct _weakrand_state *state) {
	/* This RNG implementation is a linear congruential generator, with
	 * modulus 2^31, multiplier 1103515245, and addend 12345.  It's also
	 * used by OpenBSD, and by Glibc's TYPE_0 RNG.
	 *
	 * The linear congruential generator is not an industrial-strength
	 * RNG!  It's fast, but it can have higher-order patterns.  Notably,
	 * the low bits tend to have periodicity.
	 */
	state->seed = ((state->seed) * 1103515245 + 12345) & 0x7fffffff;
	return (int32_t)(state->seed);
}

static int rand_int(int n) {
	return _weakrand_(&weakrand_state) % n;
}

static void time_cb(actor_t *actor, void *args) {
	called++;

	if ((rand_int(NEVENT) % 2 || called < NEVENT))
		events_repeat_actor(actor, 1);
	else
		events_clear_actor(actor);
}

int main(int argc, char **argv) {
	events_t *base;
	int i;

	/* Initialize the event library */
	if (events_init(1024) || !(base = events_create(60)))
		return (1);

	for (i = 0; i < NEVENT; i++) {
		events_actor(base, i, time_cb, NULL);
	}

	while (events_is_running(base))
		events_once(base, 0);

	printf("events_timeouts=%d, called=%d, EVENT=%d\n", i, called, NEVENT);
	events_destroy(base);

	if (called >= NEVENT) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}
