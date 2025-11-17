#include <events.h>
#include "assertions.h"

struct cpu_usage_timer {
#ifdef _WIN32
	HANDLE thread;
	FILETIME usertimeBegin;
	FILETIME kerneltimeBegin;
#else
	clock_t ticksBegin;
#endif
	struct timeval timeBegin;
};
static void start_cpu_usage_timer(struct cpu_usage_timer *timer) {
#ifdef _WIN32
	int r;
	FILETIME createtime, exittime;
	timer->thread = GetCurrentThread();
	r = GetThreadTimes(timer->thread, &createtime, &exittime,
	    &timer->usertimeBegin, &timer->kerneltimeBegin);
	if (r==0) printf("GetThreadTimes failed.");
#else
	timer->ticksBegin = clock();
#endif

	events_timeofday(&timer->timeBegin, NULL);
}
#ifdef _WIN32
static int64_t filetime_to_100nsec(const FILETIME *ft)
{
	/* Number of 100-nanosecond units */
	int64_t n = ft->dwHighDateTime;
	n <<= 32;
	n += ft->dwLowDateTime;
	return n;
}
static double filetime_diff(const FILETIME *ftStart, const FILETIME *ftEnd)
{
	int64_t s, e, diff;
	double r;
	s = filetime_to_100nsec(ftStart);
	e = filetime_to_100nsec(ftEnd);
	diff = e - s;
	r = (double) diff;
	return r / 1.0e7;
}
#endif
#define	get_timersub(tvp, uvp, vvp)		\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {		\
			(vvp)->tv_sec--;			\
			(vvp)->tv_usec += 1000000;	\
		}								\
	} while (0)
static void get_cpu_usage(struct cpu_usage_timer *timer, double *secElapsedOut,
    double *secUsedOut, double *usageOut) {
#ifdef _WIN32
	double usertime_seconds, kerneltime_seconds;
	FILETIME createtime, exittime, usertimeEnd, kerneltimeEnd;
	int r;
#else
	clock_t ticksEnd;
#endif
	struct timeval timeEnd, timeDiff;
	double secondsPassed, secondsUsed;

#ifdef _WIN32
	r = GetThreadTimes(timer->thread, &createtime, &exittime,
	    &usertimeEnd, &kerneltimeEnd);
	if (r==0) printf("GetThreadTimes failed.");
	usertime_seconds = filetime_diff(&timer->usertimeBegin, &usertimeEnd);
	kerneltime_seconds = filetime_diff(&timer->kerneltimeBegin, &kerneltimeEnd);
	secondsUsed = kerneltime_seconds + usertime_seconds;
#else
	ticksEnd = clock();
	secondsUsed = (ticksEnd - timer->ticksBegin) / (double)CLOCKS_PER_SEC;
#endif
	events_timeofday(&timeEnd, NULL);
	get_timersub(&timeEnd, &timer->timeBegin, &timeDiff);
	secondsPassed = timeDiff.tv_sec + (timeDiff.tv_usec / 1.0e6);

	*secElapsedOut = secondsPassed;
	*secUsedOut = secondsUsed;
	*usageOut = secondsUsed / secondsPassed;
}

static void timeout_write_cb(sockfd_t fd, int event, void *arg) {
	if (event & EVENTS_WRITE){
		printf("write callback. should only see this once\n");
		events_set_event(fd, EVENTS_TIMEOUT);
		return;
	}

	if (event & EVENTS_TIMEOUT) {
		printf("timeout fired, time to end test\n");
	}

	events_del(fd);
}

int main(int argc, char **argv) {
	int ev;
	events_t *base;
	sockfd_t pair[2];
	struct cpu_usage_timer timer;
	double usage, secPassed, secUsed;

	/* Initialize the event library */
	if (events_init(1024) || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	if (!(base = events_create(60)))
		return (1);

	/* and watch for writability on one end of the pipe */
	/* Initialize a timeout to terminate the test */
	events_add(base, pair[1], EVENTS_WRITE | EVENTS_TIMEOUT, 1, timeout_write_cb, NULL);

	start_cpu_usage_timer(&timer);
	while (events_is_running(base))
		events_once(base, 10);

	/* cleanup */
	events_destroy(base);
	events_deinit();

	get_cpu_usage(&timer, &secPassed, &secUsed, &usage);

	/* attempt to calculate our cpu usage over the test should be
	   virtually nil */

	printf("usec used=%d, usec passed=%d, cpu usage=%.2f%%\n",
	    (int)(secUsed*1e6),
	    (int)(secPassed*1e6),
	    usage*100);

	if (usage > 50.0) /* way too high */
	  return 1;

	return 0;
}
