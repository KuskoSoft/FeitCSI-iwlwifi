#ifndef __BACKPORT_TIMKEEPING_H
#define __BACKPORT_TIMKEEPING_H
#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,16,0)
#include_next <linux/timekeeping.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
static inline __kernel_time_t ktime_get_seconds(void)
{
	struct timespec t;

	ktime_get_ts(&t);

	return t.tv_sec;
}
#endif

#endif /* __BACKPORT_TIMKEEPING_H */
