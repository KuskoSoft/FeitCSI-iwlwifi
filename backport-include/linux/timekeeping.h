#ifndef __BACKPORT_TIMKEEPING_H
#define __BACKPORT_TIMKEEPING_H
#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#include_next <linux/timekeeping.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline time_t ktime_get_seconds(void)
{
	struct timespec t;

	ktime_get_ts(&t);

	return t.tv_sec;
}
#endif

#endif /* __BACKPORT_TIMKEEPING_H */
