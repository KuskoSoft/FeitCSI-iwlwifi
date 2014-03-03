#ifndef __BACKPORT_LINUX_IDI_DEVICE_PM_H
#define __BACKPORT_LINUX_IDI_DEVICE_PM_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include <mach/idi_device_pm.h>
#else
#include_next <linux/idi/idi_device_pm.h>
#endif

#endif /* __BACKPORT_LINUX_IDI_DEVICE_PM_H */
