#ifndef __BACKPORT_SI4713_H
#define __BACKPORT_SI4713_H
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#include_next <linux/platform_data/media/si4713.h>
#else
#include <media/si4713.h>
#endif /* < 4.4 */

#endif /* __BACKPORT_SI4713_H */
