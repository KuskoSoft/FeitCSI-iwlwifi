#ifndef __BACKPORT_SOC_CAMERA_H__
#define __BACKPORT_SOC_CAMERA_H__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#include_next <linux/platform_data/media/soc_camera_platform.h>
#else
#include <media/soc_camera_platform.h>
#endif /* < 4.4 */

#endif /* __BACKPORT_SOC_CAMERA_H__ */
