#ifndef __BACKPORT_BRCMNAND_PLAT_DATA_H
#define __BACKPORT_BRCMNAND_PLAT_DATA_H
#include <linux/version.h>

#if LINUX_VERSION_IS_GEQ(5,18,0)
#include_next <linux/platform_data/brcmnand.h>
#endif /* >= 5.18.0 */

#endif /* __BACKPORT_BRCMNAND_PLAT_DATA_H */
