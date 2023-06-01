// SPDX-License-Identifier: GPL-2.0
#include <linux/thermal.h>

#ifdef CONFIG_THERMAL
void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return tzd->devdata;
}
EXPORT_SYMBOL_GPL(thermal_zone_device_priv);
#endif /* CONFIG_THERMAL */
