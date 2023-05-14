// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/thermal.h>

#ifdef CONFIG_THERMAL
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, int mask, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp, int passive_delay,
					int polling_delay)
{
	return thermal_zone_device_register(type, num_trips, mask, devdata, ops, tzp,
					    passive_delay, polling_delay);
}
EXPORT_SYMBOL_GPL(thermal_zone_device_register_with_trips);
#endif /* CONFIG_THERMAL */
