// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/dropreason.h>
#include <linux/thermal.h>

void drop_reasons_register_subsys(enum skb_drop_reason_subsys subsys,
				  const struct drop_reason_list *list)
{}
EXPORT_SYMBOL_GPL(drop_reasons_register_subsys);

void drop_reasons_unregister_subsys(enum skb_drop_reason_subsys subsys)
{}
EXPORT_SYMBOL_GPL(drop_reasons_unregister_subsys);

#ifdef CONFIG_THERMAL
void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return tzd->devdata;
}
EXPORT_SYMBOL_GPL(thermal_zone_device_priv);
#endif /* CONFIG_THERMAL */
