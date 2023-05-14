#ifndef __BACKPORT_LINUX_THERMAL_H
#define __BACKPORT_LINUX_THERMAL_H
#include_next <linux/thermal.h>
#include <linux/version.h>

#ifdef CONFIG_THERMAL
#if LINUX_VERSION_IS_LESS(5,9,0)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return 0; }
#endif /* < 5.9.0 */

#if LINUX_VERSION_IS_LESS(6,0,0) && LINUX_VERSION_IS_GEQ(5,10,0)
struct thermal_trip {
	int temperature;
	int hysteresis;
	enum thermal_trip_type type;
};
#endif

#if LINUX_VERSION_IS_LESS(6,0,0)
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, int mask, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp,
					int passive_delay,
					int polling_delay);
#endif /* <6,0,0 */

#if LINUX_VERSION_IS_LESS(6,4,0)
void *thermal_zone_device_priv(struct thermal_zone_device *tzd);
#endif /* < 6.4.0 */
#else /* CONFIG_THERMAL */
#if LINUX_VERSION_IS_LESS(5,9,0)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return -ENODEV; }
#endif /* < 5.9.0 */

#if LINUX_VERSION_IS_LESS(6,0,0)
#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
static inline struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, int mask, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp,
					int passive_delay,
					int polling_delay)
{
	return NULL;
}
#endif

#if LINUX_VERSION_IS_LESS(6,4,0)
#define thermal_zone_device_priv LINUX_BACKPORT(thermal_zone_device_priv)
static inline void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return NULL;
}
#endif /* < 6.4.0 */
#endif /* CONFIG_THERMAL */

#if LINUX_VERSION_IS_LESS(5,9,0)
#define thermal_zone_device_enable LINUX_BACKPORT(thermal_zone_device_enable)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return 0; }

#define thermal_zone_device_disable LINUX_BACKPORT(thermal_zone_device_disable)
static inline int thermal_zone_device_disable(struct thermal_zone_device *tz)
{ return 0; }
#endif /* < 5.9 */

#if LINUX_VERSION_IS_LESS(4,9,0)
/* Thermal notification reason */
enum thermal_notify_event {
	THERMAL_EVENT_UNSPECIFIED, /* Unspecified event */
	THERMAL_EVENT_TEMP_SAMPLE, /* New Temperature sample */
	THERMAL_TRIP_VIOLATED, /* TRIP Point violation */
	THERMAL_TRIP_CHANGED, /* TRIP Point temperature changed */
	THERMAL_DEVICE_DOWN, /* Thermal device is down */
	THERMAL_DEVICE_UP, /* Thermal device is up after a down event */
	THERMAL_DEVICE_POWER_CAPABILITY_CHANGED, /* power capability changed */
	THERMAL_TABLE_CHANGED, /* Thermal table(s) changed */
	THERMAL_EVENT_KEEP_ALIVE, /* Request for user space handler to respond */
};

static inline void
backport_thermal_zone_device_update(struct thermal_zone_device *tz,
				    enum thermal_notify_event event)
{
	thermal_zone_device_update(tz);
}
#define thermal_zone_device_update LINUX_BACKPORT(thermal_zone_device_update)
#endif /* < 4.9 */

#endif /* __BACKPORT_LINUX_THERMAL_H */
