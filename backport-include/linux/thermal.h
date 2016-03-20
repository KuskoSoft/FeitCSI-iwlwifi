#ifndef __BACKPORT_LINUX_THERMAL_H
#define __BACKPORT_LINUX_THERMAL_H
#include_next <linux/thermal.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define thermal_notify_framework notify_thermal_framework
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0))
/* Declare the < 4.3.0 struct so we can use it when calling the outer
 * kernel.
 */
#ifndef CONFIG_BTNS_PMIC
struct old_thermal_zone_device_ops {
	int (*bind) (struct thermal_zone_device *,
		     struct thermal_cooling_device *);
	int (*unbind) (struct thermal_zone_device *,
		       struct thermal_cooling_device *);
	int (*get_temp) (struct thermal_zone_device *, unsigned long *);
	int (*get_mode) (struct thermal_zone_device *,
			 enum thermal_device_mode *);
	int (*set_mode) (struct thermal_zone_device *,
		enum thermal_device_mode);
	int (*get_trip_type) (struct thermal_zone_device *, int,
		enum thermal_trip_type *);
	int (*get_trip_temp) (struct thermal_zone_device *, int,
			      unsigned long *);
	int (*set_trip_temp) (struct thermal_zone_device *, int,
			      unsigned long);
	int (*get_trip_hyst) (struct thermal_zone_device *, int,
			      unsigned long *);
	int (*set_trip_hyst) (struct thermal_zone_device *, int,
			      unsigned long);
	int (*get_crit_temp) (struct thermal_zone_device *, unsigned long *);
	int (*set_emul_temp) (struct thermal_zone_device *, unsigned long);
	int (*get_trend) (struct thermal_zone_device *, int,
			  enum thermal_trend *);
	int (*notify) (struct thermal_zone_device *, int,
		       enum thermal_trip_type);
};
#else /* !CONFIG_BTNS_PMIC */
struct old_thermal_zone_device_ops {
	int (*bind) (struct thermal_zone_device *,
		     struct thermal_cooling_device *);
	int (*unbind) (struct thermal_zone_device *,
		       struct thermal_cooling_device *);
	int (*get_temp) (struct thermal_zone_device *, long *);
	int (*get_mode) (struct thermal_zone_device *,
			 enum thermal_device_mode *);
	int (*set_mode) (struct thermal_zone_device *,
		enum thermal_device_mode);
	int (*get_trip_type) (struct thermal_zone_device *, int,
		enum thermal_trip_type *);
	int (*get_trip_temp) (struct thermal_zone_device *, int, long *);
	int (*set_trip_temp) (struct thermal_zone_device *, int, long);
	int (*get_trip_hyst) (struct thermal_zone_device *, int, long *);
	int (*set_trip_hyst) (struct thermal_zone_device *, int, long);
	int (*get_slope) (struct thermal_zone_device *, long *);
	int (*set_slope) (struct thermal_zone_device *, long);
	int (*get_intercept) (struct thermal_zone_device *, long *);
	int (*set_intercept) (struct thermal_zone_device *, long);
	int (*get_crit_temp) (struct thermal_zone_device *, long *);
	int (*set_emul_temp) (struct thermal_zone_device *, unsigned long);
	int (*get_trend) (struct thermal_zone_device *, int,
			  enum thermal_trend *);
	int (*notify) (struct thermal_zone_device *, int,
		       enum thermal_trip_type);
};
#endif /* !CONFIG_BTNS_PMIC */

/* also add a way to call the old register and unregister functions */
static inline struct thermal_zone_device *old_thermal_zone_device_register(
	const char *type, int trips, int mask, void *devdata,
	struct old_thermal_zone_device_ops *_ops,
	const struct thermal_zone_params *_tzp,
	int passive_delay, int polling_delay)
{
	struct thermal_zone_device_ops *ops =
		(struct thermal_zone_device_ops *) _ops;

	/* cast the const away */
	struct thermal_zone_params *tzp =
		(struct thermal_zone_params *)_tzp;

	return thermal_zone_device_register(type, trips, mask, devdata,
					    ops, tzp, passive_delay,
					    polling_delay);
}

static inline
void old_thermal_zone_device_unregister(struct thermal_zone_device *dev)
{
	thermal_zone_device_unregister(dev);
}

#undef thermal_zone_device_ops
#ifndef CONFIG_BTNS_PMIC
struct backport_thermal_zone_device_ops {
	int (*bind) (struct thermal_zone_device *,
		     struct thermal_cooling_device *);
	int (*unbind) (struct thermal_zone_device *,
		       struct thermal_cooling_device *);
	int (*get_temp) (struct thermal_zone_device *, int *);
	int (*get_mode) (struct thermal_zone_device *,
			 enum thermal_device_mode *);
	int (*set_mode) (struct thermal_zone_device *,
		enum thermal_device_mode);
	int (*get_trip_type) (struct thermal_zone_device *, int,
		enum thermal_trip_type *);
	int (*get_trip_temp) (struct thermal_zone_device *, int, int *);
	int (*set_trip_temp) (struct thermal_zone_device *, int, int);
	int (*get_trip_hyst) (struct thermal_zone_device *, int, int *);
	int (*set_trip_hyst) (struct thermal_zone_device *, int, int);
	int (*get_crit_temp) (struct thermal_zone_device *, int *);
	int (*set_emul_temp) (struct thermal_zone_device *, int);
	int (*get_trend) (struct thermal_zone_device *, int,
			  enum thermal_trend *);
	int (*notify) (struct thermal_zone_device *, int,
		       enum thermal_trip_type);

	/* These ops hold the original callbacks set by the
	 * registrant, because we'll add our hooks to the ones called
	 * by the framework.  Luckily someone made this ops struct
	 * non-const so we can mangle them.
	 */
	int (*_get_temp) (struct thermal_zone_device *, int *);
	int (*_get_trip_temp) (struct thermal_zone_device *, int, int *);
	int (*_set_trip_temp) (struct thermal_zone_device *, int, int);
	int (*_get_trip_hyst) (struct thermal_zone_device *, int, int *);
	int (*_set_trip_hyst) (struct thermal_zone_device *, int, int);
	int (*_get_crit_temp) (struct thermal_zone_device *, int *);
	int (*_set_emul_temp) (struct thermal_zone_device *, int);
};
#else /* CONFIG_BTNS_PMIC */
struct backport_thermal_zone_device_ops {
	int (*bind) (struct thermal_zone_device *,
		     struct thermal_cooling_device *);
	int (*unbind) (struct thermal_zone_device *,
		       struct thermal_cooling_device *);
	int (*get_temp) (struct thermal_zone_device *, int *);
	int (*get_mode) (struct thermal_zone_device *,
			 enum thermal_device_mode *);
	int (*set_mode) (struct thermal_zone_device *,
		enum thermal_device_mode);
	int (*get_trip_type) (struct thermal_zone_device *, int,
		enum thermal_trip_type *);
	int (*get_trip_temp) (struct thermal_zone_device *, int, int *);
	int (*set_trip_temp) (struct thermal_zone_device *, int, int);
	int (*get_trip_hyst) (struct thermal_zone_device *, int, int *);
	int (*set_trip_hyst) (struct thermal_zone_device *, int, int);
	int (*get_slope) (struct thermal_zone_device *, int *);
	int (*set_slope) (struct thermal_zone_device *, int);
	int (*get_intercept) (struct thermal_zone_device *, int *);
	int (*set_intercept) (struct thermal_zone_device *, int);
	int (*get_crit_temp) (struct thermal_zone_device *, int *);
	int (*set_emul_temp) (struct thermal_zone_device *, int);
	int (*get_trend) (struct thermal_zone_device *, int,
			  enum thermal_trend *);
	int (*notify) (struct thermal_zone_device *, int,
		       enum thermal_trip_type);

	/* These ops hold the original callbacks set by the
	 * registrant, because we'll add our hooks to the ones called
	 * by the framework.  Luckily someone made this ops struct
	 * non-const so we can mangle them.
	 */
	int (*_get_temp) (struct thermal_zone_device *, int *);
	int (*_get_trip_temp) (struct thermal_zone_device *, int, int *);
	int (*_set_trip_temp) (struct thermal_zone_device *, int, int);
	int (*_get_trip_hyst) (struct thermal_zone_device *, int, int *);
	int (*_set_trip_hyst) (struct thermal_zone_device *, int, int);
	int (*_get_crit_temp) (struct thermal_zone_device *, int *);
	int (*_set_emul_temp) (struct thermal_zone_device *, int);
};
#endif /* CONFIG_BTNS_PMIC */
#define thermal_zone_device_ops LINUX_BACKPORT(thermal_zone_device_ops)

#undef thermal_zone_device_register
struct thermal_zone_device *backport_thermal_zone_device_register(
	const char *type, int trips, int mask, void *devdata,
	struct thermal_zone_device_ops *ops,
	const struct thermal_zone_params *tzp,
	int passive_delay, int polling_delay);

#define thermal_zone_device_register \
	LINUX_BACKPORT(thermal_zone_device_register)

#undef thermal_zone_device_unregister
void backport_thermal_zone_device_unregister(struct thermal_zone_device *);
#define thermal_zone_device_unregister			\
	LINUX_BACKPORT(thermal_zone_device_unregister)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0) && !defined(CONFIG_BTNS_PMIC) */

#endif /* __BACKPORT_LINUX_THERMAL_H */
