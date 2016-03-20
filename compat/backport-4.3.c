/*
 * Copyright (c) 2015  Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (c) 2015 - 2016 Intel Deutschland GmbH
 *
 * Backport functionality introduced in Linux 4.3.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/seq_file.h>
#include <linux/export.h>
#include <linux/printk.h>
#include <linux/thermal.h>

#ifndef CONFIG_BTNS_PMIC
static int backport_thermal_get_temp(struct thermal_zone_device *dev,
				     unsigned long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_temp(dev, &_temp);
	if (!ret)
		*temp = (unsigned long)_temp;

	return ret;
}

static int backport_thermal_get_trip_temp(struct thermal_zone_device *dev,
					  int i, unsigned long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_trip_temp(dev, i,  &_temp);
	if (!ret)
		*temp = (unsigned long)_temp;

	return ret;
}

static int backport_thermal_set_trip_temp(struct thermal_zone_device *dev,
					  int i, unsigned long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_trip_temp(dev, i, (int)temp);
}

static int backport_thermal_get_trip_hyst(struct thermal_zone_device *dev,
					  int i, unsigned long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_trip_hyst(dev, i, &_temp);
	if (!ret)
		*temp = (unsigned long)_temp;

	return ret;
}

static int backport_thermal_set_trip_hyst(struct thermal_zone_device *dev,
					  int i, unsigned long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_trip_hyst(dev, i, (int)temp);
}

static int backport_thermal_get_crit_temp(struct thermal_zone_device *dev,
					  unsigned long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_crit_temp(dev, &_temp);
	if (!ret)
		*temp = (unsigned long)_temp;

	return ret;
}

static int backport_thermal_set_emul_temp(struct thermal_zone_device *dev,
					  unsigned long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_emul_temp(dev, (int)temp);
}
#else /* !CONFIG_BTNS_PMIC */
static int backport_thermal_get_temp(struct thermal_zone_device *dev,
				     long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_temp(dev, &_temp);
	if (!ret)
		*temp = (long)_temp;

	return ret;
}

static int backport_thermal_get_trip_temp(struct thermal_zone_device *dev,
					  int i, long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_trip_temp(dev, i,  &_temp);
	if (!ret)
		*temp = (long)_temp;

	return ret;
}

static int backport_thermal_set_trip_temp(struct thermal_zone_device *dev,
					  int i, long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_trip_temp(dev, i, (int)temp);
}

static int backport_thermal_get_trip_hyst(struct thermal_zone_device *dev,
					  int i, long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_trip_hyst(dev, i, &_temp);
	if (!ret)
		*temp = (long)_temp;

	return ret;
}

static int backport_thermal_set_trip_hyst(struct thermal_zone_device *dev,
					  int i, long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_trip_hyst(dev, i, (int)temp);
}

static int backport_thermal_get_crit_temp(struct thermal_zone_device *dev,
					  long *temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;
	int _temp, ret;

	ret = ops->_get_crit_temp(dev, &_temp);
	if (!ret)
		*temp = (long)_temp;

	return ret;
}

static int backport_thermal_set_emul_temp(struct thermal_zone_device *dev,
					  unsigned long temp)
{
	struct backport_thermal_zone_device_ops *ops =
		(struct backport_thermal_zone_device_ops *)dev->ops;

	return ops->_set_emul_temp(dev, (int)temp);
}
#endif /* !CONFIG_BTNS_PMIC */

struct thermal_zone_device *backport_thermal_zone_device_register(
	const char *type, int trips, int mask, void *devdata,
	struct backport_thermal_zone_device_ops *ops,
	const struct thermal_zone_params *tzp,
	int passive_delay, int polling_delay)
{
	/* It's okay to cast here, because the backport is a superset
	 * of the old struct.
	 */
	struct old_thermal_zone_device_ops *_ops =
		(struct old_thermal_zone_device_ops *)ops;

	/* store the registrant's ops for the backport ops to use */
#define copy_ops(_op) ops->_##_op = ops->_op
	copy_ops(get_temp);
	copy_ops(get_trip_temp);
	copy_ops(set_trip_temp);
	copy_ops(get_trip_hyst);
	copy_ops(set_trip_hyst);
	copy_ops(get_crit_temp);
	copy_ops(set_emul_temp);
#undef copy_ops

	/* Assign the backport ops to the old struct to get the
	 * correct types.  But only assign if the registrant defined
	 * the ops.
	 */
#define assign_ops(_op)		\
	if (ops->_op)		\
		_ops->_op = backport_thermal_##_op

	assign_ops(get_temp);
	assign_ops(get_trip_temp);
	assign_ops(set_trip_temp);
	assign_ops(get_trip_hyst);
	assign_ops(set_trip_hyst);
	assign_ops(get_crit_temp);
	assign_ops(set_emul_temp);
#undef assign_ops

	return old_thermal_zone_device_register(type, trips, mask, devdata,
						_ops, tzp, passive_delay,
						polling_delay);
}
EXPORT_SYMBOL_GPL(backport_thermal_zone_device_register);

void backport_thermal_zone_device_unregister(struct thermal_zone_device *dev)
{
	/* It's okay to cast here, because the backport is a superset
	 * of the old struct.
	 */
	struct thermal_zone_device_ops *ops =
		(struct thermal_zone_device_ops *)dev->ops;

	/* restore the registrant's original ops to the right place */
#define restore_ops(_op) ops->_op = ops->_##_op
	restore_ops(get_temp);
	restore_ops(get_trip_temp);
	restore_ops(set_trip_temp);
	restore_ops(get_trip_hyst);
	restore_ops(set_trip_hyst);
	restore_ops(get_crit_temp);
	restore_ops(set_emul_temp);
#undef restore_ops

	old_thermal_zone_device_unregister(dev);
}
EXPORT_SYMBOL_GPL(backport_thermal_zone_device_unregister);

static void seq_set_overflow(struct seq_file *m)
{
	m->count = m->size;
}

/* A complete analogue of print_hex_dump() */
void seq_hex_dump(struct seq_file *m, const char *prefix_str, int prefix_type,
		  int rowsize, int groupsize, const void *buf, size_t len,
		  bool ascii)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	int ret;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len && !seq_has_overflowed(m); i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			seq_printf(m, "%s%p: ", prefix_str, ptr + i);
			break;
		case DUMP_PREFIX_OFFSET:
			seq_printf(m, "%s%.8x: ", prefix_str, i);
			break;
		default:
			seq_printf(m, "%s", prefix_str);
			break;
		}

		ret = hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
					 m->buf + m->count, m->size - m->count,
					 ascii);
		if (ret >= m->size - m->count) {
			seq_set_overflow(m);
		} else {
			m->count += ret;
			seq_putc(m, '\n');
		}
	}
}
EXPORT_SYMBOL_GPL(seq_hex_dump);
