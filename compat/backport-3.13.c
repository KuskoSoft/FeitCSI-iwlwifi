/*
 * Copyright (c) 2013  Hauke Mehrtens <hauke@hauke-m.de>
 *
 * Backport functionality introduced in Linux 3.13.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regulator/driver.h>
#include <linux/device.h>

static void devm_rdev_release(struct device *dev, void *res)
{
	regulator_unregister(*(struct regulator_dev **)res);
}

/**
 * devm_regulator_register - Resource managed regulator_register()
 * @regulator_desc: regulator to register
 * @config: runtime configuration for regulator
 *
 * Called by regulator drivers to register a regulator.  Returns a
 * valid pointer to struct regulator_dev on success or an ERR_PTR() on
 * error.  The regulator will automatically be released when the device
 * is unbound.
 */
struct regulator_dev *devm_regulator_register(struct device *dev,
				  const struct regulator_desc *regulator_desc,
				  const struct regulator_config *config)
{
	struct regulator_dev **ptr, *rdev;

	ptr = devres_alloc(devm_rdev_release, sizeof(*ptr),
			   GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	rdev = regulator_register(regulator_desc, config);
	if (!IS_ERR(rdev)) {
		*ptr = rdev;
		devres_add(dev, ptr);
	} else {
		devres_free(ptr);
	}

	return rdev;
}
EXPORT_SYMBOL_GPL(devm_regulator_register);

static int devm_rdev_match(struct device *dev, void *res, void *data)
{
	struct regulator_dev **r = res;
	if (!r || !*r) {
		WARN_ON(!r || !*r);
		return 0;
	}
	return *r == data;
}

/**
 * devm_regulator_unregister - Resource managed regulator_unregister()
 * @regulator: regulator to free
 *
 * Unregister a regulator registered with devm_regulator_register().
 * Normally this function will not need to be called and the resource
 * management code will ensure that the resource is freed.
 */
void devm_regulator_unregister(struct device *dev, struct regulator_dev *rdev)
{
	int rc;

	rc = devres_release(dev, devm_rdev_release, devm_rdev_match, rdev);
	if (rc != 0)
		WARN_ON(rc);
}
EXPORT_SYMBOL_GPL(devm_regulator_unregister);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)) */
