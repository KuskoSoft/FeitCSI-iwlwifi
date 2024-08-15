// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>

#include <linux/nl80211.h>

#include "utils.h"
#include "mld.h"
#include "iface.h"
#include "link.h"

MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);

static void iwl_mld_kunit_test_example(struct kunit *test)
{
	struct iwl_mld *mld = test->priv;
	struct ieee80211_vif *vif;
	struct iwl_mld_vif *mld_vif;

	/* Perform tests on the mld instance */
	KUNIT_EXPECT_PTR_EQ(test, mld->dev, mld->trans->dev);

	vif = kunit_add_vif(false, NL80211_IFTYPE_STATION);

	mld_vif = iwl_mld_vif_from_mac80211(vif);
	KUNIT_EXPECT_PTR_EQ(test, mld_vif->mld, mld);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(mld_vif->link[0]),
			    &mld_vif->deflink);

	vif = kunit_add_vif(true, NL80211_IFTYPE_STATION);

	KUNIT_EXPECT_NULL(test, rcu_access_pointer(vif->link_conf[0]));
}

static struct kunit_case iwl_mld_kunit_test_cases[] = {
	KUNIT_CASE(iwl_mld_kunit_test_example),
	{},
};

static struct kunit_suite iwl_mld_kunit_test_suite = {
	.name = "iwl_mld_kunit_test_suite",
	.test_cases = iwl_mld_kunit_test_cases,
	.init = kunit_test_init,
};

kunit_test_suite(iwl_mld_kunit_test_suite);
