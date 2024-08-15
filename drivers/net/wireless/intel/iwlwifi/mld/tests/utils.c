// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>
#include <kunit/test-bug.h>

#include "utils.h"

#include <linux/device.h>
#include <net/mac80211.h>
#include "fw/api/scan.h"
#include "iwl-trans.h"
#include "mld.h"
#include "iface.h"
#include "link.h"

#define KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, size)			\
do {									\
	(ptr) = kunit_kzalloc((test), (size), GFP_KERNEL);		\
	KUNIT_ASSERT_NOT_NULL((test), (ptr));				\
} while (0)

#define KUNIT_ALLOC_AND_ASSERT(test, ptr)				\
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, sizeof(*(ptr)))

int kunit_test_init(struct kunit *test)
{
	struct iwl_mld *mld;
	struct iwl_trans *trans;
	const struct iwl_cfg *cfg;
	struct iwl_fw *fw;
	struct ieee80211_hw *hw;

	KUNIT_ALLOC_AND_ASSERT(test, trans);
	KUNIT_ALLOC_AND_ASSERT(test, trans->dev);
	KUNIT_ALLOC_AND_ASSERT(test, cfg);
	KUNIT_ALLOC_AND_ASSERT(test, fw);
	KUNIT_ALLOC_AND_ASSERT(test, hw);
	KUNIT_ALLOC_AND_ASSERT(test, hw->wiphy);

	mutex_init(&hw->wiphy->mtx);

	/* Allocate and initialize the mld structure */
	KUNIT_ALLOC_AND_ASSERT(test, mld);
	iwl_construct_mld(mld, trans, cfg, fw, hw);

	mld->fwrt.trans = trans;
	mld->fwrt.fw = fw;
	mld->fwrt.dev = trans->dev;

	/* TODO: add priv_size to hw allocation and setup hw->priv to enable
	 * testing mac80211 callbacks
	 */

	KUNIT_ALLOC_AND_ASSERT(test, mld->nvm_data);
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, mld->scan.cmd,
				    sizeof(struct iwl_scan_req_umac_v17));
	mld->scan.cmd_size = sizeof(struct iwl_scan_req_umac_v17);

	/* This is not the state at the end of the regular opmode_start,
	 * but it is more common to need it. Explicitly undo this if needed.
	 */
	mld->trans->state = IWL_TRANS_FW_ALIVE;
	mld->fw_status.running = true;

	/* Avoid passing mld struct around */
	test->priv = mld;
	return 0;
}

IWL_MLD_ALLOC_FN(link, bss_conf)

static void kunit_init_link(struct ieee80211_vif *vif,
			    struct ieee80211_bss_conf *link,
			    struct iwl_mld_link *mld_link, int link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld = test->priv;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	/* setup mac80211 link */
	rcu_assign_pointer(vif->link_conf[link_id], link);
	link->link_id = link_id;
	link->vif = vif;
	link->beacon_int = 100;
	link->dtim_period = 3;
	link->qos = true;

	/* and mld_link */
	ret = iwl_mld_allocate_link_fw_id(mld, &mld_link->fw_id, link);
	KUNIT_ASSERT_EQ(test, ret, 0);
	rcu_assign_pointer(mld_vif->link[link_id], mld_link);
}

IWL_MLD_ALLOC_FN(vif, vif)

/* Helper function to add and initialize a VIF for KUnit tests */
struct ieee80211_vif *kunit_add_vif(bool mlo, enum nl80211_iftype type)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld = test->priv;
	struct ieee80211_vif *vif;
	struct iwl_mld_vif *mld_vif;
	int ret;

	/* TODO: support more types */
	KUNIT_ASSERT_EQ(test, type, NL80211_IFTYPE_STATION);

	KUNIT_ALLOC_AND_ASSERT_SIZE(test, vif,
				    sizeof(*vif) + sizeof(*mld_vif));

	vif->type = type;
	mld_vif = iwl_mld_vif_from_mac80211(vif);
	mld_vif->mld = mld;

	ret = iwl_mld_allocate_vif_fw_id(mld, &mld_vif->fw_id, vif);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* TODO: revisit (task=EHT) */
	if (mlo)
		return vif;

	/* Initialize the default link */
	kunit_init_link(vif, &vif->bss_conf, &mld_vif->deflink, 0);

	return vif;
}

/* Use only for MLO vif */
struct ieee80211_bss_conf *kunit_add_link(struct ieee80211_vif *vif,
					  int link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct ieee80211_bss_conf *link;
	struct iwl_mld_link *mld_link;

	KUNIT_ALLOC_AND_ASSERT(test, link);
	KUNIT_ALLOC_AND_ASSERT(test, mld_link);

	kunit_init_link(vif, link, mld_link, link_id);
	vif->valid_links |= BIT(link_id);

	return link;
}
