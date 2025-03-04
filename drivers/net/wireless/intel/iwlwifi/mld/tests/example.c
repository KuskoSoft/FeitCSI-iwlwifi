// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include <kunit/test.h>

#include <linux/nl80211.h>

#include "utils.h"
#include "mld.h"
#include "iface.h"
#include "link.h"
#include "phy.h"
#include "sta.h"

#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
#else
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
#endif

static void iwl_mld_kunit_test_example(struct kunit *test)
{
	struct iwl_mld *mld = test->priv;
	struct ieee80211_vif *vif;
	struct iwl_mld_vif *mld_vif;
	struct ieee80211_bss_conf *link;
	struct ieee80211_chanctx_conf *ctx;
	struct iwl_mld_phy *phy;
	struct ieee80211_sta *sta;
	struct iwl_mld_sta *mld_sta;

	/* Perform tests on the mld instance */
	KUNIT_EXPECT_PTR_EQ(test, mld->dev, mld->trans->dev);

	vif = iwlmld_kunit_add_vif(false, NL80211_IFTYPE_STATION);

	mld_vif = iwl_mld_vif_from_mac80211(vif);
	KUNIT_EXPECT_PTR_EQ(test, mld_vif->mld, mld);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(mld_vif->link[0]),
			    &mld_vif->deflink);
	KUNIT_EXPECT_FALSE(test, ieee80211_vif_is_mld(vif));

	vif = iwlmld_kunit_add_vif(true, NL80211_IFTYPE_STATION);
	mld_vif = iwl_mld_vif_from_mac80211(vif);

	KUNIT_EXPECT_NULL(test, rcu_access_pointer(vif->link_conf[0]));
	/* the vif is not considered as mld before a link is added */
	KUNIT_EXPECT_FALSE(test, ieee80211_vif_is_mld(vif));

	link = iwlmld_kunit_add_link(vif, 1);

	KUNIT_EXPECT_PTR_EQ(test, link->vif, vif);
	rcu_read_lock();
	KUNIT_EXPECT_NOT_NULL(test, iwl_mld_link_from_mac80211(link));
	rcu_read_unlock();
	KUNIT_EXPECT_TRUE(test, ieee80211_vif_is_mld(vif));

	ctx = iwlmld_kunit_add_chanctx(&chandef_2ghz_20mhz);

	phy = iwl_mld_phy_from_mac80211(ctx);
	KUNIT_ASSERT_EQ(test, ctx->def.chan->band, NL80211_BAND_2GHZ);
	KUNIT_EXPECT_MEMEQ(test, &phy->chandef, &ctx->min_def,
			   sizeof(phy->chandef));
	KUNIT_ASSERT_EQ(test, phy->fw_id, 0);

	wiphy_lock(mld->wiphy);
	iwlmld_kunit_assign_chanctx_to_link(vif, link, ctx);
	wiphy_unlock(mld->wiphy);

	KUNIT_EXPECT_TRUE(test, ieee80211_vif_link_active(vif, link->link_id));

	sta = iwlmld_kunit_setup_sta(vif, IEEE80211_STA_NONE, -1);

	KUNIT_EXPECT_PTR_EQ(test, sta->deflink.sta, sta);

	KUNIT_EXPECT_EQ(test, sta->valid_links, 0);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(sta->link[0]),
			    &sta->deflink);

	mld_sta = iwl_mld_sta_from_mac80211(sta);

	KUNIT_EXPECT_PTR_EQ(test, mld_sta->vif, vif);
	KUNIT_EXPECT_EQ(test, mld_sta->sta_state, IEEE80211_STA_NONE);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(mld_sta->link[0]),
			    &mld_sta->deflink);

	sta = iwlmld_kunit_setup_sta(vif, IEEE80211_STA_NONE, 1);

	KUNIT_EXPECT_EQ(test, sta->valid_links, BIT(1));
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(sta->link[1]),
			    &sta->deflink);
}

static void iwl_mld_kunit_assoc_example(struct kunit *test)
{
	struct ieee80211_vif *vif;
	struct iwl_mld_kunit_link assoc_link = {
		.id = 0,
		.chandef = &chandef_2ghz_40mhz,
	};
	u16 valid_links = 0x3;

	vif = iwlmld_kunit_setup_non_mlo_assoc(&assoc_link);

	KUNIT_ASSERT_NOT_NULL(test, vif);
	KUNIT_ASSERT_FALSE(test, ieee80211_vif_is_mld(vif));
	KUNIT_ASSERT_TRUE(test, vif->cfg.assoc);
	KUNIT_ASSERT_NOT_NULL(test, iwl_mld_vif_from_mac80211(vif)->ap_sta);

	vif = iwlmld_kunit_setup_mlo_assoc(valid_links, &assoc_link);

	KUNIT_ASSERT_NOT_NULL(test, vif);
	KUNIT_ASSERT_TRUE(test, ieee80211_vif_is_mld(vif));
	KUNIT_ASSERT_EQ(test, vif->valid_links, valid_links);
	KUNIT_ASSERT_EQ(test, vif->active_links, BIT(assoc_link.id));
}

static void iwl_mld_kunit_emlsr_example(struct kunit *test)
{
	struct ieee80211_vif *vif;
	struct ieee80211_sta *sta;
	struct iwl_mld_vif *mld_vif;
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_kunit_link link1 = {
		.id = 0,
		.chandef = &chandef_5ghz_40mhz,
	};
	struct iwl_mld_kunit_link link2 = {
		.id = 1,
		.chandef = &chandef_6ghz_160mhz,
	};
	u16 valid_links = BIT(link1.id) | BIT(link2.id);

	vif = iwlmld_kunit_assoc_emlsr(&link1, &link2);
	mld_vif = iwl_mld_vif_from_mac80211(vif);

	KUNIT_ASSERT_EQ(test, vif->valid_links, vif->active_links);
	KUNIT_ASSERT_NOT_NULL(test, rcu_access_pointer(vif->link_conf[0]));
	KUNIT_ASSERT_NOT_NULL(test, rcu_access_pointer(vif->link_conf[1]));

	sta = mld_vif->ap_sta;
	KUNIT_EXPECT_NOT_NULL(test, sta);

	KUNIT_EXPECT_EQ(test, sta->valid_links, valid_links);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(sta->link[0]),
			    &sta->deflink);
	KUNIT_EXPECT_NOT_NULL(test, rcu_access_pointer(sta->link[1]));

	mld_sta = iwl_mld_sta_from_mac80211(sta);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(mld_sta->link[0]),
			    &mld_sta->deflink);
	KUNIT_EXPECT_NOT_NULL(test, rcu_access_pointer(mld_sta->link[1]));
}

static struct kunit_case iwl_mld_kunit_test_cases[] = {
	KUNIT_CASE(iwl_mld_kunit_test_example),
	KUNIT_CASE(iwl_mld_kunit_assoc_example),
	KUNIT_CASE(iwl_mld_kunit_emlsr_example),
	{},
};

static struct kunit_suite iwl_mld_kunit_test_suite = {
	.name = "iwl_mld_kunit_test_suite",
	.test_cases = iwl_mld_kunit_test_cases,
	.init = iwlmld_kunit_test_init,
};

kunit_test_suite(iwl_mld_kunit_test_suite);
