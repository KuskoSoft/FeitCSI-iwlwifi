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

#include "fw/api/scan.h"
#include "iwl-trans.h"
#include "mld.h"
#include "iface.h"
#include "link.h"
#include "phy.h"
#include "sta.h"

#define KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, size)			\
do {									\
	(ptr) = kunit_kzalloc((test), (size), GFP_KERNEL);		\
	KUNIT_ASSERT_NOT_NULL((test), (ptr));				\
} while (0)

#define KUNIT_ALLOC_AND_ASSERT(test, ptr)				\
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, sizeof(*(ptr)))

int iwlmld_kunit_test_init(struct kunit *test)
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

	fw->ucode_capa.num_stations = IWL_STATION_COUNT_MAX;

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

static void iwlmld_kunit_init_link(struct ieee80211_vif *vif,
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
struct ieee80211_vif *iwlmld_kunit_add_vif(bool mlo, enum nl80211_iftype type)
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
	iwlmld_kunit_init_link(vif, &vif->bss_conf, &mld_vif->deflink, 0);

	return vif;
}

/* Use only for MLO vif */
struct ieee80211_bss_conf *
iwlmld_kunit_add_link(struct ieee80211_vif *vif, int link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct ieee80211_bss_conf *link;
	struct iwl_mld_link *mld_link;

	KUNIT_ALLOC_AND_ASSERT(test, link);
	KUNIT_ALLOC_AND_ASSERT(test, mld_link);

	iwlmld_kunit_init_link(vif, link, mld_link, link_id);
	vif->valid_links |= BIT(link_id);

	return link;
}

struct ieee80211_chanctx_conf *
iwlmld_kunit_add_chanctx_from_def(struct cfg80211_chan_def *def)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld = test->priv;
	struct ieee80211_chanctx_conf *ctx;
	struct iwl_mld_phy *phy;
	int fw_id;

	KUNIT_ALLOC_AND_ASSERT_SIZE(test, ctx, sizeof(*ctx) + sizeof(*phy));

	/* Setup the chanctx conf */
	ctx->def = *def;
	ctx->min_def = *def;
	ctx->ap = *def;

	/* and the iwl_mld_phy */
	phy = iwl_mld_phy_from_mac80211(ctx);

	fw_id = iwl_mld_allocate_fw_phy_id(mld);
	KUNIT_ASSERT_GE(test, fw_id, 0);

	phy->fw_id = fw_id;
	phy->chandef = *iwl_mld_get_chandef_from_chanctx(ctx);

	return ctx;
}

void iwlmld_kunit_assign_chanctx_to_link(struct ieee80211_vif *vif,
					 struct ieee80211_bss_conf *link,
					 struct ieee80211_chanctx_conf *ctx)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld = test->priv;
	struct iwl_mld_link *mld_link;

	KUNIT_EXPECT_NULL(test, rcu_access_pointer(link->chanctx_conf));
	rcu_assign_pointer(link->chanctx_conf, ctx);

	wiphy_lock(mld->wiphy);

	mld_link = iwl_mld_link_from_mac80211(link);

	KUNIT_EXPECT_NULL(test, rcu_access_pointer(mld_link->chan_ctx));
	KUNIT_EXPECT_FALSE(test, mld_link->active);

	rcu_assign_pointer(mld_link->chan_ctx, ctx);
	mld_link->active = true;

	if (ieee80211_vif_is_mld(vif))
		vif->active_links |= BIT(link->link_id);

	wiphy_unlock(mld->wiphy);
}

IWL_MLD_ALLOC_FN(link_sta, link_sta)

static void iwlmld_kunit_add_link_sta(struct ieee80211_sta *sta,
				      struct ieee80211_link_sta *link_sta,
				      u8 link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld = test->priv;
	u8 fw_id;
	int ret;

	/* Allocate a sta id and map it to the link_sta object */
	ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
	KUNIT_ASSERT_EQ(test, ret, 0);

	link_sta->link_id = link_id;
	rcu_assign_pointer(sta->link[link_id], link_sta);

	link_sta->sta = sta;
}

/* Allocate and initialize a STA with the first link_sta */
static struct ieee80211_sta *
iwlmld_kunit_add_sta(struct ieee80211_vif *vif, int link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct ieee80211_sta *sta;
	struct iwl_mld_sta *mld_sta;

	/* Allocate memory for ieee80211_sta with embedded iwl_mld_sta */
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, sta, sizeof(*sta) + sizeof(*mld_sta));

	/* TODO: allocate and initialize the TXQs ? */

	mld_sta = iwl_mld_sta_from_mac80211(sta);
	mld_sta->vif = vif;

	/* TODO: adjust for internal stations */
	mld_sta->sta_type = STATION_TYPE_PEER;

	if (link_id >= 0) {
		iwlmld_kunit_add_link_sta(sta, &sta->deflink, link_id);
		sta->valid_links = BIT(link_id);
	} else {
		iwlmld_kunit_add_link_sta(sta, &sta->deflink, 0);
	}
	return sta;
}

/* Move s STA to a state */
static void iwlmld_kunit_move_sta_state(struct ieee80211_vif *vif,
					struct ieee80211_sta *sta,
					enum ieee80211_sta_state state)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_vif *mld_vif;

	/* The sta will be removed automatically at the end of the test */
	KUNIT_ASSERT_NE(test, state, IEEE80211_STA_NOTEXIST);

	mld_sta = iwl_mld_sta_from_mac80211(sta);
	mld_sta->sta_state = state;

	mld_vif = iwl_mld_vif_from_mac80211(mld_sta->vif);
	mld_vif->authorized = state == IEEE80211_STA_AUTHORIZED;

	if (vif->type == NL80211_IFTYPE_STATION && !sta->tdls)
		mld_vif->ap_sta = sta;
}

struct ieee80211_sta *iwlmld_kunit_setup_sta(struct ieee80211_vif *vif,
					     enum ieee80211_sta_state state,
					     int link_id)
{
	struct kunit *test = kunit_get_current_test();
	struct ieee80211_sta *sta;

	/* The sta will be removed automatically at the end of the test */
	KUNIT_ASSERT_NE(test, state, IEEE80211_STA_NOTEXIST);

	/* First - allocate and init the STA */
	sta = iwlmld_kunit_add_sta(vif, link_id);

	/* Now move it all the way to the wanted state */
	for (enum ieee80211_sta_state _state = IEEE80211_STA_NONE;
	     _state <= state; _state++)
		iwlmld_kunit_move_sta_state(vif, sta, state);

	return sta;
}
