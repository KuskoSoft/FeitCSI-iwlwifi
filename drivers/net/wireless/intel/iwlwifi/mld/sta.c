// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "sta.h"

static int
iwl_mld_fw_sta_id_from_link_sta(struct iwl_mld *mld,
				struct ieee80211_link_sta *link_sta)
{
	for (int fw_id = 0; fw_id < ARRAY_SIZE(mld->fw_id_to_link_sta);
	     fw_id++) {
		struct ieee80211_link_sta *l_sta;

		l_sta = rcu_access_pointer(mld->fw_id_to_link_sta[fw_id]);

		if (l_sta == link_sta)
			return fw_id;
	}
	return -ENOENT;
}

IWL_MLD_ALLOC_FN(link_sta, link_sta)

static int
iwl_mld_add_link_sta(struct iwl_mld *mld, struct ieee80211_link_sta *link_sta)
{
	int ret = 0;
	u8 fw_id;

	/* We need to preserve the fw sta ids during a restart, since the fw
	 * will recover SN/PN for them
	 */
	if (!mld->fw_status.in_hw_restart) {
		/* Allocate a fw id and map it to the link_sta */
		ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
		if (ret)
			return ret;
	}

	/* TODO: send command to add to FW */

	return ret;
}

static int
iwl_mvm_remove_link_sta(struct iwl_mld *mld,
			struct ieee80211_link_sta *link_sta)
{
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

	if (WARN_ON(fw_id < 0))
		return fw_id;

	/* TODO: send command to remove from FW */

	RCU_INIT_POINTER(mld->fw_id_to_link_sta[fw_id], NULL);

	return 0;
}

static void
iwl_mld_init_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		 struct ieee80211_vif *vif)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	mld_sta->vif = vif;
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif)
{
	iwl_mld_init_sta(mld, sta, vif);

	/* When the sta is added, i.e. its state is moving from NOTEXIST to
	 * NONE, it can't have more then one active link_sta,
	 * and that one active link_sta is deflink.
	 * In restart when in EMLSR, mac80211 will first configure us to one
	 * link, and then explicitly activate the second link and the link_sta.
	 */
	return iwl_mld_add_link_sta(mld, &sta->deflink);
}

int iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	u8 link_id;
	int ret;

	/* Remove all link_sta's*/
	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		ret = iwl_mvm_remove_link_sta(mld, link_sta);
		if (ret)
			break;
	}
	return ret;
}
