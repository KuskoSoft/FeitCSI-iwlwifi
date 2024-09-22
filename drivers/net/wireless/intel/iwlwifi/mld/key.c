// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "key.h"
#include "iface.h"
#include "fw/api/sta.h"

static int iwl_mld_add_key_to_fw(void)
{
	/* TODO: implement key API */
	return 0;
}

static int iwl_mld_remove_key_from_fw(void)
{
	/* TODO: implement key API */
	return 0;
}

int iwl_mld_remove_key(struct iwl_mld *mld,
		       struct ieee80211_vif *vif,
		       struct ieee80211_sta *sta,
		       struct ieee80211_key_conf *key)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	lockdep_assert_wiphy(mld->wiphy);

	if (key->keyidx == 4 || key->keyidx == 5) {
		struct iwl_mld_link *mld_link;
		unsigned int link_id = 0;

		/* set to -1 for non-MLO right now */
		if (key->link_id >= 0)
			link_id = key->link_id;

		mld_link = iwl_mld_link_dereference_check(mld_vif, link_id);
		if (WARN_ON(!mld_link))
			return -EINVAL;

		if (mld_link->igtk == key) {
			/* no longer in HW - mark for later */
			mld_link->igtk->hw_key_idx = STA_KEY_IDX_INVALID;
			mld_link->igtk = NULL;
		}
	}

	return iwl_mld_remove_key_from_fw();
}

int iwl_mld_add_key(struct iwl_mld *mld,
		    struct ieee80211_vif *vif,
		    struct ieee80211_sta *sta,
		    struct ieee80211_key_conf *key)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *mld_link = NULL;
	bool igtk = key->keyidx == 4 || key->keyidx == 5;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (igtk) {
		u8 link_id = 0;

		/* set to -1 for non-MLO right now */
		if (key->link_id >= 0)
			link_id = key->link_id;

		mld_link = iwl_mld_link_dereference_check(mld_vif, link_id);

		if (WARN_ON(!mld_link))
			return -EINVAL;

		if (mld_link->igtk) {
			IWL_DEBUG_MAC80211(mld, "remove old IGTK %d\n",
					   mld_link->igtk->keyidx);
			ret = iwl_mld_remove_key(mld, vif, sta, mld_link->igtk);
			if (ret)
				IWL_ERR(mld,
					"failed to remove old IGTK (ret=%d)\n",
					ret);
		}

		WARN_ON(mld_link->igtk);
	}

	/* Will be set to 0 if added successfully */
	key->hw_key_idx = STA_KEY_IDX_INVALID;

	ret = iwl_mld_add_key_to_fw();
	if (ret)
		return ret;

	if (mld_link)
		mld_link->igtk = key;

	/* We don't really need this, but need it to be not invalid,
	 * so we will know if the key is in fw.
	 */
	key->hw_key_idx = 0;

	return 0;
}
