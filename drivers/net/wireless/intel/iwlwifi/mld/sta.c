// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "sta.h"

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

	return 0;
}

void iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	/* To be implemented in next patch */
}
