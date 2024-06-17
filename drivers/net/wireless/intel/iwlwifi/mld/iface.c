// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "iface.h"

/* Cleanup function for struct iwl_mld_vif, will be called in restart */
void iwl_mld_cleanup_vif(void *data, u8 *mac, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link;

	for_each_mld_vif_valid_link(mld_vif, link)
		iwl_mld_cleanup_link(link);

	CLEANUP_STRUCT(mld_vif);
}
