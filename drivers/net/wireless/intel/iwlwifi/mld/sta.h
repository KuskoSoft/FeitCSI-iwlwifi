// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#ifndef __iwl_mld_sta_h__
#define __iwl_mld_sta_h__

#include <net/mac80211.h>

#include "mld.h"

/**
 * struct iwl_mld_sta - representation of a station in the driver.
 *
 * This represent the MLD-level sta, and will not be added to the FW.
 * Embedded in ieee80211_sta.
 *
 * @vif: pointer the vif object.
 */
struct iwl_mld_sta {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
	);
	struct ieee80211_vif *vif;
	/* And here fields that survive a fw restart */
};

static inline struct iwl_mld_sta *
iwl_mld_sta_from_mac80211(struct ieee80211_sta *sta)
{
	return (void *)sta->drv_priv;
}

static inline void
iwl_mld_cleanup_sta(void *data, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	CLEANUP_STRUCT(mld_sta);
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif);
int iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta);

#endif /* __iwl_mld_sta_h__ */
