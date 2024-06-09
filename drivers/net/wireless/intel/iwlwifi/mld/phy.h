// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_phy_h__
#define __iwl_mld_phy_h__

#include "mld.h"

/**
 * struct iwl_mld_phy - PHY configuration parameters
 *
 * @id: id of the phy.
 */
struct iwl_mld_phy {
	/* Add here fields that need clean up on hw restart */
	struct_group(zeroed_on_hw_restart,
		u8 id;
	);
	/* And here fields that survive a hw restart */
};

static inline struct iwl_mld_phy *
iwl_mld_phy_from_mac80211(struct ieee80211_chanctx_conf *channel)
{
	return (void *)channel->drv_priv;
}

/* Constructor function for struct iwl_mld_phy */
static inline void
iwl_mld_init_phy(struct iwl_mld *mld, struct iwl_mld_phy *phy, u8 id)
{
	phy->id = id;
}

/* Cleanup function for struct iwl_mld_phy, will be called in restart */
static inline void
iwl_mld_cleanup_phy(struct iwl_mld *mld, struct iwl_mld_phy *phy)
{
	CLEANUP_STRUCT(phy);
}

#endif /* __iwl_mld_phy_h__ */
