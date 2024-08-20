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
 * @fw_id: fw id of the phy.
 * @chandef: the last chandef that mac80211 configured the driver
 *	with. Used to detect a no-op when the chanctx changes.
 */
struct iwl_mld_phy {
	/* Add here fields that need clean up on hw restart */
	struct_group(zeroed_on_hw_restart,
		u8 fw_id;
		struct cfg80211_chan_def chandef;
	);
	/* And here fields that survive a hw restart */
};

static inline struct iwl_mld_phy *
iwl_mld_phy_from_mac80211(struct ieee80211_chanctx_conf *channel)
{
	return (void *)channel->drv_priv;
}

/* Cleanup function for struct iwl_mld_phy, will be called in restart */
static inline void
iwl_mld_cleanup_phy(struct iwl_mld *mld, struct iwl_mld_phy *phy)
{
	CLEANUP_STRUCT(phy);
}

int iwl_mld_allocate_fw_phy_id(struct iwl_mld *mld);
int iwl_mld_phy_fw_action(struct iwl_mld *mld,
			  struct ieee80211_chanctx_conf *ctx, u32 action);
int iwl_mld_send_rlc_cmd(struct iwl_mld *mld, u8 phy_id);
struct cfg80211_chan_def *
iwl_mld_get_chandef_from_chanctx(struct ieee80211_chanctx_conf *ctx);

#endif /* __iwl_mld_phy_h__ */
