// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"

static void
iwl_mld_mac80211_tx(struct ieee80211_hw *hw,
		    struct ieee80211_tx_control *control, struct sk_buff *skb)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_mac80211_start(struct ieee80211_hw *hw)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_mac80211_stop(struct ieee80211_hw *hw, bool suspend)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_mac80211_config(struct ieee80211_hw *hw, u32 changed)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
int iwl_mld_mac80211_add_interface(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_mac80211_remove_interface(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif)
{
	WARN_ON("Not supported yet\n");
}

static
void iwl_mld_mac80211_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *total_flags,
				       u64 multicast)
{
	WARN_ON("Not supported yet\n");
}

static
void iwl_mld_mac80211_wake_tx_queue(struct ieee80211_hw *hw,
				    struct ieee80211_txq *txq)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_add_chanctx(struct ieee80211_hw *hw,
			struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_remove_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
}

static
void iwl_mld_change_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx, u32 changed)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_assign_vif_chanctx(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ieee80211_bss_conf *link_conf,
			       struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_unassign_vif_chanctx(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_bss_conf *link_conf,
				  struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
}

const struct ieee80211_ops iwl_mld_hw_ops = {
	.tx = iwl_mld_mac80211_tx,
	.start = iwl_mld_mac80211_start,
	.stop = iwl_mld_mac80211_stop,
	.config = iwl_mld_mac80211_config,
	.add_interface = iwl_mld_mac80211_add_interface,
	.remove_interface = iwl_mld_mac80211_remove_interface,
	.configure_filter = iwl_mld_mac80211_configure_filter,
	.wake_tx_queue = iwl_mld_mac80211_wake_tx_queue,
	.add_chanctx = iwl_mld_add_chanctx,
	.remove_chanctx = iwl_mld_remove_chanctx,
	.change_chanctx = iwl_mld_change_chanctx,
	.assign_vif_chanctx = iwl_mld_assign_vif_chanctx,
	.unassign_vif_chanctx = iwl_mld_unassign_vif_chanctx,
};
