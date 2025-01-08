// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#include "mld.h"
#include "hcmd.h"
#include "time_sync.h"
#include <linux/ieee80211.h>

static int iwl_mld_init_time_sync(struct iwl_mld *mld, u32 protocols,
				  const u8 *addr)
{
	struct iwl_mld_time_sync_data *time_sync = kzalloc(sizeof(*time_sync),
							   GFP_KERNEL);

	if (!time_sync)
		return -ENOMEM;

	time_sync->active_protocols = protocols;
	ether_addr_copy(time_sync->peer_addr, addr);
	rcu_assign_pointer(mld->time_sync, time_sync);

	return 0;
}

int iwl_mld_time_sync_fw_config(struct iwl_mld *mld)
{
	struct iwl_time_sync_cfg_cmd cmd = {};
	struct iwl_mld_time_sync_data *time_sync;
	int err;

	time_sync = wiphy_dereference(mld->wiphy, mld->time_sync);
	if (!time_sync)
		return -EINVAL;

	cmd.protocols = cpu_to_le32(time_sync->active_protocols);
	ether_addr_copy(cmd.peer_addr, time_sync->peer_addr);

	err = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(DATA_PATH_GROUP,
					   WNM_80211V_TIMING_MEASUREMENT_CONFIG_CMD),
				   &cmd);
	if (err)
		IWL_ERR(mld, "Failed to send time sync cfg cmd: %d\n", err);

	return err;
}

int iwl_mld_time_sync_config(struct iwl_mld *mld, const u8 *addr, u32 protocols)
{
	struct iwl_mld_time_sync_data *time_sync;
	int err;

	time_sync = wiphy_dereference(mld->wiphy, mld->time_sync);

	/* The fw only supports one peer. We do allow reconfiguration of the
	 * same peer for cases of fw reset etc.
	 */
	if (time_sync && time_sync->active_protocols &&
	    !ether_addr_equal(addr, time_sync->peer_addr)) {
		IWL_DEBUG_INFO(mld, "Time sync: reject config for peer: %pM\n",
			       addr);
		return -ENOBUFS;
	}

	if (protocols & ~(IWL_TIME_SYNC_PROTOCOL_TM |
			  IWL_TIME_SYNC_PROTOCOL_FTM))
		return -EINVAL;

	IWL_DEBUG_INFO(mld, "Time sync: set peer addr=%pM\n", addr);

	iwl_mld_deinit_time_sync(mld);
	err = iwl_mld_init_time_sync(mld, protocols, addr);
	if (err)
		return err;

	err = iwl_mld_time_sync_fw_config(mld);
	return err;
}

void iwl_mld_deinit_time_sync(struct iwl_mld *mld)
{
	struct iwl_mld_time_sync_data *time_sync =
		wiphy_dereference(mld->wiphy, mld->time_sync);

	if (!time_sync)
		return;

	RCU_INIT_POINTER(mld->time_sync, NULL);
	kfree_rcu(time_sync, rcu_head);
}
