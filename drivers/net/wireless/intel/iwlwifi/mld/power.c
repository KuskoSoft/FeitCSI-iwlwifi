// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <net/mac80211.h>

#include "mld.h"
#include "hcmd.h"
#include "power.h"

int iwl_mld_power_update_device(struct iwl_mld *mld)
{
	struct iwl_device_power_cmd cmd = {};

	/* TODO: CAM MODE, DEVICE_POWER_FLAGS_POWER_SAVE_ENA_MSK */

	/* TODO: DEVICE_POWER_FLAGS_32K_CLK_VALID_MSK */

	/* TODO: DEVICE_POWER_FLAGS_NO_SLEEP_TILL_D3_MSK */

	IWL_DEBUG_POWER(mld,
			"Sending device power command with flags = 0x%X\n",
			cmd.flags);

	return iwl_mld_send_cmd_pdu(mld, POWER_TABLE_CMD, &cmd);
}

int iwl_mld_disable_beacon_filter(struct iwl_mld *mld,
				  struct ieee80211_vif *vif)
{
	struct iwl_beacon_filter_cmd cmd = {};

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION)
		return 0;

	return iwl_mld_send_cmd_pdu(mld, REPLY_BEACON_FILTERING_CMD,
				    &cmd);
}
