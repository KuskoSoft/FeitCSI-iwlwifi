// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <net/mac80211.h>

#include "mld.h"
#include "hcmd.h"
#include "power.h"
#include "iface.h"
#include "link.h"

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

static void
iwl_mld_tpe_sta_cmd_data(struct iwl_txpower_constraints_cmd *cmd,
			 const struct ieee80211_bss_conf *link)
{
	u8 i;

	/* NOTE: the 0 here is IEEE80211_TPE_CAT_6GHZ_DEFAULT,
	 * we fully ignore IEEE80211_TPE_CAT_6GHZ_SUBORDINATE
	 */

	BUILD_BUG_ON(ARRAY_SIZE(cmd->psd_pwr) !=
		     ARRAY_SIZE(link->tpe.psd_local[0].power));

	/* if not valid, mac80211 puts default (max value) */
	for (i = 0; i < ARRAY_SIZE(cmd->psd_pwr); i++)
		cmd->psd_pwr[i] = min(link->tpe.psd_local[0].power[i],
				      link->tpe.psd_reg_client[0].power[i]);

	BUILD_BUG_ON(ARRAY_SIZE(cmd->eirp_pwr) !=
		     ARRAY_SIZE(link->tpe.max_local[0].power));

	for (i = 0; i < ARRAY_SIZE(cmd->eirp_pwr); i++)
		cmd->eirp_pwr[i] = min(link->tpe.max_local[0].power[i],
				       link->tpe.max_reg_client[0].power[i]);
}

void
iwl_mld_send_ap_tx_power_constraint_cmd(struct iwl_mld *mld,
					struct ieee80211_vif *vif,
					struct ieee80211_bss_conf *link)
{
	struct iwl_txpower_constraints_cmd cmd = {};
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (!mld_link->active)
		return;

	if (link->chanreq.oper.chan->band != NL80211_BAND_6GHZ)
		return;

	cmd.link_id = cpu_to_le16(mld_link->fw_id);
	memset(cmd.psd_pwr, DEFAULT_TPE_TX_POWER, sizeof(cmd.psd_pwr));
	memset(cmd.eirp_pwr, DEFAULT_TPE_TX_POWER, sizeof(cmd.eirp_pwr));

	if (vif->type == NL80211_IFTYPE_AP) {
		cmd.ap_type = cpu_to_le16(IWL_6GHZ_AP_TYPE_VLP);
	} else if (link->power_type == IEEE80211_REG_UNSET_AP) {
		return;
	} else {
		cmd.ap_type = cpu_to_le16(link->power_type - 1);
		iwl_mld_tpe_sta_cmd_data(&cmd, link);
	}

	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(PHY_OPS_GROUP,
					   AP_TX_POWER_CONSTRAINTS_CMD),
				   &cmd);
	if (ret)
		IWL_ERR(mld,
			"failed to send AP_TX_POWER_CONSTRAINTS_CMD (%d)\n",
			ret);
}
