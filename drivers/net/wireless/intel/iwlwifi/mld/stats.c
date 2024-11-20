// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "stats.h"
#include "hcmd.h"
#include "fw/api/stats.h"

static int iwl_mld_send_fw_stats_cmd(struct iwl_mld *mld, u32 cfg_mask,
				     u32 cfg_time, u32 type_mask)
{
	u32 cmd_id = WIDE_ID(SYSTEM_GROUP, SYSTEM_STATISTICS_CMD);
	struct iwl_system_statistics_cmd stats_cmd = {
		.cfg_mask = cpu_to_le32(cfg_mask),
		.config_time_sec = cpu_to_le32(cfg_time),
		.type_id_mask = cpu_to_le32(type_mask),
	};

	return iwl_mld_send_cmd_pdu(mld, cmd_id, &stats_cmd);
}

int iwl_mld_request_fw_stats(struct iwl_mld *mld, bool clear)
{
	u32 cfg_mask = clear ? IWL_STATS_CFG_FLG_ON_DEMAND_NTFY_MSK :
			       IWL_STATS_CFG_FLG_RESET_MSK |
			       IWL_STATS_CFG_FLG_ON_DEMAND_NTFY_MSK;
	u32 type_mask = IWL_STATS_NTFY_TYPE_ID_OPER |
			IWL_STATS_NTFY_TYPE_ID_OPER_PART1;
	static const u16 stats_complete[] = {
		WIDE_ID(SYSTEM_GROUP, SYSTEM_STATISTICS_END_NOTIF),
	};
	struct iwl_notification_wait stats_wait;
	int ret;

	iwl_init_notification_wait(&mld->notif_wait, &stats_wait,
				   stats_complete, ARRAY_SIZE(stats_complete),
				   NULL, NULL);

	/* TODO: mvm->statistics_clear (task=statistics) */

	ret = iwl_mld_send_fw_stats_cmd(mld, cfg_mask, 0, type_mask);
	if (ret) {
		iwl_remove_notification(&mld->notif_wait, &stats_wait);
		return ret;
	}

	/* Wait 500ms for OPERATIONAL, PART1, and END notifications,
	 * which should be sufficient for the firmware to gather data
	 * from all LMACs and send notifications to the host.
	 */
	ret = iwl_wait_notification(&mld->notif_wait, &stats_wait, HZ / 2);
	if (ret)
		return ret;

	/* Flush the async_handlers to process the statistics notifications */
	wiphy_work_flush(mld->wiphy, &mld->async_handlers_wk);

	/* TODO: iwl_mvm_accu_radio_stats (task=statistics)*/

	return 0;
}

#define PERIODIC_STATS_SECONDS 5

int iwl_mld_request_periodic_fw_stats(struct iwl_mld *mld, bool enable)
{
	u32 cfg_mask = enable ? 0 : IWL_STATS_CFG_FLG_DISABLE_NTFY_MSK;
	u32 type_mask = enable ? (IWL_STATS_NTFY_TYPE_ID_OPER |
				  IWL_STATS_NTFY_TYPE_ID_OPER_PART1) : 0;
	u32 cfg_time = enable ? PERIODIC_STATS_SECONDS : 0;

	return iwl_mld_send_fw_stats_cmd(mld, cfg_mask, cfg_time, type_mask);
}

void iwl_mld_handle_stats_oper_notif(struct iwl_mld *mld,
				     struct iwl_rx_packet *pkt)
{
	/* TODO */
}

void iwl_mld_handle_stats_oper_part1_notif(struct iwl_mld *mld,
					   struct iwl_rx_packet *pkt)
{
	/* TODO */
}

