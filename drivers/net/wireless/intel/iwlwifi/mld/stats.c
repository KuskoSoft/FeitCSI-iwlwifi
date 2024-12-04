// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "stats.h"
#include "sta.h"
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

static void iwl_mld_sta_stats_fill_txrate(struct iwl_mld_sta *mld_sta,
					  struct station_info *sinfo)
{
	struct rate_info *rinfo = &sinfo->txrate;
	u32 rate_n_flags = mld_sta->deflink.last_rate_n_flags;
	u32 format = rate_n_flags & RATE_MCS_MOD_TYPE_MSK;
	u32 gi_ltf;

	sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_BITRATE);

	switch (rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) {
	case RATE_MCS_CHAN_WIDTH_20:
		rinfo->bw = RATE_INFO_BW_20;
		break;
	case RATE_MCS_CHAN_WIDTH_40:
		rinfo->bw = RATE_INFO_BW_40;
		break;
	case RATE_MCS_CHAN_WIDTH_80:
		rinfo->bw = RATE_INFO_BW_80;
		break;
	case RATE_MCS_CHAN_WIDTH_160:
		rinfo->bw = RATE_INFO_BW_160;
		break;
	case RATE_MCS_CHAN_WIDTH_320:
		rinfo->bw = RATE_INFO_BW_320;
		break;
	}

	if (format == RATE_MCS_CCK_MSK || format == RATE_MCS_LEGACY_OFDM_MSK) {
		int rate = u32_get_bits(rate_n_flags, RATE_LEGACY_RATE_MSK);

		/* add the offset needed to get to the legacy ofdm indices */
		if (format == RATE_MCS_LEGACY_OFDM_MSK)
			rate += IWL_FIRST_OFDM_RATE;

		switch (rate) {
		case IWL_RATE_1M_INDEX:
			rinfo->legacy = 10;
			break;
		case IWL_RATE_2M_INDEX:
			rinfo->legacy = 20;
			break;
		case IWL_RATE_5M_INDEX:
			rinfo->legacy = 55;
			break;
		case IWL_RATE_11M_INDEX:
			rinfo->legacy = 110;
			break;
		case IWL_RATE_6M_INDEX:
			rinfo->legacy = 60;
			break;
		case IWL_RATE_9M_INDEX:
			rinfo->legacy = 90;
			break;
		case IWL_RATE_12M_INDEX:
			rinfo->legacy = 120;
			break;
		case IWL_RATE_18M_INDEX:
			rinfo->legacy = 180;
			break;
		case IWL_RATE_24M_INDEX:
			rinfo->legacy = 240;
			break;
		case IWL_RATE_36M_INDEX:
			rinfo->legacy = 360;
			break;
		case IWL_RATE_48M_INDEX:
			rinfo->legacy = 480;
			break;
		case IWL_RATE_54M_INDEX:
			rinfo->legacy = 540;
		}
		return;
	}

	rinfo->nss = u32_get_bits(rate_n_flags, RATE_MCS_NSS_MSK) + 1;

	if (format == RATE_MCS_HT_MSK)
		rinfo->mcs = RATE_HT_MCS_INDEX(rate_n_flags);
	else
		rinfo->mcs = u32_get_bits(rate_n_flags, RATE_MCS_CODE_MSK);

	if (rate_n_flags & RATE_MCS_SGI_MSK)
		rinfo->flags |= RATE_INFO_FLAGS_SHORT_GI;

	switch (format) {
	case RATE_MCS_EHT_MSK:
		rinfo->flags |= RATE_INFO_FLAGS_EHT_MCS;
		break;
	case RATE_MCS_HE_MSK:
		gi_ltf = u32_get_bits(rate_n_flags, RATE_MCS_HE_GI_LTF_MSK);

		rinfo->flags |= RATE_INFO_FLAGS_HE_MCS;

		if (rate_n_flags & RATE_MCS_HE_106T_MSK) {
			rinfo->bw = RATE_INFO_BW_HE_RU;
			rinfo->he_ru_alloc = NL80211_RATE_INFO_HE_RU_ALLOC_106;
		}

		switch (rate_n_flags & RATE_MCS_HE_TYPE_MSK) {
		case RATE_MCS_HE_TYPE_SU:
		case RATE_MCS_HE_TYPE_EXT_SU:
			if (gi_ltf == 0 || gi_ltf == 1)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
			else if (gi_ltf == 2)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
			else if (gi_ltf == 3)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
			else
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
			break;
		case RATE_MCS_HE_TYPE_MU:
			if (gi_ltf == 0 || gi_ltf == 1)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
			else if (gi_ltf == 2)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
			else
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
			break;
		case RATE_MCS_HE_TYPE_TRIG:
			if (gi_ltf == 0 || gi_ltf == 1)
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
			else
				rinfo->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
			break;
		}

		if (rate_n_flags & RATE_HE_DUAL_CARRIER_MODE_MSK)
			rinfo->he_dcm = 1;
		break;
	case RATE_MCS_HT_MSK:
		rinfo->flags |= RATE_INFO_FLAGS_MCS;
		break;
	case RATE_MCS_VHT_MSK:
		rinfo->flags |= RATE_INFO_FLAGS_VHT_MCS;
		break;
	}
}

static void iwl_mld_sta_stats_fill_signal_avg(struct iwl_mld_sta *mld_sta,
					      struct station_info *sinfo)
{
	if (mld_sta->deflink.avg_energy) {
		sinfo->signal_avg = -(s8)mld_sta->deflink.avg_energy;
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_SIGNAL_AVG);
	}
}

void iwl_mld_mac80211_sta_statistics(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif,
				     struct ieee80211_sta *sta,
				     struct station_info *sinfo)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	/* This API is not EMLSR ready, so we cannot provide complete
	 * information if EMLSR is active
	 */
	if (hweight16(vif->active_links) > 1)
		return;

	if (iwl_mld_request_fw_stats(mld_sta->mld, false))
		return;

	iwl_mld_sta_stats_fill_signal_avg(mld_sta, sinfo);

	iwl_mld_sta_stats_fill_txrate(mld_sta, sinfo);

	/* TODO: NL80211_STA_INFO_BEACON_RX */

	/* TODO: NL80211_STA_INFO_BEACON_SIGNAL_AVG */
}

static void
iwl_mld_proccess_per_sta_stats(struct iwl_mld *mld,
			       const struct iwl_stats_ntfy_per_sta *per_sta)
{
	u32 num_stations = mld->fw->ucode_capa.num_stations;

	for (u32 fw_id = 0; fw_id < num_stations; fw_id++) {
		struct iwl_mld_link_sta *mld_link_sta;
		struct ieee80211_link_sta *link_sta;

		if (!per_sta[fw_id].average_energy)
			continue;

		link_sta = wiphy_dereference(mld->wiphy,
					     mld->fw_id_to_link_sta[fw_id]);
		if (IS_ERR_OR_NULL(link_sta))
			continue;

		mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
		if (WARN_ON(!mld_link_sta))
			continue;

		mld_link_sta->avg_energy =
			le32_to_cpu(per_sta[fw_id].average_energy);
	}
}

void iwl_mld_handle_stats_oper_notif(struct iwl_mld *mld,
				     struct iwl_rx_packet *pkt)
{
	const struct iwl_system_statistics_notif_oper *stats =
		(void *)&pkt->data;

	BUILD_BUG_ON(ARRAY_SIZE(stats->per_sta) < IWL_STATION_COUNT_MAX);

	iwl_mld_proccess_per_sta_stats(mld, stats->per_sta);

	/* TODO: per_link, per_phy stats (task=statistics) */
}

void iwl_mld_handle_stats_oper_part1_notif(struct iwl_mld *mld,
					   struct iwl_rx_packet *pkt)
{
	/* TODO */
}

