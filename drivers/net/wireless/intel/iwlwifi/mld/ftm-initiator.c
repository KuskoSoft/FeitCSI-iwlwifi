// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#include <linux/etherdevice.h>
#include <linux/math64.h>
#include <net/cfg80211.h>
#include "mld.h"
#include "iface.h"
#include "phy.h"
#include "iwl-io.h"
#include "iwl-prph.h"
#include "constants.h"
#include "fw/api/location.h"
#include "ftm-initiator.h"

static void iwl_mld_ftm_cmd_common(struct iwl_mld *mld,
				   struct ieee80211_vif *vif,
				   struct iwl_tof_range_req_cmd *cmd,
				   struct cfg80211_pmsr_request *req)
{
	int i;

	cmd->initiator_flags =
		cpu_to_le32(IWL_TOF_INITIATOR_FLAGS_MACADDR_RANDOM |
			    IWL_TOF_INITIATOR_FLAGS_NON_ASAP_SUPPORT);
	cmd->request_id = req->cookie;
	cmd->num_of_ap = req->n_peers;

	/* Use a large value for "no timeout". Don't use the maximum value
	 * because of fw limitations.
	 */
	if (req->timeout)
		cmd->req_timeout_ms = cpu_to_le32(min(req->timeout, 0xfffff));
	else
		cmd->req_timeout_ms = cpu_to_le32(0xfffff);

	memcpy(cmd->macaddr_template, req->mac_addr, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		cmd->macaddr_mask[i] = ~req->mac_addr_mask[i];

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (IWL_MLD_FTM_INITIATOR_FAST_ALGO_DISABLE)
		cmd->initiator_flags |=
			cpu_to_le32(IWL_TOF_INITIATOR_FLAGS_FAST_ALGO_DISABLED);
#endif

	if (vif->cfg.assoc) {
		memcpy(cmd->range_req_bssid, vif->bss_conf.bssid, ETH_ALEN);

		/* AP's TSF is only relevant if associated */
		for (i = 0; i < req->n_peers; i++) {
			if (req->peers[i].report_ap_tsf) {
				struct iwl_mld_vif *mld_vif =
					iwl_mld_vif_from_mac80211(vif);

				cmd->tsf_mac_id = cpu_to_le32(mld_vif->fw_id);
				return;
			}
		}
	} else {
		eth_broadcast_addr(cmd->range_req_bssid);
	}

	/* Don't report AP's TSF */
	cmd->tsf_mac_id = cpu_to_le32(0xff);
}

static int
iwl_mld_ftm_set_target_chandef(struct iwl_mld *mld,
			       struct cfg80211_pmsr_request_peer *peer,
			       struct iwl_tof_range_req_ap_entry *target)
{
	u32 freq = peer->chandef.chan->center_freq;

	target->channel_num = ieee80211_frequency_to_channel(freq);

	switch (peer->chandef.width) {
		case NL80211_CHAN_WIDTH_20_NOHT:
			target->format_bw = IWL_LOCATION_FRAME_FORMAT_LEGACY;
			target->format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
			break;
		case NL80211_CHAN_WIDTH_20:
			target->format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
			target->format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
			break;
		case NL80211_CHAN_WIDTH_40:
			target->format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
			target->format_bw |= IWL_LOCATION_BW_40MHZ << LOCATION_BW_POS;
			break;
		case NL80211_CHAN_WIDTH_80:
			target->format_bw = IWL_LOCATION_FRAME_FORMAT_VHT;
			target->format_bw |= IWL_LOCATION_BW_80MHZ << LOCATION_BW_POS;
			break;
		case NL80211_CHAN_WIDTH_160:
			target->format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
			target->format_bw |= IWL_LOCATION_BW_160MHZ << LOCATION_BW_POS;
			break;
		default:
			IWL_ERR(mld, "Unsupported BW in FTM request (%d)\n",
				peer->chandef.width);
			return -EINVAL;
	}

	/* non EDCA based measurement must use HE preamble */
	if (peer->ftm.trigger_based || peer->ftm.non_trigger_based)
		target->format_bw |= IWL_LOCATION_FRAME_FORMAT_HE;

	target->ctrl_ch_position =
		(peer->chandef.width > NL80211_CHAN_WIDTH_20) ?
		iwl_mld_get_fw_ctrl_pos(&peer->chandef) : 0;

	target->band = iwl_mld_nl80211_band_to_fw(peer->chandef.chan->band);
	return 0;
}

#define FTM_SET_FLAG(flag) (target->initiator_ap_flags |= \
			    cpu_to_le32(IWL_INITIATOR_AP_FLAGS_##flag))

static void
iwl_mld_ftm_set_target_flags(struct iwl_mld *mld,
			     struct cfg80211_pmsr_request_peer *peer,
			     struct iwl_tof_range_req_ap_entry *target)
{
	target->initiator_ap_flags = cpu_to_le32(0);

	if (peer->ftm.asap)
		FTM_SET_FLAG(ASAP);

	if (peer->ftm.request_lci)
		FTM_SET_FLAG(LCI_REQUEST);

	if (peer->ftm.request_civicloc)
		FTM_SET_FLAG(CIVIC_REQUEST);

	if (IWL_MLD_FTM_INITIATOR_DYNACK)
		FTM_SET_FLAG(DYN_ACK);

	if (IWL_MLD_FTM_INITIATOR_ALGO == IWL_TOF_ALGO_TYPE_LINEAR_REG)
		FTM_SET_FLAG(ALGO_LR);
	else if (IWL_MLD_FTM_INITIATOR_ALGO == IWL_TOF_ALGO_TYPE_FFT)
		FTM_SET_FLAG(ALGO_FFT);

	if (peer->ftm.trigger_based)
		FTM_SET_FLAG(TB);
	else if (peer->ftm.non_trigger_based)
		FTM_SET_FLAG(NON_TB);

	if ((peer->ftm.trigger_based || peer->ftm.non_trigger_based) &&
	    peer->ftm.lmr_feedback)
		FTM_SET_FLAG(LMR_FEEDBACK);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (IWL_MLD_FTM_INITIATOR_MCSI_ENABLED)
		FTM_SET_FLAG(MCSI_REPORT);

	if (IWL_MLD_FTM_LMR_FEEDBACK_TERMINATE)
		FTM_SET_FLAG(TERMINATE_ON_LMR_FEEDBACK);

	if (IWL_MLD_FTM_TEST_INCORRECT_SAC)
		FTM_SET_FLAG(TEST_INCORRECT_SAC);

	if (IWL_MLD_FTM_TEST_BAD_SLTF)
		FTM_SET_FLAG(TEST_BAD_SLTF);
#endif
}

static void iwl_mld_ftm_set_sta(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct cfg80211_pmsr_request_peer *peer,
				struct iwl_tof_range_req_ap_entry *target)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	u32 sta_id_mask;

	target->sta_id = IWL_INVALID_STA;

	/* TODO: add ftm_unprotected debugfs support */

	if (!vif->cfg.assoc || !mld_vif->ap_sta)
		return;

	sta_id_mask = iwl_mld_fw_sta_id_mask(mld, mld_vif->ap_sta);
	if (WARN_ON(hweight32(sta_id_mask) != 1))
		return;

	target->sta_id = __ffs(sta_id_mask);

	if (mld_vif->ap_sta->mfp &&
	    (peer->ftm.trigger_based || peer->ftm.non_trigger_based))
		FTM_SET_FLAG(PMF);
}

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
static void iwl_mld_ftm_set_calib(struct iwl_mld *mld, __le16 *calib,
				  struct iwl_tof_range_req_ap_entry *target)
{
	if (mld->trans->dbg_cfg.MLD_FTM_INITIATOR_COMMON_CALIB) {
		/* The driver API only supports one calibration value.
		 * For now, use it for all bandwidths.
		 * TODO: Add support for per bandwidth calibration
		 * values.
		 */
		for (int j = 0; j < IWL_TOF_BW_NUM; j++)
			calib[j] =
				cpu_to_le16(mld->trans->dbg_cfg.MLD_FTM_INITIATOR_COMMON_CALIB);

		FTM_SET_FLAG(USE_CALIB);
	}
}
#endif

static int
iwl_mld_ftm_set_target(struct iwl_mld *mld, struct ieee80211_vif *vif,
		       struct cfg80211_pmsr_request_peer *peer,
		       struct iwl_tof_range_req_ap_entry *target)
{
	u32 i2r_max_sts;
	int ret;

	ret = iwl_mld_ftm_set_target_chandef(mld, peer, target);
	if (ret)
		return ret;

	memcpy(target->bssid, peer->addr, ETH_ALEN);
	target->burst_period = cpu_to_le16(peer->ftm.burst_period);
	target->samples_per_burst = peer->ftm.ftms_per_burst;
	target->num_of_bursts = peer->ftm.num_bursts_exp;
	iwl_mld_ftm_set_target_flags(mld, peer, target);
	iwl_mld_ftm_set_sta(mld, vif, peer, target);
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	iwl_mld_ftm_set_calib(mld, target->calib, target);
#endif

	/* TODO: add secured ranging support */

	i2r_max_sts = IWL_MLD_FTM_I2R_MAX_STS > 1 ? 1 :
		IWL_MLD_FTM_I2R_MAX_STS;

	target->r2i_ndp_params = IWL_MLD_FTM_R2I_MAX_REP |
		(IWL_MLD_FTM_R2I_MAX_STS << IWL_LOCATION_MAX_STS_POS) |
		(IWL_MLD_FTM_R2I_MAX_TOTAL_LTF << IWL_LOCATION_TOTAL_LTF_POS);
	target->i2r_ndp_params = IWL_MLD_FTM_I2R_MAX_REP |
		(i2r_max_sts << IWL_LOCATION_MAX_STS_POS) |
		(IWL_MLD_FTM_I2R_MAX_TOTAL_LTF << IWL_LOCATION_TOTAL_LTF_POS);

	if (peer->ftm.non_trigger_based) {
		target->min_time_between_msr =
			cpu_to_le16(IWL_MLD_FTM_NON_TB_MIN_TIME_BETWEEN_MSR);
		target->burst_period =
			cpu_to_le16(IWL_MLD_FTM_NON_TB_MAX_TIME_BETWEEN_MSR);
	} else {
		target->min_time_between_msr = cpu_to_le16(0);
	}

	/* TODO: Beacon interval is currently unknown, so use the common value
	 * of 100 TUs.
	 */
	target->beacon_interval = cpu_to_le16(100);

	return 0;
}

int iwl_mld_ftm_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
		      struct cfg80211_pmsr_request *req)
{
	struct iwl_tof_range_req_cmd cmd;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LOCATION_GROUP, TOF_RANGE_REQ_CMD),
		.dataflags[0] = IWL_HCMD_DFL_DUP,
		.data[0] = &cmd,
		.len[0] = sizeof(cmd),
	};
	u8 i;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (mld->ftm_initiator.req)
		return -EBUSY;

	if (req->n_peers > ARRAY_SIZE(cmd.ap))
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));

	iwl_mld_ftm_cmd_common(mld, vif, (void *)&cmd, req);

	for (i = 0; i < cmd.num_of_ap; i++) {
		struct cfg80211_pmsr_request_peer *peer = &req->peers[i];
		struct iwl_tof_range_req_ap_entry *target = &cmd.ap[i];

		ret = iwl_mld_ftm_set_target(mld, vif, peer, target);
		if (ret)
			return ret;
	}

	/* TODO: get the status from the response*/
	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (!ret) {
		mld->ftm_initiator.req = req;
		mld->ftm_initiator.req_wdev = ieee80211_vif_to_wdev(vif);
	}

	return ret;
}
