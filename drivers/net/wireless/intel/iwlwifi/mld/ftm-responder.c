// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#include <net/cfg80211.h>
#include <linux/etherdevice.h>
#include "mld.h"
#include "constants.h"
#include "phy.h"
#include "iface.h"
#include "ftm-responder.h"

static void
iwl_mld_ftm_responder_set_ndp(struct iwl_mld *mld,
			      struct iwl_tof_responder_config_cmd *cmd)
{
	/* Up to 2 R2I STS are allowed on the responder */
	u32 r2i_max_sts = IWL_MLD_FTM_R2I_MAX_STS < 2 ?
		IWL_MLD_FTM_R2I_MAX_STS : 1;

	cmd->r2i_ndp_params = IWL_MLD_FTM_R2I_MAX_REP |
		(r2i_max_sts << IWL_RESPONDER_STS_POS) |
		(IWL_MLD_FTM_R2I_MAX_TOTAL_LTF << IWL_RESPONDER_TOTAL_LTF_POS);
	cmd->i2r_ndp_params = IWL_MLD_FTM_I2R_MAX_REP |
		(IWL_MLD_FTM_I2R_MAX_STS << IWL_RESPONDER_STS_POS) |
		(IWL_MLD_FTM_I2R_MAX_TOTAL_LTF << IWL_RESPONDER_TOTAL_LTF_POS);
	cmd->cmd_valid_fields |=
		cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_NDP_PARAMS);
}

static int iwl_mld_ftm_responder_set_bw(struct cfg80211_chan_def *chandef,
					u8 *format_bw, u8 *ctrl_ch_position)
{
	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_LEGACY;
		*format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_20:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		*format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_40:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		*format_bw |= IWL_LOCATION_BW_40MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	case NL80211_CHAN_WIDTH_80:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_VHT;
		*format_bw |= IWL_LOCATION_BW_80MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	case NL80211_CHAN_WIDTH_160:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
		*format_bw |= IWL_LOCATION_BW_160MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
iwl_mld_ftm_responder_cmd(struct iwl_mld *mld,
			  struct ieee80211_vif *vif,
			  struct cfg80211_chan_def *chandef,
			  struct ieee80211_bss_conf *link_conf)
{
	u32 cmd_id = WIDE_ID(LOCATION_GROUP, TOF_RESPONDER_CONFIG_CMD);
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_tof_responder_config_cmd cmd = {
		.channel_num = chandef->chan->hw_value,
		.cmd_valid_fields =
			cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_CHAN_INFO |
				    IWL_TOF_RESPONDER_CMD_VALID_BSSID |
				    IWL_TOF_RESPONDER_CMD_VALID_STA_ID),
	};
	int err;
	struct iwl_mld_link *mld_link;

	lockdep_assert_wiphy(mld->wiphy);

	mld_link = iwl_mld_link_dereference_check(mld_vif, link_conf->link_id);
	if (WARN_ON(!mld_link || mld_link->bcast_sta.sta_id == IWL_INVALID_STA))
		return -EINVAL;

	cmd.sta_id = mld_link->bcast_sta.sta_id;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	cmd.cmd_valid_fields |=
		cpu_to_le32(mld->trans->dbg_cfg.MLD_FTM_RESP_VALID);
	cmd.responder_cfg_flags |=
		cpu_to_le32(mld->trans->dbg_cfg.MLD_FTM_RESP_FLAGS);

	if (mld->trans->dbg_cfg.MLD_FTM_RESP_TOA_OFFSET) {
		cmd.cmd_valid_fields |=
			cpu_to_le32(IWL_TOF_RESPONDER_FLAGS_TOA_OFFSET_MODE);
		cmd.toa_offset =
			cpu_to_le16(mld->trans->dbg_cfg.MLD_FTM_RESP_TOA_OFFSET);
	}
#endif

	cmd.band = iwl_mld_nl80211_band_to_fw(chandef->chan->band);

	/* Use a default of bss_color=1 for now */
	cmd.cmd_valid_fields |=
		cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_BSS_COLOR |
			    IWL_TOF_RESPONDER_CMD_VALID_MIN_MAX_TIME_BETWEEN_MSR);
	cmd.bss_color = 1;
	cmd.min_time_between_msr =
		cpu_to_le16(IWL_MLD_FTM_NON_TB_MIN_TIME_BETWEEN_MSR);
	cmd.max_time_between_msr =
		cpu_to_le16(IWL_MLD_FTM_NON_TB_MAX_TIME_BETWEEN_MSR);

	iwl_mld_ftm_responder_set_ndp(mld, &cmd);

	err = iwl_mld_ftm_responder_set_bw(chandef, &cmd.format_bw,
					   &cmd.ctrl_ch_position);

	if (err) {
		IWL_ERR(mld, "Failed to set responder bandwidth\n");
		return err;
	}

	memcpy(cmd.bssid, vif->addr, ETH_ALEN);

	return iwl_mld_send_cmd_pdu(mld, cmd_id, &cmd);
}

static int
iwl_mld_ftm_responder_dyn_cfg_cmd(struct iwl_mld *mld,
				  struct ieee80211_ftm_responder_params *params)
{
	struct iwl_tof_responder_dyn_config_cmd cmd;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LOCATION_GROUP, TOF_RESPONDER_DYN_CONFIG_CMD),
		.data[0] = &cmd,
		.len[0] = sizeof(cmd),
		/* may not be able to DMA from stack */
		.dataflags[0] = IWL_HCMD_DFL_DUP,
	};

	lockdep_assert_wiphy(mld->wiphy);

	cmd.valid_flags = 0;

	if (params) {
		if (params->lci_len + 2 > sizeof(cmd.lci_buf) ||
		    params->civicloc_len + 2 > sizeof(cmd.civic_buf)) {
			IWL_ERR(mld,
				"LCI/civic data too big (lci=%zd, civic=%zd)\n",
				params->lci_len, params->civicloc_len);
			return -ENOBUFS;
		}

		if (params->lci_len) {
			cmd.lci_buf[0] = WLAN_EID_MEASURE_REPORT;
			cmd.lci_buf[1] = params->lci_len;
			memcpy(cmd.lci_buf + 2, params->lci, params->lci_len);
			cmd.lci_len = params->lci_len + 2;
			cmd.valid_flags |= IWL_RESPONDER_DYN_CFG_VALID_LCI;
		}

		if (params->civicloc_len) {
			cmd.civic_buf[0] = WLAN_EID_MEASURE_REPORT;
			cmd.civic_buf[1] = params->civicloc_len;
			memcpy(cmd.civic_buf + 2, params->civicloc,
			       params->civicloc_len);
			cmd.civic_len = params->civicloc_len + 2;
			cmd.valid_flags |= IWL_RESPONDER_DYN_CFG_VALID_CIVIC;
		}
	}

	return iwl_mld_send_cmd(mld, &hcmd);
}

int iwl_mld_ftm_start_responder(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct ieee80211_chanctx_conf *ctx;
	struct cfg80211_chan_def *chandef;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON_ONCE(!bss_conf->ftm_responder))
		return -EINVAL;

	if (vif->p2p || vif->type != NL80211_IFTYPE_AP ||
	    !mld_vif->ap_ibss_active) {
		IWL_ERR(mld, "Cannot start responder, not in AP mode\n");
		return -EIO;
	}

	ctx = wiphy_dereference(mld->wiphy, bss_conf->chanctx_conf);
	chandef = iwl_mld_get_chandef_from_chanctx(mld, ctx);

	ret = iwl_mld_ftm_responder_cmd(mld, vif, chandef, bss_conf);
	if (ret)
		return ret;

	if (bss_conf->ftmr_params)
		ret = iwl_mld_ftm_responder_dyn_cfg_cmd(mld,
							bss_conf->ftmr_params);

	return ret;
}
