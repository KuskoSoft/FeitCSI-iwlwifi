// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <linux/crc32.h>

#include <net/mac80211.h>

#include "ap.h"
#include "iface.h"
#include "hcmd.h"
#include "tx.h"
#include "iwl-utils.h"

#include "fw/api/tx.h"

static void iwl_mld_set_tim_idx(struct iwl_mld *mld, __le32 *tim_index,
				u8 *beacon, u32 frame_size)
{
	u32 tim_idx;
	struct ieee80211_mgmt *mgmt = (void *)beacon;

	/* The index is relative to frame start but we start looking at the
	 * variable-length part of the beacon.
	 */
	tim_idx = mgmt->u.beacon.variable - beacon;

	/* Parse variable-length elements of beacon to find WLAN_EID_TIM */
	while ((tim_idx < (frame_size - 2)) &&
	       (beacon[tim_idx] != WLAN_EID_TIM))
		tim_idx += beacon[tim_idx + 1] + 2;

	/* If TIM field was found, set variables */
	if ((tim_idx < (frame_size - 1)) && beacon[tim_idx] == WLAN_EID_TIM)
		*tim_index = cpu_to_le32(tim_idx);
	else
		IWL_WARN(mld, "Unable to find TIM Element in beacon\n");
}

static u8 iwl_mld_get_rate_flags(struct iwl_mld *mld,
				 struct ieee80211_tx_info *info,
				 struct ieee80211_vif *vif,
				 struct ieee80211_bss_conf *link,
				 enum nl80211_band band)
{
	u32 legacy = link->beacon_tx_rate.control[band].legacy;
	u32 rate_idx, rate_flags = 0, fw_rate;

	/* if beacon rate was configured try using it */
	if (hweight32(legacy) == 1) {
		u32 rate = ffs(legacy) - 1;
		struct ieee80211_supported_band *sband =
			mld->hw->wiphy->bands[band];

		rate_idx = sband->bitrates[rate].hw_value;
	} else {
		rate_idx = iwl_mld_get_lowest_rate(mld, info, vif);
	}

	if (rate_idx <= IWL_LAST_CCK_RATE)
		rate_flags = IWL_MAC_BEACON_CCK;

	/* Legacy rates are indexed as follows:
	 * 0 - 3 for CCK and 0 - 7 for OFDM.
	 */
	fw_rate = (rate_idx >= IWL_FIRST_OFDM_RATE ?
		     rate_idx - IWL_FIRST_OFDM_RATE : rate_idx);

	return fw_rate | rate_flags;
}

static int iwl_mld_send_beacon_template_cmd(struct iwl_mld *mld,
					    struct sk_buff *beacon,
					    struct iwl_mac_beacon_cmd *cmd)
{
	struct iwl_host_cmd hcmd = {
		.id = BEACON_TEMPLATE_CMD,
	};

	hcmd.len[0] = sizeof(*cmd);
	hcmd.data[0] = cmd;

	hcmd.len[1] = beacon->len;
	hcmd.data[1] = beacon->data;
	hcmd.dataflags[1] = IWL_HCMD_DFL_DUP;

	return iwl_mld_send_cmd(mld, &hcmd);
}

static int iwl_mld_fill_beacon_template_cmd(struct iwl_mld *mld,
					    struct ieee80211_vif *vif,
					    struct sk_buff *beacon,
					    struct iwl_mac_beacon_cmd *cmd,
					    struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(beacon);
	struct ieee80211_chanctx_conf *ctx;
	bool enable_fils;
	u16 flags = 0;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	cmd->link_id = cpu_to_le32(mld_link->fw_id);

	ctx = wiphy_dereference(mld->wiphy, link->chanctx_conf);
	if (WARN_ON(!ctx || !ctx->def.chan))
		return -EINVAL;

	enable_fils = cfg80211_channel_is_psc(ctx->def.chan) ||
		(ctx->def.chan->band == NL80211_BAND_6GHZ &&
		 ctx->def.width >= NL80211_CHAN_WIDTH_80);

	if (enable_fils) {
		flags |= IWL_MAC_BEACON_FILS;
		cmd->short_ssid = cpu_to_le32(~crc32_le(~0, vif->cfg.ssid,
							vif->cfg.ssid_len));
	}

	cmd->byte_cnt = cpu_to_le16((u16)beacon->len);

	flags |= iwl_mld_get_rate_flags(mld, info, vif, link,
					ctx->def.chan->band);

	cmd->flags = cpu_to_le16(flags);

	if (vif->type == NL80211_IFTYPE_AP) {
		iwl_mld_set_tim_idx(mld, &cmd->tim_idx,
				    beacon->data, beacon->len);

		cmd->btwt_offset =
			cpu_to_le32(iwl_find_ie_offset(beacon->data,
						       WLAN_EID_S1G_TWT,
						       beacon->len));
	}

	cmd->csa_offset =
		cpu_to_le32(iwl_find_ie_offset(beacon->data,
					       WLAN_EID_CHANNEL_SWITCH,
					       beacon->len));
	cmd->ecsa_offset =
		cpu_to_le32(iwl_find_ie_offset(beacon->data,
					       WLAN_EID_EXT_CHANSWITCH_ANN,
					       beacon->len));

	return 0;
}

/* The beacon template for the AP/GO/IBSS has changed and needs update */
int iwl_mld_update_beacon_template(struct iwl_mld *mld,
				   struct ieee80211_vif *vif,
				   struct ieee80211_bss_conf *link_conf)
{
	struct iwl_mac_beacon_cmd cmd = {};
	struct sk_buff *beacon;
	int ret;

	WARN_ON(vif->type != NL80211_IFTYPE_AP &&
		vif->type != NL80211_IFTYPE_ADHOC);

	beacon = ieee80211_beacon_get_template(mld->hw, vif, NULL,
					       link_conf->link_id);
	if (!beacon)
		return -ENOMEM;

	ret = iwl_mld_fill_beacon_template_cmd(mld, vif, beacon, &cmd,
					       link_conf);

	if (!ret)
		ret = iwl_mld_send_beacon_template_cmd(mld, beacon, &cmd);

	dev_kfree_skb(beacon);

	return ret;
}
