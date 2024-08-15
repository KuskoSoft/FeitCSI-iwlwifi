// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "constants.h"
#include "link.h"
#include "iface.h"
#include "hcmd.h"
#include "phy.h"
#include "fw/api/rs.h"
#include "fw/api/txq.h"
#include "fw/api/mac.h"

#include "fw/api/context.h"
#include "fw/dbg.h"

static int iwl_mld_send_link_cmd(struct iwl_mld *mld,
				 struct iwl_link_config_cmd *cmd,
				 enum iwl_ctxt_action action)
{
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	cmd->action = cpu_to_le32(action);
	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(MAC_CONF_GROUP, LINK_CONFIG_CMD),
				   cmd);
	if (ret)
		IWL_ERR(mld, "Failed to send LINK_CONFIG_CMD (action:%d): %d\n",
			action, ret);
	return ret;
}

static int iwl_mld_add_link_to_fw(struct iwl_mld *mld,
				  struct ieee80211_bss_conf *link_conf)
{
	struct ieee80211_vif *vif = link_conf->vif;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(link_conf);
	struct iwl_link_config_cmd cmd = {};

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(link->fw_id);
	cmd.mac_id = cpu_to_le32(mld_vif->fw_id);
	cmd.spec_link_id = link_conf->link_id;
	cmd.phy_id = cpu_to_le32(FW_CTXT_ID_INVALID);

	ether_addr_copy(cmd.local_link_addr, link_conf->addr);

	if (vif->type == NL80211_IFTYPE_ADHOC && link_conf->bssid)
		ether_addr_copy(cmd.ibss_bssid_addr, link_conf->bssid);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_ADD);
}

/* Get the basic rates of the used band and add the mandatory ones */
static void iwl_mld_fill_rates(struct iwl_mld *mld,
			       struct ieee80211_bss_conf *link,
			       struct ieee80211_chanctx_conf *chan_ctx,
			       __le32 *cck_rates, __le32 *ofdm_rates)
{
	struct cfg80211_chan_def *chandef =
		iwl_mld_get_chandef_from_chanctx(chan_ctx);
	struct ieee80211_supported_band *sband =
		mld->hw->wiphy->bands[chandef->chan->band];
	unsigned long basic = link->basic_rates;
	int lowest_present_ofdm = 100;
	int lowest_present_cck = 100;
	u32 cck = 0;
	u32 ofdm = 0;
	int i;

	for_each_set_bit(i, &basic, BITS_PER_LONG) {
		int hw = sband->bitrates[i].hw_value;

		if (hw >= IWL_FIRST_OFDM_RATE) {
			ofdm |= BIT(hw - IWL_FIRST_OFDM_RATE);
			if (lowest_present_ofdm > hw)
				lowest_present_ofdm = hw;
		} else {
			BUILD_BUG_ON(IWL_FIRST_CCK_RATE != 0);

			cck |= BIT(hw);
			if (lowest_present_cck > hw)
				lowest_present_cck = hw;
		}
	}

	/* Now we've got the basic rates as bitmaps in the ofdm and cck
	 * variables. This isn't sufficient though, as there might not
	 * be all the right rates in the bitmap. E.g. if the only basic
	 * rates are 5.5 Mbps and 11 Mbps, we still need to add 1 Mbps
	 * and 6 Mbps because the 802.11-2007 standard says in 9.6:
	 *
	 *    [...] a STA responding to a received frame shall transmit
	 *    its Control Response frame [...] at the highest rate in the
	 *    BSSBasicRateSet parameter that is less than or equal to the
	 *    rate of the immediately previous frame in the frame exchange
	 *    sequence ([...]) and that is of the same modulation class
	 *    ([...]) as the received frame. If no rate contained in the
	 *    BSSBasicRateSet parameter meets these conditions, then the
	 *    control frame sent in response to a received frame shall be
	 *    transmitted at the highest mandatory rate of the PHY that is
	 *    less than or equal to the rate of the received frame, and
	 *    that is of the same modulation class as the received frame.
	 *
	 * As a consequence, we need to add all mandatory rates that are
	 * lower than all of the basic rates to these bitmaps.
	 */

	if (lowest_present_ofdm > IWL_RATE_24M_INDEX)
		ofdm |= IWL_RATE_BIT_MSK(24) >> IWL_FIRST_OFDM_RATE;
	if (lowest_present_ofdm > IWL_RATE_12M_INDEX)
		ofdm |= IWL_RATE_BIT_MSK(12) >> IWL_FIRST_OFDM_RATE;
	/* 6M already there or needed so always add */
	ofdm |= IWL_RATE_BIT_MSK(6) >> IWL_FIRST_OFDM_RATE;

	/* CCK is a bit more complex with DSSS vs. HR/DSSS vs. ERP.
	 * Note, however:
	 *  - if no CCK rates are basic, it must be ERP since there must
	 *    be some basic rates at all, so they're OFDM => ERP PHY
	 *    (or we're in 5 GHz, and the cck bitmap will never be used)
	 *  - if 11M is a basic rate, it must be ERP as well, so add 5.5M
	 *  - if 5.5M is basic, 1M and 2M are mandatory
	 *  - if 2M is basic, 1M is mandatory
	 *  - if 1M is basic, that's the only valid ACK rate.
	 * As a consequence, it's not as complicated as it sounds, just add
	 * any lower rates to the ACK rate bitmap.
	 */
	if (lowest_present_cck > IWL_RATE_11M_INDEX)
		cck |= IWL_RATE_BIT_MSK(11) >> IWL_FIRST_CCK_RATE;
	if (lowest_present_cck > IWL_RATE_5M_INDEX)
		cck |= IWL_RATE_BIT_MSK(5) >> IWL_FIRST_CCK_RATE;
	if (lowest_present_cck > IWL_RATE_2M_INDEX)
		cck |= IWL_RATE_BIT_MSK(2) >> IWL_FIRST_CCK_RATE;
	/* 1M already there or needed so always add */
	cck |= IWL_RATE_BIT_MSK(1) >> IWL_FIRST_CCK_RATE;

	*cck_rates = cpu_to_le32((u32)cck);
	*ofdm_rates = cpu_to_le32((u32)ofdm);
}

static void iwl_mld_fill_pretection_flags(struct iwl_mld *mld,
					  struct ieee80211_bss_conf *link,
					  __le32 *protection_flags)
{
	u8 protection_mode = link->ht_operation_mode &
				IEEE80211_HT_OP_MODE_PROTECTION;
	u8 ht_flag = LINK_PROT_FLG_HT_PROT | LINK_PROT_FLG_FAT_PROT;

	IWL_DEBUG_RATE(mld, "HT protection mode: %d\n", protection_mode);

	if (link->use_cts_prot)
		*protection_flags |= cpu_to_le32(LINK_PROT_FLG_TGG_PROTECT);

	/* See section 9.23.3.1 of IEEE 80211-2012.
	 * Nongreenfield HT STAs Present is not supported.
	 */
	switch (protection_mode) {
	case IEEE80211_HT_OP_MODE_PROTECTION_NONE:
		break;
	case IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER:
	case IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED:
		*protection_flags |= cpu_to_le32(ht_flag);
		break;
	case IEEE80211_HT_OP_MODE_PROTECTION_20MHZ:
		/* Protect when channel wider than 20MHz */
		if (link->chanreq.oper.width > NL80211_CHAN_WIDTH_20)
			*protection_flags |= cpu_to_le32(ht_flag);
		break;
	default:
		IWL_ERR(mld, "Illegal protection mode %d\n",
			protection_mode);
		break;
	}
}

static u8 iwl_mld_mac80211_ac_to_fw_ac(enum ieee80211_ac_numbers ac)
{
	static const u8 mac80211_ac_to_fw[] = {
		AC_VO,
		AC_VI,
		AC_BE,
		AC_BK
	};

	return mac80211_ac_to_fw[ac];
}

static void iwl_mld_fill_qos_params(struct ieee80211_bss_conf *link,
				    struct iwl_ac_qos *ac, __le32 *qos_flags)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);

	/* no need to check mld_link since it is done in the caller */

	for (int mac_ac = 0; mac_ac < IEEE80211_NUM_ACS; mac_ac++) {
		u8 txf = iwl_mld_mac80211_ac_to_fw_tx_fifo(mac_ac);
		u8 fw_ac = iwl_mld_mac80211_ac_to_fw_ac(mac_ac);

		ac[fw_ac].cw_min =
			cpu_to_le16(mld_link->queue_params[mac_ac].cw_min);
		ac[fw_ac].cw_max =
			cpu_to_le16(mld_link->queue_params[mac_ac].cw_max);
		ac[fw_ac].edca_txop =
			cpu_to_le16(mld_link->queue_params[mac_ac].txop * 32);
		ac[fw_ac].aifsn = mld_link->queue_params[mac_ac].aifs;
		ac[fw_ac].fifos_mask = BIT(txf);
	}

	if (link->qos)
		*qos_flags |= cpu_to_le32(MAC_QOS_FLG_UPDATE_EDCA);

	if (link->chanreq.oper.width != NL80211_CHAN_WIDTH_20_NOHT)
		*qos_flags |= cpu_to_le32(MAC_QOS_FLG_TGN);
}

static bool iwl_mld_fill_mu_edca(const struct iwl_mld_link *mld_link,
				 struct iwl_he_backoff_conf *trig_based_txf)
{
	for (int mac_ac = 0; mac_ac < IEEE80211_NUM_ACS; mac_ac++) {
		const struct ieee80211_he_mu_edca_param_ac_rec *mu_edca =
			&mld_link->queue_params[mac_ac].mu_edca_param_rec;
		u8 fw_ac = iwl_mld_mac80211_ac_to_fw_ac(mac_ac);

		if (!mld_link->queue_params[mac_ac].mu_edca)
			return false;

		trig_based_txf[fw_ac].cwmin =
			cpu_to_le16(mu_edca->ecw_min_max & 0xf);
		trig_based_txf[fw_ac].cwmax =
			cpu_to_le16((mu_edca->ecw_min_max & 0xf0) >> 4);
		trig_based_txf[fw_ac].aifsn =
			cpu_to_le16(mu_edca->aifsn & 0xf);
		trig_based_txf[fw_ac].mu_time =
			cpu_to_le16(mu_edca->mu_edca_timer);
	}

	return true;
}

int
iwl_mld_change_link_in_fw(struct iwl_mld *mld, struct ieee80211_bss_conf *link,
			  u32 changes)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	struct ieee80211_vif *vif = link->vif;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct ieee80211_chanctx_conf *chan_ctx;
	struct iwl_link_config_cmd cmd = {};
	u32 flags = 0;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(mld_link->fw_id);
	cmd.spec_link_id = link->link_id;
	cmd.mac_id = cpu_to_le32(mld_vif->fw_id);

	chan_ctx = wiphy_dereference(mld->wiphy, mld_link->chan_ctx);

	cmd.phy_id = cpu_to_le32(chan_ctx ?
		iwl_mld_phy_from_mac80211(chan_ctx)->fw_id :
		FW_CTXT_ID_INVALID);

	ether_addr_copy(cmd.local_link_addr, link->addr);

	cmd.active = cpu_to_le32(mld_link->active);

	if (vif->type == NL80211_IFTYPE_ADHOC && link->bssid)
		ether_addr_copy(cmd.ibss_bssid_addr, link->bssid);

	/* Channel context is needed to get the rates */
	if (chan_ctx)
		iwl_mld_fill_rates(mld, link, chan_ctx, &cmd.cck_rates,
				   &cmd.ofdm_rates);

	cmd.cck_short_preamble = cpu_to_le32(link->use_short_preamble);
	cmd.short_slot = cpu_to_le32(link->use_short_slot);

	iwl_mld_fill_pretection_flags(mld, link, &cmd.protection_flags);

	iwl_mld_fill_qos_params(link, cmd.ac, &cmd.qos_flags);

	cmd.bi = cpu_to_le32(link->beacon_int);
	cmd.dtim_interval = cpu_to_le32(link->beacon_int * link->dtim_period);

	/* Configure HE parameters only if HE is supported, and only after
	 * the parameters are set in mac80211 (meaning after assoc)
	 */
	if (!link->he_support || iwlwifi_mod_params.disable_11ax ||
	    (vif->type == NL80211_IFTYPE_STATION && !vif->cfg.assoc)) {
		changes &= ~LINK_CONTEXT_MODIFY_HE_PARAMS;
		goto send_cmd;
	}

	/* ap_sta may be NULL if we're disconnecting */
	if (mld_vif->ap_sta) {
		struct ieee80211_link_sta *link_sta =
			link_sta_dereference_check(mld_vif->ap_sta,
						   link->link_id);

		if (!WARN_ON(!link_sta) && link_sta->he_cap.has_he &&
		    link_sta->he_cap.he_cap_elem.mac_cap_info[5] &
		    IEEE80211_HE_MAC_CAP5_OM_CTRL_UL_MU_DATA_DIS_RX)
			cmd.ul_mu_data_disable = 1;
	}

	cmd.htc_trig_based_pkt_ext = link->htc_trig_based_pkt_ext;

	if (link->uora_exists) {
		cmd.rand_alloc_ecwmin = link->uora_ocw_range & 0x7;
		cmd.rand_alloc_ecwmax = (link->uora_ocw_range >> 3) & 0x7;
	}

	if (iwl_mld_fill_mu_edca(mld_link, cmd.trig_based_txf))
		flags |= LINK_FLG_MU_EDCA_CW;

	cmd.bss_color = link->he_bss_color.color;

	if (!link->he_bss_color.enabled)
		flags |= LINK_FLG_BSS_COLOR_DIS;

	cmd.frame_time_rts_th = cpu_to_le16(link->frame_time_rts_th);

	/* Block 26-tone RU OFDMA transmissions */
	/* TODO: calculate he_ru_2mhz_block upon assoc (task=assoc) */
	if (mld_link->he_ru_2mhz_block)
		flags |= LINK_FLG_RU_2MHZ_BLOCK;

	if (link->nontransmitted) {
		ether_addr_copy(cmd.ref_bssid_addr, link->transmitter_bssid);
		cmd.bssid_index = link->bssid_index;
	}

	/* The only EHT parameter is puncturing, and starting from PHY cmd
	 * version 6 - it is sent there. For older versions of the PHY cmd,
	 * puncturing is not needed at all.
	 */
	if (WARN_ON(changes & LINK_CONTEXT_MODIFY_EHT_PARAMS))
		changes &= ~LINK_CONTEXT_MODIFY_EHT_PARAMS;

send_cmd:
	cmd.modify_mask = cpu_to_le32(changes);
	cmd.flags = cpu_to_le32(flags);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_MODIFY);
}

int iwl_mld_activate_link(struct iwl_mld *mld,
			  struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	mld_link->active = true;

	ret = iwl_mld_change_link_in_fw(mld, link,
					LINK_CONTEXT_MODIFY_ACTIVE);
	if (ret)
		mld_link->active = false;

	return ret;
}

int iwl_mld_deactivate_link(struct iwl_mld *mld,
			    struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	ret = iwl_mld_cancel_session_protection(mld, link->vif, link->link_id);
	if (ret)
		return ret;

	mld_link->active = false;

	ret = iwl_mld_change_link_in_fw(mld, link,
					LINK_CONTEXT_MODIFY_ACTIVE);

	if (ret)
		mld_link->active = true;

	return ret;
}

static int
iwl_mld_rm_link_from_fw(struct iwl_mld *mld, struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	struct iwl_link_config_cmd cmd = {};

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(mld_link->fw_id);
	cmd.spec_link_id = link->link_id;
	cmd.phy_id = cpu_to_le32(FW_CTXT_ID_INVALID);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_REMOVE);
}

IWL_MLD_ALLOC_FN(link, bss_conf)

/* Constructor function for struct iwl_mld_link */
static int
iwl_mld_init_link(struct iwl_mld *mld, struct ieee80211_bss_conf *link,
		  struct iwl_mld_link *mld_link)
{
	return iwl_mld_allocate_link_fw_id(mld, &mld_link->fw_id, link);
}

/* Initializes the link structure, maps fw id to the ieee80211_bss_conf, and
 * adds a link to the fw
 */
int iwl_mld_add_link(struct iwl_mld *mld,
		     struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(bss_conf);
	int ret;

	ret = iwl_mld_init_link(mld, bss_conf, link);
	if (ret)
		return ret;

	ret = iwl_mld_add_link_to_fw(mld, bss_conf);
	if (ret)
		RCU_INIT_POINTER(mld->fw_id_to_bss_conf[link->fw_id], NULL);

	return ret;
}

/* Remove link from fw, unmap the bss_conf, and destroy the link structure */
int iwl_mld_remove_link(struct iwl_mld *mld,
			struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(bss_conf);
	int ret;

	if (link->active) {
		ret = iwl_mld_deactivate_link(mld, bss_conf);
		if (ret)
			return ret;
	}

	ret = iwl_mld_rm_link_from_fw(mld, bss_conf);
	if (ret)
		return ret;

	if (WARN_ON(link->fw_id >= ARRAY_SIZE(mld->fw_id_to_bss_conf)))
		return -EINVAL;

	RCU_INIT_POINTER(mld->fw_id_to_bss_conf[link->fw_id], NULL);

	return 0;
}

void iwl_mld_handle_missed_beacon_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt)
{
	const struct iwl_missed_beacons_notif *notif = (const void *)pkt->data;
	union iwl_dbg_tlv_tp_data tp_data = { .fw_pkt = pkt };
	u32 link_id = le32_to_cpu(notif->link_id);
	u32 missed_bcon = le32_to_cpu(notif->consec_missed_beacons);
	u32 missed_bcon_since_rx =
		le32_to_cpu(notif->consec_missed_beacons_since_last_rx);
	u32 scnd_lnk_bcn_lost =
		le32_to_cpu(notif->consec_missed_beacons_other_link);
	struct ieee80211_bss_conf *link_conf =
		iwl_mld_fw_id_to_link_conf(mld, link_id);
	u32 bss_param_ch_cnt_link_id;
	struct ieee80211_vif *vif;

	if (WARN_ON(!link_conf))
		return;

	vif = link_conf->vif;
	bss_param_ch_cnt_link_id = link_conf->bss_param_ch_cnt_link_id;

	IWL_DEBUG_INFO(mld,
		       "missed bcn link_id=%u, %u consecutive=%u\n",
		       link_id, missed_bcon, missed_bcon_since_rx);

	if (WARN_ON(!vif))
		return;

	mld->trans->dbg.dump_file_name_ext_valid = true;
	snprintf(mld->trans->dbg.dump_file_name_ext, IWL_FW_INI_MAX_NAME,
		 "LinkId_%d_MacType_%d", link_id,
		 iwl_mld_mac80211_iftype_to_fw(vif));

	iwl_dbg_tlv_time_point(&mld->fwrt,
			       IWL_FW_INI_TIME_POINT_MISSED_BEACONS, &tp_data);

	if (missed_bcon >= IWL_MLD_MISSED_BEACONS_THRESHOLD_LONG) {
		if (missed_bcon_since_rx >=
		    IWL_MLD_MISSED_BEACONS_SINCE_RX_THOLD) {
			ieee80211_connection_loss(vif);
			return;
		}
		IWL_WARN(mld,
			 "missed beacons exceeds threshold, but receiving data. Stay connected, Expect bugs.\n");
		return;
	}

	if (missed_bcon_since_rx > IWL_MLD_MISSED_BEACONS_THRESHOLD)
		ieee80211_cqm_beacon_loss_notify(vif, GFP_ATOMIC);

	/* no more logic if we're not in EMLSR */
	if (hweight16(vif->active_links) <= 1)
		return;

	if (IWL_FW_CHECK(mld,
			 le32_to_cpu(notif->other_link_id) == FW_CTXT_ID_INVALID,
			 "No data for other link id but we are in EMLSR. active_links: 0x%x\n",
			 vif->active_links))
		return;

	/* Exit EMLSR if we lost more than
	 * IWL_MLD_MISSED_BEACONS_EXIT_ESR_THRESH beacons on boths links
	 * OR more than IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH on current link.
	 * OR more than IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH_BSS_PARAM_CHANGED
	 * on current link and the link's bss_param_ch_count has changed on
	 * the other link's beacon.
	 */
	if ((missed_bcon >= IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH_2_LINKS &&
	     scnd_lnk_bcn_lost >= IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH_2_LINKS) ||
	    missed_bcon >= IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH ||
	    (bss_param_ch_cnt_link_id != link_id &&
	     missed_bcon >=
	     IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH_BSS_PARAM_CHANGED)) {
		/* TODO EMLSR: exit esr */
		IWL_ERR(mld, "Not implemented, exist EMLSR\n");
	}
}

int iwl_mld_link_set_associated(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *link)
{
	return iwl_mld_change_link_in_fw(mld, link, LINK_CONTEXT_MODIFY_ALL &
					 ~(LINK_CONTEXT_MODIFY_ACTIVE |
					   LINK_CONTEXT_MODIFY_EHT_PARAMS));
}
