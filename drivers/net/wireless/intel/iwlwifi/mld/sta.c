// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <linux/ieee80211.h>

#include "sta.h"
#include "hcmd.h"
#include "iface.h"
#include "fw/api/sta.h"
#include "fw/api/mac.h"

static int
iwl_mld_fw_sta_id_from_link_sta(struct iwl_mld *mld,
				struct ieee80211_link_sta *link_sta)
{
	/* This is not meant to be called with a NULL pointer */
	if (WARN_ON(!link_sta))
		return -ENOENT;

	for (int fw_id = 0; fw_id < mld->fw->ucode_capa.num_stations;
	     fw_id++) {
		struct ieee80211_link_sta *l_sta;

		l_sta = rcu_access_pointer(mld->fw_id_to_link_sta[fw_id]);

		if (l_sta == link_sta)
			return fw_id;
	}
	return -ENOENT;
}

static void
iwl_mld_fill_ampdu_size_and_dens(struct ieee80211_link_sta *link_sta,
				 struct ieee80211_bss_conf *link,
				 __le32 *tx_ampdu_max_size,
				 __le32 *tx_ampdu_spacing)
{
	u32 agg_size = 0, mpdu_dens = 0;

	if (WARN_ON(!link_sta || !link))
		return;

	/* Note that we always use only legacy & highest supported PPDUs, so
	 * of Draft P802.11be D.30 Table 10-12a--Fields used for calculating
	 * the maximum A-MPDU size of various PPDU types in different bands,
	 * we only need to worry about the highest supported PPDU type here.
	 */

	if (link_sta->ht_cap.ht_supported) {
		agg_size = link_sta->ht_cap.ampdu_factor;
		mpdu_dens = link_sta->ht_cap.ampdu_density;
	}

	if (link->chanreq.oper.chan->band == NL80211_BAND_6GHZ) {
		/* overwrite HT values on 6 GHz */
		mpdu_dens =
			le16_get_bits(link_sta->he_6ghz_capa.capa,
				      IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START);
		agg_size =
			le16_get_bits(link_sta->he_6ghz_capa.capa,
				      IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP);
	} else if (link_sta->vht_cap.vht_supported) {
		/* if VHT supported overwrite HT value */
		agg_size =
			u32_get_bits(link_sta->vht_cap.cap,
				     IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK);
	}

	/* D6.0 10.12.2 A-MPDU length limit rules
	 * A STA indicates the maximum length of the A-MPDU preEOF padding
	 * that it can receive in an HE PPDU in the Maximum A-MPDU Length
	 * Exponent field in its HT Capabilities, VHT Capabilities,
	 * and HE 6 GHz Band Capabilities elements (if present) and the
	 * Maximum AMPDU Length Exponent Extension field in its HE
	 * Capabilities element
	 */
	if (link_sta->he_cap.has_he)
		agg_size +=
			u8_get_bits(link_sta->he_cap.he_cap_elem.mac_cap_info[3],
				    IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK);

	if (link_sta->eht_cap.has_eht)
		agg_size +=
			u8_get_bits(link_sta->eht_cap.eht_cap_elem.mac_cap_info[1],
				    IEEE80211_EHT_MAC_CAP1_MAX_AMPDU_LEN_MASK);

	/* Limit to max A-MPDU supported by FW */
	agg_size = min_t(u32, agg_size,
			 STA_FLG_MAX_AGG_SIZE_4M >> STA_FLG_MAX_AGG_SIZE_SHIFT);

	*tx_ampdu_max_size = cpu_to_le32(agg_size);
	*tx_ampdu_spacing = cpu_to_le32(mpdu_dens);
}

static u8 iwl_mld_get_uapsd_acs(struct ieee80211_sta *sta)
{
	u8 uapsd_acs = 0;

	if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BK)
		uapsd_acs |= BIT(AC_BK);
	if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BE)
		uapsd_acs |= BIT(AC_BE);
	if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VI)
		uapsd_acs |= BIT(AC_VI);
	if (sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VO)
		uapsd_acs |= BIT(AC_VO);

	return uapsd_acs | uapsd_acs << 4;
}

static void iwl_mld_fill_pkt_ext(struct ieee80211_link_sta *link_sta,
				 struct iwl_he_pkt_ext_v2 *pkt_ext)
{
	/* TODO (task=EHT connection)*/
}

static u32 iwl_mld_get_htc_flags(struct ieee80211_link_sta *link_sta)
{
	u8 *mac_cap_info =
		&link_sta->he_cap.he_cap_elem.mac_cap_info[0];
	u32 htc_flags = 0;

	if (mac_cap_info[0] & IEEE80211_HE_MAC_CAP0_HTC_HE)
		htc_flags |= IWL_HE_HTC_SUPPORT;
	if ((mac_cap_info[1] & IEEE80211_HE_MAC_CAP1_LINK_ADAPTATION) ||
	    (mac_cap_info[2] & IEEE80211_HE_MAC_CAP2_LINK_ADAPTATION)) {
		u8 link_adap =
			((mac_cap_info[2] &
			  IEEE80211_HE_MAC_CAP2_LINK_ADAPTATION) << 1) +
			 (mac_cap_info[1] &
			  IEEE80211_HE_MAC_CAP1_LINK_ADAPTATION);

		if (link_adap == 2)
			htc_flags |=
				IWL_HE_HTC_LINK_ADAP_UNSOLICITED;
		else if (link_adap == 3)
			htc_flags |= IWL_HE_HTC_LINK_ADAP_BOTH;
	}
	if (mac_cap_info[2] & IEEE80211_HE_MAC_CAP2_BSR)
		htc_flags |= IWL_HE_HTC_BSR_SUPP;
	if (mac_cap_info[3] & IEEE80211_HE_MAC_CAP3_OMI_CONTROL)
		htc_flags |= IWL_HE_HTC_OMI_SUPP;
	if (mac_cap_info[4] & IEEE80211_HE_MAC_CAP4_BQR)
		htc_flags |= IWL_HE_HTC_BQR_SUPP;

	return htc_flags;
}

static int iwl_mld_send_sta_cmd(struct iwl_mld *mld,
				const struct iwl_sta_cfg_cmd *cmd)
{
	int ret = iwl_mld_send_cmd_pdu(mld,
				       WIDE_ID(MAC_CONF_GROUP, STA_CONFIG_CMD),
				       cmd);
	if (ret)
		IWL_ERR(mld, "STA_CONFIG_CMD send failed, ret=0x%x\n", ret);
	return ret;
}

static int
iwl_mld_add_modify_sta_cmd(struct iwl_mld *mld,
			   struct ieee80211_link_sta *link_sta)
{
	struct ieee80211_sta *sta = link_sta->sta;
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_bss_conf *link;
	struct iwl_mld_link *mld_link;
	struct iwl_sta_cfg_cmd cmd = {};
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

	lockdep_assert_wiphy(mld->wiphy);

	link = link_conf_dereference_protected(mld_sta->vif,
					       link_sta->link_id);

	mld_link = iwl_mld_link_from_mac80211(link);

	if (WARN_ON(!link || !mld_link || fw_id < 0))
		return -EINVAL;

	cmd.sta_id = cpu_to_le32(fw_id);
	cmd.station_type = cpu_to_le32(mld_sta->sta_type);
	cmd.link_id = cpu_to_le32(mld_link->fw_id);

	memcpy(&cmd.peer_mld_address, sta->addr, ETH_ALEN);
	memcpy(&cmd.peer_link_address, link_sta->addr, ETH_ALEN);

	if (mld_sta->sta_state >= IEEE80211_STA_ASSOC)
		cmd.assoc_id = cpu_to_le32(sta->aid);

	if (sta->mfp || mld_sta->sta_state < IEEE80211_STA_AUTHORIZED)
		cmd.mfp = cpu_to_le32(1);

	switch (link_sta->rx_nss) {
	case 1:
		cmd.mimo = cpu_to_le32(0);
		break;
	case 2 ... 8:
		cmd.mimo = cpu_to_le32(1);
		break;
	}

	switch (link_sta->smps_mode) {
	case IEEE80211_SMPS_AUTOMATIC:
	case IEEE80211_SMPS_NUM_MODES:
		WARN_ON(1);
		break;
	case IEEE80211_SMPS_STATIC:
		/* override NSS */
		cmd.mimo = cpu_to_le32(0);
		break;
	case IEEE80211_SMPS_DYNAMIC:
		cmd.mimo_protection = cpu_to_le32(1);
		break;
	case IEEE80211_SMPS_OFF:
		/* nothing */
		break;
	}

	iwl_mld_fill_ampdu_size_and_dens(link_sta, link,
					 &cmd.tx_ampdu_max_size,
					 &cmd.tx_ampdu_spacing);

	if (sta->wme) {
		cmd.sp_length =
			cpu_to_le32(sta->max_sp ? sta->max_sp * 2 : 128);
		cmd.uapsd_acs = cpu_to_le32(iwl_mld_get_uapsd_acs(sta));
	}

	if (link_sta->he_cap.has_he) {
		cmd.trig_rnd_alloc =
			cpu_to_le32(link->uora_exists ? 1 : 0);

		/* PPE Thresholds */
		iwl_mld_fill_pkt_ext(link_sta, &cmd.pkt_ext);

		/* HTC flags */
		cmd.htc_flags =
			cpu_to_le32(iwl_mld_get_htc_flags(link_sta));

		if (link_sta->he_cap.he_cap_elem.mac_cap_info[2] &
		    IEEE80211_HE_MAC_CAP2_ACK_EN)
			cmd.ack_enabled = cpu_to_le32(1);
	}

	return iwl_mld_send_sta_cmd(mld, &cmd);
}

IWL_MLD_ALLOC_FN(link_sta, link_sta)

static int
iwl_mld_add_link_sta(struct iwl_mld *mld, struct ieee80211_link_sta *link_sta)
{
	int ret;
	u8 fw_id;

	/* We need to preserve the fw sta ids during a restart, since the fw
	 * will recover SN/PN for them
	 */
	if (!mld->fw_status.in_hw_restart) {
		/* Allocate a fw id and map it to the link_sta */
		ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
		if (ret)
			return ret;
	}

	ret = iwl_mld_add_modify_sta_cmd(mld, link_sta);
	if (ret)
		RCU_INIT_POINTER(mld->fw_id_to_link_sta[fw_id], NULL);

	return ret;
}

static int iwl_mld_rm_sta_from_fw(struct iwl_mld *mld, u8 fw_sta_id)
{
	struct iwl_remove_sta_cmd cmd = {
		.sta_id = cpu_to_le32(fw_sta_id),
	};
	int ret;

	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(MAC_CONF_GROUP, STA_REMOVE_CMD),
				   &cmd);
	if (ret)
		IWL_ERR(mld, "Failed to remove station. Id=%d\n", fw_sta_id);

	return ret;
}

static void
iwl_mvm_remove_link_sta(struct iwl_mld *mld,
			struct ieee80211_link_sta *link_sta)
{
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

	if (WARN_ON(fw_id < 0))
		return;

	iwl_mld_rm_sta_from_fw(mld, fw_id);

	/* This will not be set to NULL upon reconfig, so set it also when
	 * failed to remove from fw
	 */
	RCU_INIT_POINTER(mld->fw_id_to_link_sta[fw_id], NULL);
}

int iwl_mld_update_all_link_stations(struct iwl_mld *mld,
				     struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	int link_id;

	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		int ret = iwl_mld_add_modify_sta_cmd(mld, link_sta);
			if (ret)
				return ret;
	}
	return 0;
}

static void
iwl_mld_init_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		 struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	mld_sta->vif = vif;
	mld_sta->sta_type = type;

	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++)
		iwl_mld_init_txq(iwl_mld_txq_from_mac80211(sta->txq[i]));
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	int link_id;

	iwl_mld_init_sta(mld, sta, vif, type);

	/* We could have add only the deflink link_sta, but it will not work
	 * in the restart case if the single link that is active during
	 * reconfig is not the deflink one.
	 */
	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		int ret = iwl_mld_add_link_sta(mld, link_sta);
			if (ret)
				return ret;
	}
	return 0;
}

void iwl_mld_flush_sta_txqs(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	int link_id;

	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		u32 fw_sta_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

		iwl_mld_flush_link_sta_txqs(mld, fw_sta_id);
	}
}

void iwl_mld_wait_sta_txqs_empty(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	/* Avoid a warning in iwl_trans_wait_txq_empty if are anyway on the way
	 * to a restart.
	 */
	if (iwl_mld_error_before_recovery(mld))
		return;

	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++) {
		struct iwl_mld_txq *mld_txq =
			iwl_mld_txq_from_mac80211(sta->txq[i]);

		if (!mld_txq->status.allocated)
			continue;

		iwl_trans_wait_txq_empty(mld->trans, mld_txq->fw_id);
	}
}

void iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	u8 link_id;

	lockdep_assert_wiphy(mld->wiphy);

	/* Tell the HW to flush the queues */
	iwl_mld_flush_sta_txqs(mld, sta);

	/* Wait for trans to empty its queues */
	iwl_mld_wait_sta_txqs_empty(mld, sta);

	/* Now we can remove the queues */
	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++)
		iwl_mld_remove_txq(mld, sta->txq[i]);

	/* Remove all link_sta's*/
	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id)
		iwl_mvm_remove_link_sta(mld, link_sta);
}

u32 iwl_mld_fw_sta_id_mask(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct ieee80211_vif *vif = iwl_mld_sta_from_mac80211(sta)->vif;
	struct ieee80211_link_sta *link_sta;
	unsigned int link_id;
	u32 result = 0;
	u8 fw_id;

	/* it's easy when the STA is not an MLD */
	if (!sta->valid_links) {
		fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, &sta->deflink);
		return BIT(fw_id);
	}

	/* but if it is an MLD, get the mask of all the FW STAs it has ... */
	for_each_sta_active_link(vif, sta, link_sta, link_id) {
		fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);
		result |= BIT(fw_id);
	}

	return result;
}
