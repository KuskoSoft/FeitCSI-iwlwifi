// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <linux/ieee80211.h>
#include <kunit/static_stub.h>

#include "sta.h"
#include "hcmd.h"
#include "iface.h"
#include "key.h"
#include "fw/api/sta.h"
#include "fw/api/mac.h"
#include "fw/api/rx.h"

int iwl_mld_fw_sta_id_from_link_sta(struct ieee80211_link_sta *link_sta)
{
	struct iwl_mld_link_sta *mld_link_sta;

	/* This is not meant to be called with a NULL pointer */
	if (WARN_ON(!link_sta))
		return -ENOENT;

	mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
	if (WARN_ON(!mld_link_sta))
		return -ENOENT;

	return mld_link_sta->fw_id;
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
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(link_sta);

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
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(link_sta->sta);
	struct iwl_mld_link_sta *mld_link_sta;
	int ret;
	u8 fw_id;

	lockdep_assert_wiphy(mld->wiphy);

	/* We will fail to add it to the FW anyway */
	if (iwl_mld_error_before_recovery(mld))
		return -ENODEV;

	/* We need to preserve the fw sta ids during a restart, since the fw
	 * will recover SN/PN for them
	 */
	if (mld->fw_status.in_hw_restart) {
		fw_id = iwl_mld_fw_sta_id_from_link_sta(link_sta);
		goto add_to_fw;
	}

	/* Allocate a fw id and map it to the link_sta */
	ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
	if (ret)
		return ret;

	if (link_sta == &link_sta->sta->deflink) {
		mld_link_sta = &mld_sta->deflink;
	} else {
		mld_link_sta = kzalloc(sizeof(*mld_link_sta), GFP_KERNEL);
		if (!mld_link_sta)
			return -ENOMEM;
	}

	mld_link_sta->fw_id = fw_id;
	mld_link_sta->mld = mld;
	rcu_assign_pointer(mld_sta->link[link_sta->link_id], mld_link_sta);

add_to_fw:
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
iwl_mld_remove_link_sta(struct iwl_mld *mld,
			struct ieee80211_link_sta *link_sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(link_sta->sta);
	struct iwl_mld_link_sta *mld_link_sta =
		iwl_mld_link_sta_from_mac80211(link_sta);

	if (WARN_ON(!mld_link_sta))
		return;

	iwl_mld_rm_sta_from_fw(mld, mld_link_sta->fw_id);

	/* This will not be done upon reconfig, so do it also when
	 * failed to remove from fw
	 */
	RCU_INIT_POINTER(mld->fw_id_to_link_sta[mld_link_sta->fw_id], NULL);
	RCU_INIT_POINTER(mld_sta->link[link_sta->link_id], NULL);
	if (mld_link_sta != &mld_sta->deflink)
		kfree_rcu(mld_link_sta, rcu_head);
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

static void iwl_mld_destroy_sta(struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	kfree(mld_sta->dup_data);
	kfree(mld_sta->mpdu_counters);
}

static int
iwl_mld_alloc_dup_data(struct iwl_mld *mld, struct iwl_mld_sta *mld_sta)
{
	struct iwl_mld_rxq_dup_data *dup_data;

	if (mld->fw_status.in_hw_restart)
		return 0;

	dup_data = kcalloc(mld->trans->num_rx_queues, sizeof(*dup_data),
			   GFP_KERNEL);
	if (!dup_data)
		return -ENOMEM;

	/* Initialize all the last_seq values to 0xffff which can never
	 * compare equal to the frame's seq_ctrl in the check in
	 * iwl_mld_is_dup() since the lower 4 bits are the fragment
	 * number and fragmented packets don't reach that function.
	 *
	 * This thus allows receiving a packet with seqno 0 and the
	 * retry bit set as the very first packet on a new TID.
	 */
	for (int q = 0; q < mld->trans->num_rx_queues; q++)
		memset(dup_data[q].last_seq, 0xff,
		       sizeof(dup_data[q].last_seq));
	mld_sta->dup_data = dup_data;

	return 0;
}

static void iwl_mld_alloc_mpdu_counters(struct iwl_mld *mld,
					struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_vif *vif = mld_sta->vif;

	if (mld->fw_status.in_hw_restart)
		return;

	/* MPDUs are counted only when EMLSR is possible */
	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION ||
	    sta->tdls || !ieee80211_vif_is_mld(vif))
		return;

	mld_sta->mpdu_counters = kcalloc(mld->trans->num_rx_queues,
					 sizeof(*mld_sta->mpdu_counters),
					 GFP_KERNEL);
	if (!mld_sta->mpdu_counters)
		return;

	for (int q = 0; q < mld->trans->num_rx_queues; q++)
		spin_lock_init(&mld_sta->mpdu_counters[q].lock);
}

static int
iwl_mld_init_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		 struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	mld_sta->vif = vif;
	mld_sta->sta_type = type;
	mld_sta->mld = mld;

	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++)
		iwl_mld_init_txq(iwl_mld_txq_from_mac80211(sta->txq[i]));

	iwl_mld_alloc_mpdu_counters(mld, sta);

	iwl_mld_toggle_tx_ant(mld, &mld_sta->data_tx_ant);

	return iwl_mld_alloc_dup_data(mld, mld_sta);
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	int link_id;
	int ret;

	ret = iwl_mld_init_sta(mld, sta, vif, type);
	if (ret)
		return ret;

	/* We could have add only the deflink link_sta, but it will not work
	 * in the restart case if the single link that is active during
	 * reconfig is not the deflink one.
	 */
	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		ret = iwl_mld_add_link_sta(mld, link_sta);
		if (ret)
			goto destroy_sta;
	}

	return 0;

destroy_sta:
	iwl_mld_destroy_sta(sta);

	return ret;
}

void iwl_mld_flush_sta_txqs(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	int link_id;

	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		u32 fw_sta_id = iwl_mld_fw_sta_id_from_link_sta(link_sta);

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
	struct ieee80211_vif *vif = mld_sta->vif;
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

	for_each_sta_active_link(vif, sta, link_sta, link_id) {
		/* Mac8011 will remove the groupwise keys after the sta is
		 * removed, but FW expects all the keys to be removed before
		 * the STA is, so remove them all here.
		 */
		if (vif->type == NL80211_IFTYPE_STATION)
			iwl_mld_remove_ap_keys(mld, vif, link_id);

		/* Remove the link_sta */
		iwl_mld_remove_link_sta(mld, link_sta);
	}

	iwl_mld_destroy_sta(sta);
}

u32 iwl_mld_fw_sta_id_mask(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct ieee80211_vif *vif = iwl_mld_sta_from_mac80211(sta)->vif;
	struct ieee80211_link_sta *link_sta;
	unsigned int link_id;
	u32 result = 0;

	KUNIT_STATIC_STUB_REDIRECT(iwl_mld_fw_sta_id_mask, mld, sta);

	for_each_sta_active_link(vif, sta, link_sta, link_id) {
		int fw_id = iwl_mld_fw_sta_id_from_link_sta(link_sta);

		if (!WARN_ON(fw_id < 0))
			result |= BIT(fw_id);
	}

	return result;
}
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_mld_fw_sta_id_mask);

static void iwl_mld_count_mpdu(struct ieee80211_link_sta *link_sta, int queue,
			       u32 count, bool tx)
{
	struct iwl_mld_per_q_mpdu_counter *queue_counter;
	struct iwl_mld_per_link_mpdu_counter *link_counter;
	struct iwl_mld_vif *mld_vif;
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_link *mld_link;

	if (WARN_ON(!link_sta))
		return;

	mld_sta = iwl_mld_sta_from_mac80211(link_sta->sta);
	if (!mld_sta->mpdu_counters)
		return;

	mld_vif = iwl_mld_vif_from_mac80211(mld_sta->vif);
	mld_link = iwl_mld_link_dereference_check(mld_vif, link_sta->link_id);

	if (WARN_ON_ONCE(!mld_link))
		return;

	queue_counter = &mld_sta->mpdu_counters[queue];
	link_counter = &queue_counter->per_link[mld_link->fw_id];

	spin_lock_bh(&queue_counter->lock);

	if (tx)
		link_counter->tx += count;
	else
		link_counter->rx += count;

	/* TODO (task=EMLSR)
	 * 1. Return early if esr_active is set.
	 * 2. Sum total_mpdus in the queue_counter.
	 * 3. Clear counters when the defined window time has passed.
	 * 4. Compare total_mpdus to the threshold to unblock EMLSR.
	 */

	spin_unlock_bh(&queue_counter->lock);
}

/* must be called under rcu_read_lock() */
void iwl_mld_count_mpdu_rx(struct ieee80211_link_sta *link_sta, int queue,
			   u32 count)
{
	iwl_mld_count_mpdu(link_sta, queue, count, false);
}

/* must be called under rcu_read_lock() */
void iwl_mld_count_mpdu_tx(struct ieee80211_link_sta *link_sta, u32 count)
{
	/* use queue 0 for all TX */
	iwl_mld_count_mpdu(link_sta, 0, count, true);
}

static int iwl_mld_allocate_internal_txq(struct iwl_mld *mld,
					 struct iwl_mld_int_sta *internal_sta,
					 u8 tid)
{
	u32 sta_mask = BIT(internal_sta->sta_id);
	int queue, size;

	size = max_t(u32, IWL_MGMT_QUEUE_SIZE,
		     mld->trans->cfg->min_txq_size);

	queue = iwl_trans_txq_alloc(mld->trans, 0, sta_mask, tid, size,
				    IWL_WATCHDOG_DISABLED);

	if (queue >= 0)
		IWL_DEBUG_TX_QUEUES(mld,
				    "Enabling TXQ #%d for sta mask 0x%x tid %d\n",
				    queue, sta_mask, tid);
	return queue;
}

static int iwl_mld_send_aux_sta_cmd(void)
{
	/* TODO: send aux cmd. (task=p2p) */
	return -EOPNOTSUPP;
}

static int
iwl_mld_add_internal_sta_to_fw(struct iwl_mld *mld,
			       const struct iwl_mld_int_sta *internal_sta,
			       u8 fw_link_id,
			       const u8 *addr)
{
	struct iwl_sta_cfg_cmd cmd = {};

	if (internal_sta->sta_type == STATION_TYPE_AUX)
		return iwl_mld_send_aux_sta_cmd();

	cmd.sta_id = cpu_to_le32((u8)internal_sta->sta_id);
	cmd.link_id = cpu_to_le32(fw_link_id);
	cmd.station_type = cpu_to_le32(internal_sta->sta_type);

	/* FW doesn't allow to add a IGTK/BIGTK if the sta isn't marked as MFP.
	 * On the other hand, FW will never check this flag during RX since
	 * an AP/GO doesn't receive protected broadcast management frames.
	 * So, we can set it unconditionally.
	 */
	if (internal_sta->sta_type == STATION_TYPE_BCAST_MGMT)
		cmd.mfp = cpu_to_le32(1);

	if (addr) {
		memcpy(cmd.peer_mld_address, addr, ETH_ALEN);
		memcpy(cmd.peer_link_address, addr, ETH_ALEN);
	}

	return iwl_mld_send_sta_cmd(mld, &cmd);
}

static int iwl_mld_add_internal_sta(struct iwl_mld *mld,
				    struct iwl_mld_int_sta *internal_sta,
				    enum iwl_fw_sta_type sta_type,
				    u8 fw_link_id, const u8 *addr, u8 tid)
{
	int ret, queue_id;

	ret = iwl_mld_allocate_link_sta_fw_id(mld,
					      &internal_sta->sta_id,
					      ERR_PTR(-EINVAL));
	if (ret)
		return ret;

	internal_sta->sta_type = sta_type;

	ret = iwl_mld_add_internal_sta_to_fw(mld, internal_sta, fw_link_id,
					     addr);
	if (ret)
		goto err;

	queue_id = iwl_mld_allocate_internal_txq(mld, internal_sta, tid);
	if (queue_id < 0) {
		iwl_mld_rm_sta_from_fw(mld, internal_sta->sta_id);
		ret = queue_id;
		goto err;
	}

	internal_sta->queue_id = queue_id;

	return 0;
err:
	iwl_mld_free_internal_sta(mld, internal_sta);
	return ret;
}

int iwl_mld_add_bcast_sta(struct iwl_mld *mld,
			  struct ieee80211_vif *vif,
			  struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	const u8 bcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	const u8 *addr;

	if (WARN_ON(!mld_link))
		return -EINVAL;

	if (WARN_ON(vif->type != NL80211_IFTYPE_AP &&
		    vif->type != NL80211_IFTYPE_ADHOC))
		return -EINVAL;

	addr = vif->type == NL80211_IFTYPE_ADHOC ?
		link->bssid : bcast_addr;

	return iwl_mld_add_internal_sta(mld, &mld_link->bcast_sta,
					STATION_TYPE_BCAST_MGMT,
					mld_link->fw_id, addr,
					IWL_MGMT_TID);
}

int iwl_mld_add_mcast_sta(struct iwl_mld *mld,
			  struct ieee80211_vif *vif,
			  struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	const u8 mcast_addr[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00};

	if (WARN_ON(!mld_link))
		return -EINVAL;

	if (WARN_ON(vif->type != NL80211_IFTYPE_AP &&
		    vif->type != NL80211_IFTYPE_ADHOC))
		return -EINVAL;

	return iwl_mld_add_internal_sta(mld, &mld_link->mcast_sta,
					STATION_TYPE_MCAST,
					mld_link->fw_id, mcast_addr, 0);
}

static void iwl_mld_remove_internal_sta(struct iwl_mld *mld,
					struct iwl_mld_int_sta *internal_sta,
					bool flush, u8 tid)
{
	if (WARN_ON_ONCE(internal_sta->sta_id == IWL_INVALID_STA ||
			 internal_sta->queue_id == IWL_MLD_INVALID_QUEUE))
		return;

	if (flush)
		iwl_mld_flush_link_sta_txqs(mld, internal_sta->sta_id);

	iwl_mld_free_txq(mld, BIT(internal_sta->sta_id),
			 tid, internal_sta->queue_id);

	iwl_mld_rm_sta_from_fw(mld, internal_sta->sta_id);

	iwl_mld_free_internal_sta(mld, internal_sta);
}

void iwl_mld_remove_bcast_sta(struct iwl_mld *mld,
			      struct ieee80211_vif *vif,
			      struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);

	if (WARN_ON(!mld_link))
		return;

	if (WARN_ON(vif->type != NL80211_IFTYPE_AP &&
		    vif->type != NL80211_IFTYPE_ADHOC))
		return;

	iwl_mld_remove_internal_sta(mld, &mld_link->bcast_sta, true,
				    IWL_MGMT_TID);
}

void iwl_mld_remove_mcast_sta(struct iwl_mld *mld,
			      struct ieee80211_vif *vif,
			      struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);

	if (WARN_ON(!mld_link))
		return;

	if (WARN_ON(vif->type != NL80211_IFTYPE_AP &&
		    vif->type != NL80211_IFTYPE_ADHOC))
		return;

	iwl_mld_remove_internal_sta(mld, &mld_link->mcast_sta, true, 0);
}
