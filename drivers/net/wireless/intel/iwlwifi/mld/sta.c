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
#include "fw/api/rx.h"

int iwl_mld_fw_sta_id_from_link_sta(struct iwl_mld *mld,
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

	/* We will fail to add it to the FW anyway */
	if (iwl_mld_error_before_recovery(mld))
		return -ENODEV;

	/* We need to preserve the fw sta ids during a restart, since the fw
	 * will recover SN/PN for them
	 */
	if (!mld->fw_status.in_hw_restart) {
		/* Allocate a fw id and map it to the link_sta */
		ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
		if (ret)
			return ret;
	} else {
		fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);
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
iwl_mld_remove_link_sta(struct iwl_mld *mld,
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

static void iwl_mld_destroy_sta(struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	kfree(mld_sta->dup_data);
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

static int
iwl_mld_init_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		 struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	mld_sta->vif = vif;
	mld_sta->sta_type = type;

	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++)
		iwl_mld_init_txq(iwl_mld_txq_from_mac80211(sta->txq[i]));

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
		iwl_mld_remove_link_sta(mld, link_sta);

	iwl_mld_destroy_sta(sta);
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

static int
iwl_mld_sta_stop_ba_in_fw(struct iwl_mld *mld, struct ieee80211_sta *sta,
			  int tid)
{
	struct iwl_rx_baid_cfg_cmd cmd = {
		.action = cpu_to_le32(IWL_RX_BAID_ACTION_REMOVE),
		.remove.sta_id_mask =
			cpu_to_le32(iwl_mld_fw_sta_id_mask(mld, sta)),
		.remove.tid = cpu_to_le32(tid),

	};
	int ret;

	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(DATA_PATH_GROUP,
					   RX_BAID_ALLOCATION_CONFIG_CMD),
				   &cmd);
	if (ret)
		return ret;

	IWL_DEBUG_HT(mld, "RX BA Session stopped in fw\n");

	return ret;
}

static int
iwl_mld_sta_start_ba_in_fw(struct iwl_mld *mld, struct ieee80211_sta *sta,
			   int tid, u16 ssn, u16 buf_size)
{
	struct iwl_rx_baid_cfg_cmd cmd = {
		.action = cpu_to_le32(IWL_RX_BAID_ACTION_ADD),
		.alloc.sta_id_mask =
			cpu_to_le32(iwl_mld_fw_sta_id_mask(mld, sta)),
		.alloc.tid = tid,
		.alloc.ssn = cpu_to_le16(ssn),
		.alloc.win_size = cpu_to_le16(buf_size),
	};
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(DATA_PATH_GROUP, RX_BAID_ALLOCATION_CONFIG_CMD),
		.flags = CMD_WANT_SKB,
		.len[0] = sizeof(cmd),
		.data[0] = &cmd,
	};
	struct iwl_rx_baid_cfg_resp *resp;
	struct iwl_rx_packet *pkt;
	u32 resp_len;
	int ret, baid;

	BUILD_BUG_ON(sizeof(*resp) != sizeof(baid));

	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (ret)
		return ret;

	pkt = hcmd.resp_pkt;

	resp_len = iwl_rx_packet_payload_len(pkt);
	if (IWL_FW_CHECK(mld, resp_len != sizeof(*resp),
			 "BAID_ALLOC_CMD: unexpected response length %d\n",
			 resp_len)) {
		ret = -EIO;
		goto out;
	}

	IWL_DEBUG_HT(mld, "RX BA Session started in fw\n");

	resp = (void *)pkt->data;
	baid = le32_to_cpu(resp->baid);

	if (IWL_FW_CHECK(mld, baid < 0 || baid >= ARRAY_SIZE(mld->fw_id_to_ba),
			 "BAID_ALLOC_CMD: invalid BAID response %d\n", baid)) {
		ret = -EINVAL;
		goto out;
	}

	ret = baid;
out:
	iwl_free_resp(&hcmd);
	return ret;
}

static void iwl_mld_init_reorder_buffer(struct iwl_mld *mld,
					struct iwl_mld_baid_data *data,
					u16 ssn)
{
	for (int i = 0; i < mld->trans->num_rx_queues; i++) {
		struct iwl_mld_reorder_buffer *reorder_buf =
			&data->reorder_buf[i];
		struct iwl_mld_reorder_buf_entry *entries =
			&data->entries[i * data->entries_per_queue];

		reorder_buf->head_sn = ssn;
		reorder_buf->queue = i;

		for (int j = 0; j < data->buf_size; j++)
			__skb_queue_head_init(&entries[j].frames);
	}
}

int iwl_mld_sta_ampdu_rx_start(struct iwl_mld *mld, struct ieee80211_sta *sta,
			       int tid, u16 ssn, u16 buf_size, u16 timeout)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct iwl_mld_baid_data *baid_data = NULL;
	u32 reorder_buf_size = buf_size * sizeof(baid_data->entries[0]);
	int ret, baid;

	lockdep_assert_wiphy(mld->wiphy);

	if (mld->num_rx_ba_sessions >= IWL_MAX_BAID) {
		IWL_DEBUG_HT(mld,
			     "Max num of RX BA sessions reached; blocking new session\n");
		return -ENOSPC;
	}

	/* sparse doesn't like the __align() so don't check */
#ifndef __CHECKER__
	/* The division below will be OK if either the cache line size
	 * can be divided by the entry size (ALIGN will round up) or if
	 * the entry size can be divided by the cache line size, in which
	 * case the ALIGN() will do nothing.
	 */
	BUILD_BUG_ON(SMP_CACHE_BYTES % sizeof(baid_data->entries[0]) &&
		     sizeof(baid_data->entries[0]) % SMP_CACHE_BYTES);
#endif

	/* Upward align the reorder buffer size to fill an entire cache
	 * line for each queue, to avoid sharing cache lines between
	 * different queues.
	 */
	reorder_buf_size = ALIGN(reorder_buf_size, SMP_CACHE_BYTES);

	/* Allocate here so if allocation fails we can bail out early
	 * before starting the BA session in the firmware
	 */
	baid_data = kzalloc(sizeof(*baid_data) +
			    mld->trans->num_rx_queues * reorder_buf_size,
			    GFP_KERNEL);
	if (!baid_data)
		return -ENOMEM;

	/* This division is why we need the above BUILD_BUG_ON(),
	 * if that doesn't hold then this will not be right.
	 */
	baid_data->entries_per_queue =
		reorder_buf_size / sizeof(baid_data->entries[0]);

	baid = iwl_mld_sta_start_ba_in_fw(mld, sta, tid, ssn, buf_size);
	if (baid < 0) {
		ret = baid;
		goto out_free;
	}

	mld->num_rx_ba_sessions++;
	mld_sta->tid_to_baid[tid] = baid;

	/* TODO: session timer setup (task=DP) */

	baid_data->baid = baid;
	baid_data->mld = mld;
	baid_data->tid = tid;
	baid_data->buf_size = buf_size;
	baid_data->sta_mask = iwl_mld_fw_sta_id_mask(mld, sta);

	iwl_mld_init_reorder_buffer(mld, baid_data, ssn);

	IWL_DEBUG_HT(mld, "STA mask=0x%x (tid=%d) is assigned to BAID %d\n",
		     baid_data->sta_mask, tid, baid);

	/* protect the BA data with RCU to cover a case where our
	 * internal RX sync mechanism will timeout (not that it's
	 * supposed to happen) and we will free the session data while
	 * RX is being processed in parallel
	 */
	WARN_ON(rcu_access_pointer(mld->fw_id_to_ba[baid]));
	rcu_assign_pointer(mld->fw_id_to_ba[baid], baid_data);

	return 0;

out_free:
	kfree(baid_data);
	return ret;
}

static void iwl_mld_free_reorder_buffer(struct iwl_mld *mld,
					struct iwl_mld_baid_data *data)
{
	/* TODO: synchronize all rx queues so we can safely delete (task=DP) */
	for (int i = 0; i < mld->trans->num_rx_queues; i++) {
		struct iwl_mld_reorder_buffer *reorder_buf =
			&data->reorder_buf[i];
		struct iwl_mld_reorder_buf_entry *entries =
			&data->entries[i * data->entries_per_queue];

		if (likely(!reorder_buf->num_stored))
			continue;

		/* This shouldn't happen in regular DELBA since the RX queues
		 * sync internal DELBA notification should trigger a release
		 * of all frames in the reorder buffer.
		 */
		WARN_ON(1);

		for (int j = 0; j < data->buf_size; j++)
			__skb_queue_purge(&entries[j].frames);
	}
}

int iwl_mld_sta_ampdu_rx_stop(struct iwl_mld *mld, struct ieee80211_sta *sta,
			      int tid)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	int baid = mld_sta->tid_to_baid[tid];
	struct iwl_mld_baid_data *baid_data;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	/* during firmware restart, do not send the command as the firmware no
	 * longer recognizes the session. instead, only clear the driver BA
	 * session data.
	 */
	if (!mld->fw_status.in_hw_restart) {
		ret = iwl_mld_sta_stop_ba_in_fw(mld, sta, tid);
		if (ret)
			return ret;
	}

	if (!WARN_ON(mld->num_rx_ba_sessions == 0))
		mld->num_rx_ba_sessions--;

	baid_data = rcu_access_pointer(mld->fw_id_to_ba[baid]);
	if (WARN_ON(!baid_data))
		return -EINVAL;

	/* TODO: shutdown session timer (task=DP) */

	iwl_mld_free_reorder_buffer(mld, baid_data);

	RCU_INIT_POINTER(mld->fw_id_to_ba[baid], NULL);
	kfree_rcu(baid_data, rcu_head);

	IWL_DEBUG_HT(mld, "BAID %d is free\n", baid);

	return 0;
}
