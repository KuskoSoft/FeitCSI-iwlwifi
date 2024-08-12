// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"
#include "sta.h"
#include "fw/dbg.h"
#include "fw/api/rx.h"
#include "fw/api/rs.h"

/* stores relevant PHY data fields extracted from iwl_rx_mpdu_desc */
struct iwl_mld_rx_phy_data {
	enum iwl_rx_phy_info_type info_type;
	__le32 data1;
	u32 rate_n_flags;
	u32 gp2_on_air_rise;
	u16 phy_info;
	u8 energy_a, energy_b;
	u8 channel;
	/* TODO: add more fields */
};

static void iwl_mld_fill_phy_data(struct iwl_rx_mpdu_desc *desc,
				  struct iwl_mld_rx_phy_data *phy_data)
{
	phy_data->phy_info = le16_to_cpu(desc->phy_info);
	phy_data->rate_n_flags = le32_to_cpu(desc->v3.rate_n_flags);
	phy_data->gp2_on_air_rise = le32_to_cpu(desc->v3.gp2_on_air_rise);
	phy_data->channel = desc->v3.channel;
	phy_data->energy_a = desc->v3.energy_a;
	phy_data->energy_b = desc->v3.energy_b;
	phy_data->data1 = desc->v3.phy_data1;
}

/* iwl_mld_pass_packet_to_mac80211 - passes the packet for mac80211 */
static void iwl_mld_pass_packet_to_mac80211(struct iwl_mld *mld,
					    struct napi_struct *napi,
					    struct sk_buff *skb, int queue,
					    struct ieee80211_sta *sta)
{
	/* TODO: check PN (task=DP) */
	ieee80211_rx_napi(mld->hw, sta, skb, napi);
}

static void iwl_mld_fill_signal(struct iwl_mld *mld,
				struct ieee80211_rx_status *rx_status,
				struct iwl_mld_rx_phy_data *phy_data)
{
	u32 rate_n_flags = phy_data->rate_n_flags;
	int energy_a = phy_data->energy_a;
	int energy_b = phy_data->energy_b;
	int max_energy;

	energy_a = energy_a ? -energy_a : S8_MIN;
	energy_b = energy_b ? -energy_b : S8_MIN;
	max_energy = max(energy_a, energy_b);

	IWL_DEBUG_STATS(mld, "energy in A %d B %d, and max %d\n",
			energy_a, energy_b, max_energy);

	rx_status->signal = max_energy;
	rx_status->chains =
	    (rate_n_flags & RATE_MCS_ANT_AB_MSK) >> RATE_MCS_ANT_POS;
	rx_status->chain_signal[0] = energy_a;
	rx_status->chain_signal[1] = energy_b;
}

static int
iwl_mld_legacy_hw_idx_to_mac80211_idx(u32 rate_n_flags,
				      enum nl80211_band band)
{
	int format = rate_n_flags & RATE_MCS_MOD_TYPE_MSK;
	int rate = rate_n_flags & RATE_LEGACY_RATE_MSK;
	bool is_lb = band == NL80211_BAND_2GHZ;

	if (format == RATE_MCS_LEGACY_OFDM_MSK)
		return is_lb ? rate + IWL_FIRST_OFDM_RATE : rate;

	/* CCK is not allowed in 5 GHz */
	return is_lb ? rate : -1;
}

static void iwl_mld_rx_fill_status(struct iwl_mld *mld, struct sk_buff *skb,
				   struct iwl_mld_rx_phy_data *phy_data,
				   struct iwl_rx_mpdu_desc *mpdu_desc,
				   struct ieee80211_hdr *hdr,
				   int queue)
{
	struct ieee80211_rx_status *rx_status = IEEE80211_SKB_RXCB(skb);
	u32 format = phy_data->rate_n_flags & RATE_MCS_MOD_TYPE_MSK;
	u32 rate_n_flags = phy_data->rate_n_flags;
	u8 stbc = u32_get_bits(rate_n_flags, RATE_MCS_STBC_MSK);
	bool is_sgi = rate_n_flags & RATE_MCS_SGI_MSK;
	u8 band;

	/* Keep packets with CRC errors (and with overrun) for monitor mode
	 * (otherwise the firmware discards them) but mark them as bad.
	 */
	if (!(mpdu_desc->status & cpu_to_le32(IWL_RX_MPDU_STATUS_CRC_OK)) ||
	    !(mpdu_desc->status & cpu_to_le32(IWL_RX_MPDU_STATUS_OVERRUN_OK))) {
		IWL_DEBUG_RX(mld, "Bad CRC or FIFO: 0x%08X.\n",
			     le32_to_cpu(mpdu_desc->status));
		rx_status->flag |= RX_FLAG_FAILED_FCS_CRC;
	}

	phy_data->info_type = IWL_RX_PHY_INFO_TYPE_NONE;

	if (likely(!(phy_data->phy_info & IWL_RX_MPDU_PHY_TSF_OVERLOAD))) {
		rx_status->mactime =
			le64_to_cpu(mpdu_desc->v3.tsf_on_air_rise);

		/* TSF as indicated by the firmware is at INA time */
		rx_status->flag |= RX_FLAG_MACTIME_PLCP_START;
	} else {
		phy_data->info_type =
			le32_get_bits(phy_data->data1,
				      IWL_RX_PHY_DATA1_INFO_TYPE_MASK);
	}

	/* management stuff on default queue */
	if (!queue &&
	    unlikely(ieee80211_is_beacon(hdr->frame_control) ||
		     ieee80211_is_probe_resp(hdr->frame_control))) {
		rx_status->boottime_ns = ktime_get_boottime_ns();

		if (mld->scan.pass_all_sched_res == SCHED_SCAN_PASS_ALL_STATE_ENABLED)
			mld->scan.pass_all_sched_res = SCHED_SCAN_PASS_ALL_STATE_FOUND;
	}

	/* set the preamble flag if appropriate */
	if (format == RATE_MCS_CCK_MSK &&
	    phy_data->phy_info & IWL_RX_MPDU_PHY_SHORT_PREAMBLE)
		rx_status->enc_flags |= RX_ENC_FLAG_SHORTPRE;

	band = BAND_IN_RX_STATUS(mpdu_desc->mac_phy_idx);
	rx_status->band = iwl_mld_phy_band_to_nl80211(band);
	rx_status->freq = ieee80211_channel_to_frequency(phy_data->channel,
							 rx_status->band);
	iwl_mld_fill_signal(mld, rx_status, phy_data);

	switch (rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) {
	case RATE_MCS_CHAN_WIDTH_20:
		break;
	case RATE_MCS_CHAN_WIDTH_40:
		rx_status->bw = RATE_INFO_BW_40;
		break;
	case RATE_MCS_CHAN_WIDTH_80:
		rx_status->bw = RATE_INFO_BW_80;
		break;
	case RATE_MCS_CHAN_WIDTH_160:
		rx_status->bw = RATE_INFO_BW_160;
		break;
	case RATE_MCS_CHAN_WIDTH_320:
		rx_status->bw = RATE_INFO_BW_320;
		break;
	}

	/* TODO: rx_he before L-SIG (task=sniffer)*/
	/* TODO: decode_lsig (task=sniffer)*/
	/* TODO: rx_eht (task=sniffer)*/
	/* TODO: RX_FLAG_MACTIME_IS_RTAP_TS64 (task=ptp)*/

	rx_status->device_timestamp = phy_data->gp2_on_air_rise;

	if (format != RATE_MCS_CCK_MSK && is_sgi)
		rx_status->enc_flags |= RX_ENC_FLAG_SHORT_GI;

	if (rate_n_flags & RATE_MCS_LDPC_MSK)
		rx_status->enc_flags |= RX_ENC_FLAG_LDPC;

	switch (format) {
	case RATE_MCS_HT_MSK:
		rx_status->encoding = RX_ENC_HT;
		rx_status->rate_idx = RATE_HT_MCS_INDEX(rate_n_flags);
		rx_status->enc_flags |= stbc << RX_ENC_FLAG_STBC_SHIFT;
		break;
	case RATE_MCS_VHT_MSK:
	case RATE_MCS_HE_MSK:
	case RATE_MCS_EHT_MSK:
		if (format == RATE_MCS_VHT_MSK) {
			rx_status->encoding = RX_ENC_VHT;
		} else if (format == RATE_MCS_HE_MSK) {
			rx_status->encoding = RX_ENC_HE;
			rx_status->he_dcm =
				!!(rate_n_flags & RATE_HE_DUAL_CARRIER_MODE_MSK);
		} else if (format == RATE_MCS_EHT_MSK) {
			rx_status->encoding = RX_ENC_EHT;
		}

		rx_status->nss = u32_get_bits(rate_n_flags, RATE_MCS_NSS_MSK) + 1;
		rx_status->rate_idx = rate_n_flags & RATE_MCS_CODE_MSK;
		rx_status->enc_flags |= stbc << RX_ENC_FLAG_STBC_SHIFT;
		break;
	default: {
		int rate =
		    iwl_mld_legacy_hw_idx_to_mac80211_idx(rate_n_flags,
							  rx_status->band);

		/* valid rate */
		if (rate >= 0 && rate <= 0xFF) {
			rx_status->rate_idx = rate;
			break;
		}

		/* invalid rate */
		rx_status->rate_idx = 0;

		if (net_ratelimit())
			IWL_ERR(mld, "invalid rate_n_flags=0x%x, band=%d\n",
				rate_n_flags, rx_status->band);
		break;
		}
	}
}

/* iwl_mld_create_skb adds the rxb to a new skb */
static int iwl_mld_create_skb(struct iwl_mld *mld, struct sk_buff *skb,
			      struct ieee80211_hdr *hdr, u16 len, u8 crypt_len,
			      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_rx_mpdu_desc *desc = (void *)pkt->data;
	unsigned int headlen, fraglen, pad_len = 0;
	unsigned int hdrlen = ieee80211_hdrlen(hdr->frame_control);
	u8 mic_crc_len = u8_get_bits(desc->mac_flags1,
				     IWL_RX_MPDU_MFLG1_MIC_CRC_LEN_MASK) << 1;

	if (desc->mac_flags2 & IWL_RX_MPDU_MFLG2_PAD) {
		len -= 2;
		pad_len = 2;
	}

	/* For non monitor interface strip the bytes the RADA might not have
	 * removed (it might be disabled, e.g. for mgmt frames). As a monitor
	 * interface cannot exist with other interfaces, this removal is safe
	 * and sufficient, in monitor mode there's no decryption being done.
	 */
	if (len > mic_crc_len && !ieee80211_hw_check(mld->hw, RX_INCLUDES_FCS))
		len -= mic_crc_len;

	/* If frame is small enough to fit in skb->head, pull it completely.
	 * If not, only pull ieee80211_hdr (including crypto if present, and
	 * an additional 8 bytes for SNAP/ethertype, see below) so that
	 * splice() or TCP coalesce are more efficient.
	 *
	 * Since, in addition, ieee80211_data_to_8023() always pull in at
	 * least 8 bytes (possibly more for mesh) we can do the same here
	 * to save the cost of doing it later. That still doesn't pull in
	 * the actual IP header since the typical case has a SNAP header.
	 * If the latter changes (there are efforts in the standards group
	 * to do so) we should revisit this and ieee80211_data_to_8023().
	 */
	headlen = (len <= skb_tailroom(skb)) ? len : hdrlen + crypt_len + 8;

	/* TODO: CONFIG_HSR */

	/* The firmware may align the packet to DWORD.
	 * The padding is inserted after the IV.
	 * After copying the header + IV skip the padding if
	 * present before copying packet data.
	 */
	hdrlen += crypt_len;

	if (unlikely(headlen < hdrlen))
		return -EINVAL;

	/* Since data doesn't move data while putting data on skb and that is
	 * the only way we use, data + len is the next place that hdr would
	 * be put
	 */
	skb_set_mac_header(skb, skb->len);
	skb_put_data(skb, hdr, hdrlen);
	skb_put_data(skb, (u8 *)hdr + hdrlen + pad_len, headlen - hdrlen);

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		struct {
			u8 hdr[6];
			__be16 type;
		} __packed *shdr = (void *)((u8 *)hdr + hdrlen + pad_len);

		if (unlikely(headlen - hdrlen < sizeof(*shdr) ||
			     !ether_addr_equal(shdr->hdr, rfc1042_header) ||
			     (shdr->type != htons(ETH_P_IP) &&
			      shdr->type != htons(ETH_P_ARP) &&
			      shdr->type != htons(ETH_P_IPV6) &&
			      shdr->type != htons(ETH_P_8021Q) &&
			      shdr->type != htons(ETH_P_PAE) &&
			      shdr->type != htons(ETH_P_TDLS))))
			skb->ip_summed = CHECKSUM_NONE;
	}

	fraglen = len - headlen;

	if (fraglen) {
		int offset = (u8 *)hdr + headlen + pad_len -
			     (u8 *)rxb_addr(rxb) + rxb_offset(rxb);

		skb_add_rx_frag(skb, 0, rxb_steal_page(rxb), offset,
				fraglen, rxb->truesize);
	}

	return 0;
}

/* returns true if a packet is a duplicate or invalid tid and
 * should be dropped. Updates AMSDU PN tracking info
 */
static bool
iwl_mld_is_dup(struct iwl_mld *mld, struct ieee80211_sta *sta,
	       struct ieee80211_hdr *hdr,
	       const struct iwl_rx_mpdu_desc *mpdu_desc,
	       struct ieee80211_rx_status *rx_status, int queue)
{
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_rxq_dup_data *dup_data;
	u8 tid, sub_frame_idx;

	if (WARN_ON(!sta))
		return false;

	mld_sta = iwl_mld_sta_from_mac80211(sta);

	if (WARN_ON_ONCE(!mld_sta->dup_data))
		return false;

	dup_data = &mld_sta->dup_data[queue];

	/* Drop duplicate 802.11 retransmissions
	 * (IEEE 802.11-2020: 10.3.2.14 "Duplicate detection and recovery")
	 */
	if (ieee80211_is_ctl(hdr->frame_control) ||
	    ieee80211_is_any_nullfunc(hdr->frame_control) ||
	    is_multicast_ether_addr(hdr->addr1))
		return false;

	if (ieee80211_is_data_qos(hdr->frame_control)) {
		/* frame has qos control */
		tid = ieee80211_get_tid(hdr);
		if (tid >= IWL_MAX_TID_COUNT)
			return true;
	} else {
		tid = IWL_MAX_TID_COUNT;
	}

	/* If this wasn't a part of an A-MSDU the sub-frame index will be 0 */
	sub_frame_idx = mpdu_desc->amsdu_info &
		IWL_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK;

	if (IWL_FW_CHECK(mld,
			 sub_frame_idx > 0 &&
			 !(mpdu_desc->mac_flags2 & IWL_RX_MPDU_MFLG2_AMSDU),
			 "got sub_frame_idx=%d but A-MSDU flag is not set\n",
			 sub_frame_idx))
		return true;

	if (unlikely(ieee80211_has_retry(hdr->frame_control) &&
		     dup_data->last_seq[tid] == hdr->seq_ctrl &&
		     dup_data->last_sub_frame_idx[tid] >= sub_frame_idx))
		return true;

	/* Allow same PN as the first subframe for following sub frames */
	if (dup_data->last_seq[tid] == hdr->seq_ctrl &&
	    sub_frame_idx > dup_data->last_sub_frame_idx[tid])
		rx_status->flag |= RX_FLAG_ALLOW_SAME_PN;

	dup_data->last_seq[tid] = hdr->seq_ctrl;
	dup_data->last_sub_frame_idx[tid] = sub_frame_idx;

	rx_status->flag |= RX_FLAG_DUP_VALIDATED;

	return false;
}

/* Processes received packets for a station.
 * Sets *drop to true if the packet should be dropped.
 * Returns the station if found, or NULL otherwise.
 */
static struct ieee80211_sta *
iwl_mld_rx_with_sta(struct iwl_mld *mld, struct ieee80211_hdr *hdr,
		    struct sk_buff *skb,
		    const struct iwl_rx_mpdu_desc *mpdu_desc,
		    const struct iwl_rx_packet *pkt, int queue, bool *drop)
{
	struct ieee80211_sta *sta = NULL;
	struct ieee80211_link_sta *link_sta = NULL;
	struct ieee80211_rx_status *rx_status;

	if (mpdu_desc->status & cpu_to_le32(IWL_RX_MPDU_STATUS_SRC_STA_FOUND)) {
		u8 sta_id = le32_get_bits(mpdu_desc->status,
					  IWL_RX_MPDU_STATUS_STA_ID);

		if (IWL_FW_CHECK(mld,
				 sta_id >= mld->fw->ucode_capa.num_stations,
				 "rx_mpdu: invalid sta_id %d\n", sta_id))
			return NULL;

		link_sta = rcu_dereference(mld->fw_id_to_link_sta[sta_id]);
		if (link_sta)
			sta = link_sta->sta;
	} else if (!is_multicast_ether_addr(hdr->addr2)) {
		/* Passing NULL is fine since we prevent two stations with the
		 * same address from being added.
		 */
		sta = ieee80211_find_sta_by_ifaddr(mld->hw, hdr->addr2, NULL);
	}

	/* we may not have any station yet */
	if (!sta)
		return NULL;

	rx_status = IEEE80211_SKB_RXCB(skb);

	if (link_sta && sta->valid_links) {
		rx_status->link_valid = true;
		rx_status->link_id = link_sta->link_id;
	}

	/* fill checksum */
	if (ieee80211_is_data(hdr->frame_control) &&
	    pkt->len_n_flags & cpu_to_le32(FH_RSCSR_RPA_EN)) {
		u16 hwsum = be16_to_cpu(mpdu_desc->v3.raw_xsum);

		skb->ip_summed = CHECKSUM_COMPLETE;
		skb->csum = csum_unfold(~(__force __sum16)hwsum);
	}

	if (iwl_mld_is_dup(mld, sta, hdr, mpdu_desc, rx_status, queue)) {
		IWL_DEBUG_DROP(mld, "Dropping duplicate packet 0x%x\n",
			       le16_to_cpu(hdr->seq_ctrl));
		*drop = true;
		return NULL;
	}

	return sta;
}

static void
iwl_mld_reorder_release_frames(struct iwl_mld *mld, struct ieee80211_sta *sta,
			       struct napi_struct *napi,
			       struct iwl_mld_baid_data *baid_data,
			       struct iwl_mld_reorder_buffer *reorder_buf,
			       u16 nssn)
{
	struct iwl_mld_reorder_buf_entry *entries =
		&baid_data->entries[reorder_buf->queue *
				    baid_data->entries_per_queue];
	u16 ssn = reorder_buf->head_sn;

	while (ieee80211_sn_less(ssn, nssn)) {
		int index = ssn % baid_data->buf_size;
		struct sk_buff_head *skb_list = &entries[index].frames;
		struct sk_buff *skb;

		ssn = ieee80211_sn_inc(ssn);

		/* Empty the list. Will have more than one frame for A-MSDU.
		 * Empty list is valid as well since nssn indicates frames were
		 * received.
		 */
		while ((skb = __skb_dequeue(skb_list))) {
			iwl_mld_pass_packet_to_mac80211(mld, napi, skb,
							reorder_buf->queue,
							sta);
			reorder_buf->num_stored--;
		}
	}
	reorder_buf->head_sn = nssn;
}

/* Returns true if the MPDU was buffered\dropped, false if it should be passed
 * to upper layer.
 */
static bool iwl_mld_reorder(struct iwl_mld *mld, struct napi_struct *napi,
			    int queue, struct ieee80211_sta *sta,
			    struct sk_buff *skb, struct iwl_rx_mpdu_desc *desc)
{
	struct ieee80211_hdr *hdr = (void *)skb_mac_header(skb);
	struct iwl_mld_baid_data *baid_data;
	struct iwl_mld_reorder_buffer *buffer;
	struct iwl_mld_reorder_buf_entry *entries;
	u32 reorder = le32_to_cpu(desc->reorder_data);
	bool amsdu, last_subframe, is_old_sn, is_dup;
	u8 tid = ieee80211_get_tid(hdr);
	u8 baid;
	u16 nssn, sn;
	u32 sta_mask;
	int index;

	baid = u32_get_bits(reorder, IWL_RX_MPDU_REORDER_BAID_MASK);

	/* This also covers the case of receiving a Block Ack Request
	 * outside a BA session; we'll pass it to mac80211 and that
	 * then sends a delBA action frame.
	 * This also covers pure monitor mode, in which case we won't
	 * have any BA sessions.
	 */
	if (baid == IWL_RX_REORDER_DATA_INVALID_BAID)
		return false;

	/* no sta yet */
	if (WARN_ONCE(!sta,
		      "Got valid BAID without a valid station assigned\n"))
		return false;

	/* not a data packet */
	if (!ieee80211_is_data_qos(hdr->frame_control) ||
	    is_multicast_ether_addr(hdr->addr1))
		return false;

	if (unlikely(!ieee80211_is_data_present(hdr->frame_control)))
		return false;

	baid_data = rcu_dereference(mld->fw_id_to_ba[baid]);
	if (IWL_FW_CHECK(mld, !baid_data,
			 "Got valid BAID but no baid allocated (BAID=%d reorder=0x%x)\n",
			 baid, reorder))
		return false;

	sta_mask = iwl_mld_fw_sta_id_mask(mld, sta);

	/* verify the BAID is correctly mapped to the sta and tid */
	if (IWL_FW_CHECK(mld,
			 tid != baid_data->tid ||
			 !(sta_mask & baid_data->sta_mask),
			 "BAID 0x%x is mapped to sta_mask:0x%x tid:%d, but was received for sta_mask:0x%x tid:%d\n",
			 baid, baid_data->sta_mask, baid_data->tid,
			 sta_mask, tid))
		return false;

	buffer = &baid_data->reorder_buf[queue];
	entries = &baid_data->entries[queue * baid_data->entries_per_queue];

	is_old_sn = !!(reorder & IWL_RX_MPDU_REORDER_BA_OLD_SN);

	if (!buffer->valid && is_old_sn)
		return false;

	buffer->valid = true;

	is_dup = !!(desc->status & cpu_to_le32(IWL_RX_MPDU_STATUS_DUPLICATE));

	/* drop any duplicated or outdated packets */
	if (is_dup || is_old_sn) {
		kfree_skb(skb);
		return true;
	}

	sn = u32_get_bits(reorder, IWL_RX_MPDU_REORDER_SN_MASK);
	nssn = u32_get_bits(reorder, IWL_RX_MPDU_REORDER_NSSN_MASK);
	amsdu = desc->mac_flags2 & IWL_RX_MPDU_MFLG2_AMSDU;
	last_subframe = desc->amsdu_info & IWL_RX_MPDU_AMSDU_LAST_SUBFRAME;

	/* release immediately if allowed by nssn and no stored frames */
	if (!buffer->num_stored && ieee80211_sn_less(sn, nssn)) {
		if (!amsdu || last_subframe)
			buffer->head_sn = nssn;
		return false;
	}

	/* release immediately if there are no stored frames, and the sn is
	 * equal to the head.
	 * This can happen due to reorder timer, where NSSN is behind head_sn.
	 * When we released everything, and we got the next frame in the
	 * sequence, according to the NSSN we can't release immediately,
	 * while technically there is no hole and we can move forward.
	 */
	if (!buffer->num_stored && sn == buffer->head_sn) {
		if (!amsdu || last_subframe)
			buffer->head_sn = ieee80211_sn_inc(buffer->head_sn);

		return false;
	}

	/* put in reorder buffer */
	index = sn % baid_data->buf_size;
	__skb_queue_tail(&entries[index].frames, skb);
	buffer->num_stored++;

	/* We cannot trust NSSN for AMSDU sub-frames that are not the last. The
	 * reason is that NSSN advances on the first sub-frame, and may cause
	 * the reorder buffer to advance before all the sub-frames arrive.
	 *
	 * Example: reorder buffer contains SN 0 & 2, and we receive AMSDU with
	 * SN 1. NSSN for first sub frame will be 3 with the result of driver
	 * releasing SN 0,1, 2. When sub-frame 1 arrives - reorder buffer is
	 * already ahead and it will be dropped.
	 * If the last sub-frame is not on this queue - we will get frame
	 * release notification with up to date NSSN.
	 */
	if (!amsdu || last_subframe)
		iwl_mld_reorder_release_frames(mld, sta, napi, baid_data,
					       buffer, nssn);

	return true;
}

void iwl_mld_rx_mpdu(struct iwl_mld *mld, struct napi_struct *napi,
		     struct iwl_rx_cmd_buffer *rxb, int queue)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mld_rx_phy_data phy_data = {};
	struct iwl_rx_mpdu_desc *mpdu_desc = (void *)pkt->data;
	struct ieee80211_sta *sta;
	struct ieee80211_hdr *hdr;
	struct sk_buff *skb;
	size_t mpdu_desc_size = sizeof(*mpdu_desc);
	bool drop = false;
	u32 pkt_len = iwl_rx_packet_payload_len(pkt);
	u32 mpdu_len;

	if (unlikely(mld->fw_status.in_hw_restart))
		return;

	if (IWL_FW_CHECK(mld, pkt_len < mpdu_desc_size,
			 "Bad REPLY_RX_MPDU_CMD size (%d)\n", pkt_len))
		return;

	mpdu_len = le16_to_cpu(mpdu_desc->mpdu_len);

	if (IWL_FW_CHECK(mld, mpdu_len + mpdu_desc_size > pkt_len,
			 "FW lied about packet len (%d)\n", pkt_len))
		return;

	/* Don't use dev_alloc_skb(), we'll have enough headroom once
	 * ieee80211_hdr pulled.
	 */
	skb = alloc_skb(128, GFP_ATOMIC);
	if (!skb) {
		IWL_ERR(mld, "alloc_skb failed\n");
		return;
	}

	hdr = (void *)(pkt->data + mpdu_desc_size);

	iwl_mld_fill_phy_data(mpdu_desc, &phy_data);

	if (mpdu_desc->mac_flags2 & IWL_RX_MPDU_MFLG2_PAD) {
		/* If the device inserted padding it means that (it thought)
		 * the 802.11 header wasn't a multiple of 4 bytes long. In
		 * this case, reserve two bytes at the start of the SKB to
		 * align the payload properly in case we end up copying it.
		 */
		skb_reserve(skb, 2);
	}

	iwl_mld_rx_fill_status(mld, skb, &phy_data, mpdu_desc, hdr, queue);

	/* TODO: update aggregation data (task=monitor) */
	/* TODO: handle crypto */

	rcu_read_lock();

	sta = iwl_mld_rx_with_sta(mld, hdr, skb, mpdu_desc, pkt, queue, &drop);
	if (drop) {
		kfree_skb(skb);
		goto unlock;
	}

	/* TODO: pass crypto len */
	if (iwl_mld_create_skb(mld, skb, hdr, mpdu_len, 0, rxb)) {
		kfree_skb(skb);
		goto unlock;
	}

	/* TODO: verify the following before passing frames to mac80211:
	 * 1. time sync frame
	 * 2. FPGA valid packet channel
	 * 3. mei_scan_filter
	 */

	if (!iwl_mld_reorder(mld, napi, queue, sta, skb, mpdu_desc))
		iwl_mld_pass_packet_to_mac80211(mld, napi, skb, queue, sta);

unlock:
	rcu_read_unlock();
}

static void iwl_mld_release_frames_from_notif(struct iwl_mld *mld,
					      struct napi_struct *napi,
					      u8 baid, u16 nssn, int queue)
{
	struct iwl_mld_reorder_buffer *reorder_buf;
	struct iwl_mld_baid_data *ba_data;
	struct ieee80211_link_sta *link_sta;
	u32 sta_id;

	IWL_DEBUG_HT(mld, "Frame release notification for BAID %u, NSSN %d\n",
		     baid, nssn);

	if (WARN_ON_ONCE(baid == IWL_RX_REORDER_DATA_INVALID_BAID ||
			 baid >= ARRAY_SIZE(mld->fw_id_to_ba)))
		return;

	rcu_read_lock();

	ba_data = rcu_dereference(mld->fw_id_to_ba[baid]);
	if (IWL_FW_CHECK(mld, !ba_data, "BAID %d not found in map\n", baid))
		goto out_unlock;

	/* pick any STA ID to find the pointer */
	sta_id = ffs(ba_data->sta_mask) - 1;
	link_sta = rcu_dereference(mld->fw_id_to_link_sta[sta_id]);
	if (WARN_ON_ONCE(!link_sta || !link_sta->sta))
		goto out_unlock;

	reorder_buf = &ba_data->reorder_buf[queue];

	iwl_mld_reorder_release_frames(mld, link_sta->sta, napi, ba_data,
				       reorder_buf, nssn);
out_unlock:
	rcu_read_unlock();
}

void iwl_mld_handle_frame_release_notif(struct iwl_mld *mld,
					struct napi_struct *napi,
					struct iwl_rx_packet *pkt, int queue)
{
	struct iwl_frame_release *release = (void *)pkt->data;
	u32 pkt_len = iwl_rx_packet_payload_len(pkt);

	if (IWL_FW_CHECK(mld, pkt_len < sizeof(*release),
			 "Unexpected frame release notif size %d (expected %ld)\n",
			 pkt_len, sizeof(*release)))
		return;

	iwl_mld_release_frames_from_notif(mld, napi, release->baid,
					  le16_to_cpu(release->nssn),
					  queue);
}

void iwl_mld_handle_bar_frame_release_notif(struct iwl_mld *mld,
					    struct napi_struct *napi,
					    struct iwl_rx_packet *pkt,
					    int queue)
{
	struct iwl_bar_frame_release *release = (void *)pkt->data;
	struct iwl_mld_baid_data *baid_data;
	unsigned int baid = le32_get_bits(release->ba_info,
					  IWL_BAR_FRAME_RELEASE_BAID_MASK);
	unsigned int nssn = le32_get_bits(release->ba_info,
					  IWL_BAR_FRAME_RELEASE_NSSN_MASK);
	unsigned int sta_id = le32_get_bits(release->sta_tid,
					    IWL_BAR_FRAME_RELEASE_STA_MASK);
	unsigned int tid = le32_get_bits(release->sta_tid,
					 IWL_BAR_FRAME_RELEASE_TID_MASK);
	u32 pkt_len = iwl_rx_packet_payload_len(pkt);

	if (IWL_FW_CHECK(mld, pkt_len < sizeof(*release),
			 "Unexpected frame release notif size %d (expected %ld)\n",
			 pkt_len, sizeof(*release)))
		return;

	if (IWL_FW_CHECK(mld, baid >= ARRAY_SIZE(mld->fw_id_to_ba),
			 "BAR release: invalid BAID (%x)\n", baid))
		return;

	rcu_read_lock();
	baid_data = rcu_dereference(mld->fw_id_to_ba[baid]);
	if (!IWL_FW_CHECK(mld, !baid_data,
			  "Got valid BAID %d but not allocated, invalid BAR release!\n",
			  baid))
		goto out_unlock;

	if (IWL_FW_CHECK(mld, tid != baid_data->tid ||
			 sta_id > mld->fw->ucode_capa.num_stations ||
			 !(baid_data->sta_mask & BIT(sta_id)),
			 "BAID 0x%x is mapped to sta_mask:0x%x tid:%d, but BAR release received for sta:%d tid:%d\n",
			 baid, baid_data->sta_mask, baid_data->tid, sta_id,
			 tid))
		goto out_unlock;

	IWL_DEBUG_DROP(mld, "Received a BAR, expect packet loss: nssn %d\n",
		       nssn);

	iwl_mld_release_frames_from_notif(mld, napi, baid, nssn, queue);
out_unlock:
	rcu_read_unlock();
}
