// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"
#include "fw/dbg.h"
#include "fw/api/rx.h"
#include "fw/api/rs.h"

/* stores relevant PHY data fields extracted from iwl_rx_mpdu_desc */
struct iwl_mld_rx_phy_data {
	u32 rate_n_flags;
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
	phy_data->channel = desc->v3.channel;
	phy_data->energy_a = desc->v3.energy_a;
	phy_data->energy_b = desc->v3.energy_b;
}

/* iwl_mld_pass_packet_to_mac80211 - passes the packet for mac80211 */
static void iwl_mld_pass_packet_to_mac80211(struct iwl_mld *mld,
					    struct napi_struct *napi,
					    struct sk_buff *skb,
					    struct ieee80211_sta *sta)
{
	/* TODO: check PN */
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

static void iwl_mld_rx_fill_status(struct iwl_mld *mld, struct sk_buff *skb,
				   struct iwl_mld_rx_phy_data *phy_data,
				   struct iwl_rx_mpdu_desc *mpdu_desc,
				   struct ieee80211_hdr *hdr,
				   int queue)
{
	struct ieee80211_rx_status *rx_status = IEEE80211_SKB_RXCB(skb);
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

	if (likely(!(phy_data->phy_info & IWL_RX_MPDU_PHY_TSF_OVERLOAD))) {
		rx_status->mactime =
			le64_to_cpu(mpdu_desc->v3.tsf_on_air_rise);

		/* TSF as indicated by the firmware is at INA time */
		rx_status->flag |= RX_FLAG_MACTIME_PLCP_START;
	}

	/* management stuff on default queue */
	if (!queue) {
		if (unlikely(ieee80211_is_beacon(hdr->frame_control) ||
			     ieee80211_is_probe_resp(hdr->frame_control)))
			rx_status->boottime_ns = ktime_get_boottime_ns();

		/* TODO: SCHED_SCAN_PASS_ALL_FOUND */
	}

	band = BAND_IN_RX_STATUS(mpdu_desc->mac_phy_idx);
	rx_status->band = iwl_mld_phy_band_to_nl80211(band);
	rx_status->freq = ieee80211_channel_to_frequency(phy_data->channel,
							 rx_status->band);
	iwl_mld_fill_signal(mld, rx_status, phy_data);

	/* TODO: fill more fields */
}

/* iwl_mld_create_skb adds the rxb to a new skb */
static int iwl_mld_create_skb(struct iwl_mld *mld, struct sk_buff *skb,
			      struct ieee80211_hdr *hdr, u16 len, u8 crypt_len,
			      struct iwl_rx_cmd_buffer *rxb)
{
	unsigned int headlen, fraglen, pad_len = 0;
	unsigned int hdrlen = ieee80211_hdrlen(hdr->frame_control);

	/* TODO: handle IWL_RX_MPDU_MFLG2_PAD */

	/* TODO: strip mic_crc_len for non monitor interface */

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

	/* TODO: CHECKSUM_COMPLETE (task=DP) */

	fraglen = len - headlen;

	if (fraglen) {
		int offset = (u8 *)hdr + headlen + pad_len -
			     (u8 *)rxb_addr(rxb) + rxb_offset(rxb);

		skb_add_rx_frag(skb, 0, rxb_steal_page(rxb), offset,
				fraglen, rxb->truesize);
	}

	return 0;
}

void iwl_mld_rx_mpdu(struct iwl_mld *mld, struct napi_struct *napi,
		     struct iwl_rx_cmd_buffer *rxb, int queue)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mld_rx_phy_data phy_data = {};
	struct iwl_rx_mpdu_desc *mpdu_desc = (void *)pkt->data;
	struct ieee80211_sta *sta = NULL;
	struct ieee80211_hdr *hdr;
	struct sk_buff *skb;
	size_t mpdu_desc_size = sizeof(*mpdu_desc);
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

	/* TODO: IWL_RX_MPDU_MFLG2_PAD */

	iwl_mld_rx_fill_status(mld, skb, &phy_data, mpdu_desc, hdr, queue);

	/* TODO: RATE_MCS_MOD_TYPE_MSK */
	/* TODO: RX_ENC_FLAG_SHORTPRE */
	/* TODO: update aggregation data (task=monitor) */
	/* TODO: IWL_RX_MPDU_STATUS_SRC_STA_FOUND case */
	/* TODO: !multicast_addr case */
	/* TODO: handle crypto */
	/* TODO: handle sta found */

	/* TODO: pass crypto len */
	if (iwl_mld_create_skb(mld, skb, hdr, mpdu_len, 0, rxb))
		goto out_free;

	/* TODO: verify the following before passing frames to mac80211:
	 * 1. reorder buffer
	 * 2. time sync frame
	 * 3. FPGA valid packet channel
	 * 4. mei_scan_filter
	 */

	iwl_mld_pass_packet_to_mac80211(mld, napi, skb, sta);

	return;

out_free:
	kfree_skb(skb);
}
