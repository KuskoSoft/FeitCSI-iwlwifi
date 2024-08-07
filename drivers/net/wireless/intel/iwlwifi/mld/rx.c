// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>
#include <kunit/static_stub.h>

#include "mld.h"
#include "sta.h"
#include "agg.h"
#include "rx.h"
#include "hcmd.h"
#include "iface.h"
#include "fw/dbg.h"
#include "fw/api/rx.h"

/* stores relevant PHY data fields extracted from iwl_rx_mpdu_desc */
struct iwl_mld_rx_phy_data {
	enum iwl_rx_phy_info_type info_type;
	__le32 data0;
	__le32 data1;
	__le32 data2;
	__le32 data3;
	__le16 data4;
	bool first_subframe;
	bool with_data;
	__le32 rx_vec[4];
	u32 rate_n_flags;
	u32 gp2_on_air_rise;
	u16 phy_info;
	u8 energy_a, energy_b;
	u8 channel;
	/* TODO: add more fields */
};

static void
iwl_mld_fill_phy_data(struct iwl_rx_mpdu_desc *desc,
		      struct iwl_mld_rx_phy_data *phy_data)
{
	phy_data->phy_info = le16_to_cpu(desc->phy_info);
	phy_data->rate_n_flags = le32_to_cpu(desc->v3.rate_n_flags);
	phy_data->gp2_on_air_rise = le32_to_cpu(desc->v3.gp2_on_air_rise);
	phy_data->channel = desc->v3.channel;
	phy_data->energy_a = desc->v3.energy_a;
	phy_data->energy_b = desc->v3.energy_b;
	phy_data->data0 = desc->v3.phy_data0;
	phy_data->data1 = desc->v3.phy_data1;
	phy_data->data2 = desc->v3.phy_data2;
	phy_data->data3 = desc->v3.phy_data3;
	phy_data->data4 = desc->phy_data4;
	phy_data->with_data = true;
}

static inline int iwl_mld_check_pn(struct iwl_mld *mld, struct sk_buff *skb,
				   int queue, struct ieee80211_sta *sta)
{
	struct ieee80211_hdr *hdr = (void *)skb_mac_header(skb);
	struct ieee80211_rx_status *stats = IEEE80211_SKB_RXCB(skb);
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_ptk_pn *ptk_pn;
	int res;
	u8 tid, keyidx;
	u8 pn[IEEE80211_CCMP_PN_LEN];
	u8 *extiv;

	/* multicast and non-data only arrives on default queue; avoid checking
	 * for default queue - we don't want to replicate all the logic that's
	 * necessary for checking the PN on fragmented frames, leave that
	 * to mac80211
	 */
	if (queue == 0 || !ieee80211_is_data(hdr->frame_control) ||
	    is_multicast_ether_addr(hdr->addr1))
		return 0;

	if (!(stats->flag & RX_FLAG_DECRYPTED))
		return 0;

	/* if we are here - this for sure is either CCMP or GCMP */
	if (!sta) {
		IWL_DEBUG_DROP(mld,
			       "expected hw-decrypted unicast frame for station\n");
		return -1;
	}

	mld_sta = iwl_mld_sta_from_mac80211(sta);

	extiv = (u8 *)hdr + ieee80211_hdrlen(hdr->frame_control);
	keyidx = extiv[3] >> 6;

	ptk_pn = rcu_dereference(mld_sta->ptk_pn[keyidx]);
	if (!ptk_pn)
		return -1;

	if (ieee80211_is_data_qos(hdr->frame_control))
		tid = ieee80211_get_tid(hdr);
	else
		tid = 0;

	/* we don't use HCCA/802.11 QoS TSPECs, so drop such frames */
	if (tid >= IWL_MAX_TID_COUNT)
		return -1;

	/* load pn */
	pn[0] = extiv[7];
	pn[1] = extiv[6];
	pn[2] = extiv[5];
	pn[3] = extiv[4];
	pn[4] = extiv[1];
	pn[5] = extiv[0];

	res = memcmp(pn, ptk_pn->q[queue].pn[tid], IEEE80211_CCMP_PN_LEN);
	if (res < 0)
		return -1;
	if (!res && !(stats->flag & RX_FLAG_ALLOW_SAME_PN))
		return -1;

	memcpy(ptk_pn->q[queue].pn[tid], pn, IEEE80211_CCMP_PN_LEN);
	stats->flag |= RX_FLAG_PN_VALIDATED;

	return 0;
}

/* iwl_mld_pass_packet_to_mac80211 - passes the packet for mac80211 */
void iwl_mld_pass_packet_to_mac80211(struct iwl_mld *mld,
				     struct napi_struct *napi,
				     struct sk_buff *skb, int queue,
				     struct ieee80211_sta *sta)
{
	KUNIT_STATIC_STUB_REDIRECT(iwl_mld_pass_packet_to_mac80211,
				   mld, napi, skb, queue, sta);

	if (unlikely(iwl_mld_check_pn(mld, skb, queue, sta))) {
		kfree_skb(skb);
		return;
	}

	ieee80211_rx_napi(mld->hw, sta, skb, napi);
}
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_mld_pass_packet_to_mac80211);

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

static void
iwl_mld_decode_he_phy_ru_alloc(struct iwl_mld_rx_phy_data *phy_data,
			       struct ieee80211_radiotap_he *he,
			       struct ieee80211_radiotap_he_mu *he_mu,
			       struct ieee80211_rx_status *rx_status)
{
	/* Unfortunately, we have to leave the mac80211 data
	 * incorrect for the case that we receive an HE-MU
	 * transmission and *don't* have the HE phy data (due
	 * to the bits being used for TSF). This shouldn't
	 * happen though as management frames where we need
	 * the TSF/timers are not be transmitted in HE-MU.
	 */
	u8 ru = le32_get_bits(phy_data->data1, IWL_RX_PHY_DATA1_HE_RU_ALLOC_MASK);
	u32 rate_n_flags = phy_data->rate_n_flags;
	u32 he_type = rate_n_flags & RATE_MCS_HE_TYPE_MSK;
	u8 offs = 0;

	rx_status->bw = RATE_INFO_BW_HE_RU;

	he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN);

	switch (ru) {
	case 0 ... 36:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_26;
		offs = ru;
		break;
	case 37 ... 52:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_52;
		offs = ru - 37;
		break;
	case 53 ... 60:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_106;
		offs = ru - 53;
		break;
	case 61 ... 64:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_242;
		offs = ru - 61;
		break;
	case 65 ... 66:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_484;
		offs = ru - 65;
		break;
	case 67:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_996;
		break;
	case 68:
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_2x996;
		break;
	}
	he->data2 |= le16_encode_bits(offs,
				      IEEE80211_RADIOTAP_HE_DATA2_RU_OFFSET);
	he->data2 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA2_PRISEC_80_KNOWN |
				 IEEE80211_RADIOTAP_HE_DATA2_RU_OFFSET_KNOWN);
	if (phy_data->data1 & cpu_to_le32(IWL_RX_PHY_DATA1_HE_RU_ALLOC_SEC80))
		he->data2 |=
			cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA2_PRISEC_80_SEC);

#define CHECK_BW(bw) \
	BUILD_BUG_ON(IEEE80211_RADIOTAP_HE_MU_FLAGS2_BW_FROM_SIG_A_BW_ ## bw ## MHZ != \
		     RATE_MCS_CHAN_WIDTH_##bw >> RATE_MCS_CHAN_WIDTH_POS); \
	BUILD_BUG_ON(IEEE80211_RADIOTAP_HE_DATA6_TB_PPDU_BW_ ## bw ## MHZ != \
		     RATE_MCS_CHAN_WIDTH_##bw >> RATE_MCS_CHAN_WIDTH_POS)
	CHECK_BW(20);
	CHECK_BW(40);
	CHECK_BW(80);
	CHECK_BW(160);

	if (he_mu)
		he_mu->flags2 |=
			le16_encode_bits(u32_get_bits(rate_n_flags,
						      RATE_MCS_CHAN_WIDTH_MSK),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS2_BW_FROM_SIG_A_BW);
	else if (he_type == RATE_MCS_HE_TYPE_TRIG)
		he->data6 |=
			cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA6_TB_PPDU_BW_KNOWN) |
			le16_encode_bits(u32_get_bits(rate_n_flags,
						      RATE_MCS_CHAN_WIDTH_MSK),
					 IEEE80211_RADIOTAP_HE_DATA6_TB_PPDU_BW);
}

static void
iwl_mld_decode_he_mu_ext(struct iwl_mld_rx_phy_data *phy_data,
			 struct ieee80211_radiotap_he_mu *he_mu)
{
	u32 phy_data2 = le32_to_cpu(phy_data->data2);
	u32 phy_data3 = le32_to_cpu(phy_data->data3);
	u16 phy_data4 = le16_to_cpu(phy_data->data4);
	u32 rate_n_flags = phy_data->rate_n_flags;

	if (u32_get_bits(phy_data4, IWL_RX_PHY_DATA4_HE_MU_EXT_CH1_CRC_OK)) {
		he_mu->flags1 |=
			cpu_to_le16(IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH1_RU_KNOWN |
				    IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH1_CTR_26T_RU_KNOWN);

		he_mu->flags1 |=
			le16_encode_bits(u32_get_bits(phy_data4,
						      IWL_RX_PHY_DATA4_HE_MU_EXT_CH1_CTR_RU),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH1_CTR_26T_RU);

		he_mu->ru_ch1[0] = u32_get_bits(phy_data2,
						IWL_RX_PHY_DATA2_HE_MU_EXT_CH1_RU0);
		he_mu->ru_ch1[1] = u32_get_bits(phy_data3,
						IWL_RX_PHY_DATA3_HE_MU_EXT_CH1_RU1);
		he_mu->ru_ch1[2] = u32_get_bits(phy_data2,
						IWL_RX_PHY_DATA2_HE_MU_EXT_CH1_RU2);
		he_mu->ru_ch1[3] = u32_get_bits(phy_data3,
						IWL_RX_PHY_DATA3_HE_MU_EXT_CH1_RU3);
	}

	if (u32_get_bits(phy_data4, IWL_RX_PHY_DATA4_HE_MU_EXT_CH2_CRC_OK) &&
	    (rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) != RATE_MCS_CHAN_WIDTH_20) {
		he_mu->flags1 |=
			cpu_to_le16(IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH2_RU_KNOWN |
				    IEEE80211_RADIOTAP_HE_MU_FLAGS1_CH2_CTR_26T_RU_KNOWN);

		he_mu->flags2 |=
			le16_encode_bits(u32_get_bits(phy_data4,
						      IWL_RX_PHY_DATA4_HE_MU_EXT_CH2_CTR_RU),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS2_CH2_CTR_26T_RU);

		he_mu->ru_ch2[0] = u32_get_bits(phy_data2,
						IWL_RX_PHY_DATA2_HE_MU_EXT_CH2_RU0);
		he_mu->ru_ch2[1] = u32_get_bits(phy_data3,
						IWL_RX_PHY_DATA3_HE_MU_EXT_CH2_RU1);
		he_mu->ru_ch2[2] = u32_get_bits(phy_data2,
						IWL_RX_PHY_DATA2_HE_MU_EXT_CH2_RU2);
		he_mu->ru_ch2[3] = u32_get_bits(phy_data3,
						IWL_RX_PHY_DATA3_HE_MU_EXT_CH2_RU3);
	}
}

static void
iwl_mld_decode_he_phy_data(struct iwl_mld_rx_phy_data *phy_data,
			   struct ieee80211_radiotap_he *he,
			   struct ieee80211_radiotap_he_mu *he_mu,
			   struct ieee80211_rx_status *rx_status,
			   int queue)
{
	switch (phy_data->info_type) {
	case IWL_RX_PHY_INFO_TYPE_NONE:
	case IWL_RX_PHY_INFO_TYPE_CCK:
	case IWL_RX_PHY_INFO_TYPE_OFDM_LGCY:
	case IWL_RX_PHY_INFO_TYPE_HT:
	case IWL_RX_PHY_INFO_TYPE_VHT_SU:
	case IWL_RX_PHY_INFO_TYPE_VHT_MU:
	case IWL_RX_PHY_INFO_TYPE_EHT_MU:
	case IWL_RX_PHY_INFO_TYPE_EHT_TB:
	case IWL_RX_PHY_INFO_TYPE_EHT_MU_EXT:
	case IWL_RX_PHY_INFO_TYPE_EHT_TB_EXT:
		return;
	case IWL_RX_PHY_INFO_TYPE_HE_TB_EXT:
		he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE2_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE3_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE4_KNOWN);
		he->data4 |= le16_encode_bits(le32_get_bits(phy_data->data2,
							    IWL_RX_PHY_DATA2_HE_TB_EXT_SPTL_REUSE1),
					      IEEE80211_RADIOTAP_HE_DATA4_TB_SPTL_REUSE1);
		he->data4 |= le16_encode_bits(le32_get_bits(phy_data->data2,
							    IWL_RX_PHY_DATA2_HE_TB_EXT_SPTL_REUSE2),
					      IEEE80211_RADIOTAP_HE_DATA4_TB_SPTL_REUSE2);
		he->data4 |= le16_encode_bits(le32_get_bits(phy_data->data2,
							    IWL_RX_PHY_DATA2_HE_TB_EXT_SPTL_REUSE3),
					      IEEE80211_RADIOTAP_HE_DATA4_TB_SPTL_REUSE3);
		he->data4 |= le16_encode_bits(le32_get_bits(phy_data->data2,
							    IWL_RX_PHY_DATA2_HE_TB_EXT_SPTL_REUSE4),
					      IEEE80211_RADIOTAP_HE_DATA4_TB_SPTL_REUSE4);
		fallthrough;
	case IWL_RX_PHY_INFO_TYPE_HE_SU:
	case IWL_RX_PHY_INFO_TYPE_HE_MU:
	case IWL_RX_PHY_INFO_TYPE_HE_MU_EXT:
	case IWL_RX_PHY_INFO_TYPE_HE_TB:
		/* HE common */
		he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_LDPC_XSYMSEG_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA1_DOPPLER_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA1_BSS_COLOR_KNOWN);
		he->data2 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA2_PRE_FEC_PAD_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA2_PE_DISAMBIG_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA2_TXOP_KNOWN |
					 IEEE80211_RADIOTAP_HE_DATA2_NUM_LTF_SYMS_KNOWN);
		he->data3 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_BSS_COLOR_MASK),
					      IEEE80211_RADIOTAP_HE_DATA3_BSS_COLOR);
		if (phy_data->info_type != IWL_RX_PHY_INFO_TYPE_HE_TB &&
		    phy_data->info_type != IWL_RX_PHY_INFO_TYPE_HE_TB_EXT) {
			he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_UL_DL_KNOWN);
			he->data3 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_UPLINK),
						      IEEE80211_RADIOTAP_HE_DATA3_UL_DL);
		}
		he->data3 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_LDPC_EXT_SYM),
					      IEEE80211_RADIOTAP_HE_DATA3_LDPC_XSYMSEG);
		he->data5 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_PRE_FEC_PAD_MASK),
					      IEEE80211_RADIOTAP_HE_DATA5_PRE_FEC_PAD);
		he->data5 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_PE_DISAMBIG),
					      IEEE80211_RADIOTAP_HE_DATA5_PE_DISAMBIG);
		he->data5 |= le16_encode_bits(le32_get_bits(phy_data->data1,
							    IWL_RX_PHY_DATA1_HE_LTF_NUM_MASK),
					      IEEE80211_RADIOTAP_HE_DATA5_NUM_LTF_SYMS);
		he->data6 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_TXOP_DUR_MASK),
					      IEEE80211_RADIOTAP_HE_DATA6_TXOP);
		he->data6 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_DOPPLER),
					      IEEE80211_RADIOTAP_HE_DATA6_DOPPLER);
		break;
	}

	switch (phy_data->info_type) {
	case IWL_RX_PHY_INFO_TYPE_HE_MU_EXT:
	case IWL_RX_PHY_INFO_TYPE_HE_MU:
	case IWL_RX_PHY_INFO_TYPE_HE_SU:
		he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_SPTL_REUSE_KNOWN);
		he->data4 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_SPATIAL_REUSE_MASK),
					      IEEE80211_RADIOTAP_HE_DATA4_SU_MU_SPTL_REUSE);
		break;
	default:
		/* nothing here */
		break;
	}

	switch (phy_data->info_type) {
	case IWL_RX_PHY_INFO_TYPE_HE_MU_EXT:
		he_mu->flags1 |=
			le16_encode_bits(le16_get_bits(phy_data->data4,
						       IWL_RX_PHY_DATA4_HE_MU_EXT_SIGB_DCM),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_DCM);
		he_mu->flags1 |=
			le16_encode_bits(le16_get_bits(phy_data->data4,
						       IWL_RX_PHY_DATA4_HE_MU_EXT_SIGB_MCS_MASK),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_MCS);
		he_mu->flags2 |=
			le16_encode_bits(le16_get_bits(phy_data->data4,
						       IWL_RX_PHY_DATA4_HE_MU_EXT_PREAMBLE_PUNC_TYPE_MASK),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS2_PUNC_FROM_SIG_A_BW);
		iwl_mld_decode_he_mu_ext(phy_data, he_mu);
		fallthrough;
	case IWL_RX_PHY_INFO_TYPE_HE_MU:
		he_mu->flags2 |=
			le16_encode_bits(le32_get_bits(phy_data->data1,
						       IWL_RX_PHY_DATA1_HE_MU_SIBG_SYM_OR_USER_NUM_MASK),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS2_SIG_B_SYMS_USERS);
		he_mu->flags2 |=
			le16_encode_bits(le32_get_bits(phy_data->data1,
						       IWL_RX_PHY_DATA1_HE_MU_SIGB_COMPRESSION),
					 IEEE80211_RADIOTAP_HE_MU_FLAGS2_SIG_B_COMP);
		fallthrough;
	case IWL_RX_PHY_INFO_TYPE_HE_TB:
	case IWL_RX_PHY_INFO_TYPE_HE_TB_EXT:
		iwl_mld_decode_he_phy_ru_alloc(phy_data, he, he_mu, rx_status);
		break;
	case IWL_RX_PHY_INFO_TYPE_HE_SU:
		he->data1 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_BEAM_CHANGE_KNOWN);
		he->data3 |= le16_encode_bits(le32_get_bits(phy_data->data0,
							    IWL_RX_PHY_DATA0_HE_BEAM_CHNG),
					      IEEE80211_RADIOTAP_HE_DATA3_BEAM_CHANGE);
		break;
	default:
		/* nothing */
		break;
	}
}

static void iwl_mld_rx_he(struct iwl_mld *mld, struct sk_buff *skb,
			  struct iwl_mld_rx_phy_data *phy_data,
			  int queue)
{
	struct ieee80211_rx_status *rx_status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_radiotap_he *he = NULL;
	struct ieee80211_radiotap_he_mu *he_mu = NULL;
	u32 rate_n_flags = phy_data->rate_n_flags;
	u32 he_type = rate_n_flags & RATE_MCS_HE_TYPE_MSK;
	u8 ltf;
	static const struct ieee80211_radiotap_he known = {
		.data1 = cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_DATA_MCS_KNOWN |
				     IEEE80211_RADIOTAP_HE_DATA1_DATA_DCM_KNOWN |
				     IEEE80211_RADIOTAP_HE_DATA1_STBC_KNOWN	|
				     IEEE80211_RADIOTAP_HE_DATA1_CODING_KNOWN),
		.data2 = cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA2_GI_KNOWN |
				     IEEE80211_RADIOTAP_HE_DATA2_TXBF_KNOWN),
	};
	static const struct ieee80211_radiotap_he_mu mu_known = {
		.flags1 = cpu_to_le16(IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_MCS_KNOWN |
				      IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_DCM_KNOWN |
				      IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_SYMS_USERS_KNOWN |
				      IEEE80211_RADIOTAP_HE_MU_FLAGS1_SIG_B_COMP_KNOWN),
		.flags2 = cpu_to_le16(IEEE80211_RADIOTAP_HE_MU_FLAGS2_PUNC_FROM_SIG_A_BW_KNOWN |
				      IEEE80211_RADIOTAP_HE_MU_FLAGS2_BW_FROM_SIG_A_BW_KNOWN),
	};
	u16 phy_info = phy_data->phy_info;

	he = skb_put_data(skb, &known, sizeof(known));
	rx_status->flag |= RX_FLAG_RADIOTAP_HE;

	if (phy_data->info_type == IWL_RX_PHY_INFO_TYPE_HE_MU ||
	    phy_data->info_type == IWL_RX_PHY_INFO_TYPE_HE_MU_EXT) {
		he_mu = skb_put_data(skb, &mu_known, sizeof(mu_known));
		rx_status->flag |= RX_FLAG_RADIOTAP_HE_MU;
	}

	/* report the AMPDU-EOF bit on single frames */
	if (!queue && !(phy_info & IWL_RX_MPDU_PHY_AMPDU)) {
		rx_status->flag |= RX_FLAG_AMPDU_DETAILS;
		rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT_KNOWN;
		if (phy_data->data0 & cpu_to_le32(IWL_RX_PHY_DATA0_HE_DELIM_EOF))
			rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT;
	}

	if (phy_info & IWL_RX_MPDU_PHY_TSF_OVERLOAD)
		iwl_mld_decode_he_phy_data(phy_data, he, he_mu, rx_status,
					   queue);

	/* update aggregation data for monitor sake on default queue */
	if (!queue && (phy_info & IWL_RX_MPDU_PHY_TSF_OVERLOAD) &&
	    (phy_info & IWL_RX_MPDU_PHY_AMPDU) && phy_data->first_subframe) {
		rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT_KNOWN;
		if (phy_data->data0 & cpu_to_le32(IWL_RX_PHY_DATA0_EHT_DELIM_EOF))
			rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT;
	}

	if (he_type == RATE_MCS_HE_TYPE_EXT_SU &&
	    rate_n_flags & RATE_MCS_HE_106T_MSK) {
		rx_status->bw = RATE_INFO_BW_HE_RU;
		rx_status->he_ru = NL80211_RATE_INFO_HE_RU_ALLOC_106;
	}

	/* actually data is filled in mac80211 */
	if (he_type == RATE_MCS_HE_TYPE_SU ||
	    he_type == RATE_MCS_HE_TYPE_EXT_SU)
		he->data1 |=
			cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN);

#define CHECK_TYPE(F)							\
	BUILD_BUG_ON(IEEE80211_RADIOTAP_HE_DATA1_FORMAT_ ## F !=	\
		     (RATE_MCS_HE_TYPE_ ## F >> RATE_MCS_HE_TYPE_POS))

	CHECK_TYPE(SU);
	CHECK_TYPE(EXT_SU);
	CHECK_TYPE(MU);
	CHECK_TYPE(TRIG);

	he->data1 |= cpu_to_le16(he_type >> RATE_MCS_HE_TYPE_POS);

	if (rate_n_flags & RATE_MCS_BF_MSK)
		he->data5 |= cpu_to_le16(IEEE80211_RADIOTAP_HE_DATA5_TXBF);

	switch ((rate_n_flags & RATE_MCS_HE_GI_LTF_MSK) >>
		RATE_MCS_HE_GI_LTF_POS) {
	case 0:
		if (he_type == RATE_MCS_HE_TYPE_TRIG)
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
		else
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
		if (he_type == RATE_MCS_HE_TYPE_MU)
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
		else
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_1X;
		break;
	case 1:
		if (he_type == RATE_MCS_HE_TYPE_TRIG)
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
		else
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_2X;
		break;
	case 2:
		if (he_type == RATE_MCS_HE_TYPE_TRIG) {
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
		} else {
			rx_status->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_2X;
		}
		break;
	case 3:
		rx_status->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
		break;
	case 4:
		rx_status->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
		break;
	default:
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_UNKNOWN;
	}

	he->data5 |= le16_encode_bits(ltf,
				      IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE);
}

static void iwl_mld_decode_lsig(struct sk_buff *skb,
				struct iwl_mld_rx_phy_data *phy_data)
{
	struct ieee80211_rx_status *rx_status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_radiotap_lsig *lsig;

	switch (phy_data->info_type) {
	case IWL_RX_PHY_INFO_TYPE_HT:
	case IWL_RX_PHY_INFO_TYPE_VHT_SU:
	case IWL_RX_PHY_INFO_TYPE_VHT_MU:
	case IWL_RX_PHY_INFO_TYPE_HE_TB_EXT:
	case IWL_RX_PHY_INFO_TYPE_HE_SU:
	case IWL_RX_PHY_INFO_TYPE_HE_MU:
	case IWL_RX_PHY_INFO_TYPE_HE_MU_EXT:
	case IWL_RX_PHY_INFO_TYPE_HE_TB:
	case IWL_RX_PHY_INFO_TYPE_EHT_MU:
	case IWL_RX_PHY_INFO_TYPE_EHT_TB:
	case IWL_RX_PHY_INFO_TYPE_EHT_MU_EXT:
	case IWL_RX_PHY_INFO_TYPE_EHT_TB_EXT:
		lsig = skb_put(skb, sizeof(*lsig));
		lsig->data1 = cpu_to_le16(IEEE80211_RADIOTAP_LSIG_DATA1_LENGTH_KNOWN);
		lsig->data2 = le16_encode_bits(le32_get_bits(phy_data->data1,
							     IWL_RX_PHY_DATA1_LSIG_LEN_MASK),
					       IEEE80211_RADIOTAP_LSIG_DATA2_LENGTH);
		rx_status->flag |= RX_FLAG_RADIOTAP_LSIG;
		break;
	default:
		break;
	}
}

/* Put a TLV on the skb and return data pointer
 *
 * Also pad the len to 4 and zero out all data part
 */
static void *
iwl_mld_radiotap_put_tlv(struct sk_buff *skb, u16 type, u16 len)
{
	struct ieee80211_radiotap_tlv *tlv;

	tlv = skb_put(skb, sizeof(*tlv));
	tlv->type = cpu_to_le16(type);
	tlv->len = cpu_to_le16(len);
	return skb_put_zero(skb, ALIGN(len, 4));
}

static void iwl_mld_rx_eht(struct sk_buff *skb,
			   struct iwl_mld_rx_phy_data *phy_data,
			   int queue)
{
	struct ieee80211_rx_status *rx_status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_radiotap_eht *eht;
	struct ieee80211_radiotap_eht_usig *usig;
	size_t eht_len = sizeof(*eht);

	u32 rate_n_flags = phy_data->rate_n_flags;
	u32 he_type = rate_n_flags & RATE_MCS_HE_TYPE_MSK;
	/* EHT and HE have the same values for LTF */
	u8 ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_UNKNOWN;
	u16 phy_info = phy_data->phy_info;
	u32 bw;

	/* u32 for 1 user_info */
	if (phy_data->with_data)
		eht_len += sizeof(u32);

	eht = iwl_mld_radiotap_put_tlv(skb, IEEE80211_RADIOTAP_EHT, eht_len);

	usig = iwl_mld_radiotap_put_tlv(skb, IEEE80211_RADIOTAP_EHT_USIG,
					sizeof(*usig));
	rx_status->flag |= RX_FLAG_RADIOTAP_TLV_AT_END;
	usig->common |=
		cpu_to_le32(IEEE80211_RADIOTAP_EHT_USIG_COMMON_BW_KNOWN);

	/* specific handling for 320MHz */
	bw = u32_get_bits(rate_n_flags, RATE_MCS_CHAN_WIDTH_MSK);
	if (bw == RATE_MCS_CHAN_WIDTH_320_VAL)
		bw += le32_get_bits(phy_data->data0,
				    IWL_RX_PHY_DATA0_EHT_BW320_SLOT);

	usig->common |= cpu_to_le32
		(FIELD_PREP(IEEE80211_RADIOTAP_EHT_USIG_COMMON_BW, bw));

	/* report the AMPDU-EOF bit on single frames */
	if (!queue && !(phy_info & IWL_RX_MPDU_PHY_AMPDU)) {
		rx_status->flag |= RX_FLAG_AMPDU_DETAILS;
		rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT_KNOWN;
		if (phy_data->data0 &
		    cpu_to_le32(IWL_RX_PHY_DATA0_EHT_DELIM_EOF))
			rx_status->flag |= RX_FLAG_AMPDU_EOF_BIT;
	}

	/* TODO: update agg data and decode eht phy data (task=sniffer) */

#define CHECK_TYPE(F)							\
	BUILD_BUG_ON(IEEE80211_RADIOTAP_HE_DATA1_FORMAT_ ## F !=	\
		     (RATE_MCS_HE_TYPE_ ## F >> RATE_MCS_HE_TYPE_POS))

	CHECK_TYPE(SU);
	CHECK_TYPE(EXT_SU);
	CHECK_TYPE(MU);
	CHECK_TYPE(TRIG);

	switch (u32_get_bits(rate_n_flags, RATE_MCS_HE_GI_LTF_MSK)) {
	case 0:
		if (he_type == RATE_MCS_HE_TYPE_TRIG) {
			rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_1_6;
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_1X;
		} else {
			rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_0_8;
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_2X;
		}
		break;
	case 1:
		rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_1_6;
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_2X;
		break;
	case 2:
		ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
		if (he_type == RATE_MCS_HE_TYPE_TRIG)
			rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_3_2;
		else
			rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_0_8;
		break;
	case 3:
		if (he_type != RATE_MCS_HE_TYPE_TRIG) {
			ltf = IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X;
			rx_status->eht.gi = NL80211_RATE_INFO_EHT_GI_3_2;
		}
		break;
	default:
		/* nothing here */
		break;
	}

	if (ltf != IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_UNKNOWN) {
		eht->known |= cpu_to_le32(IEEE80211_RADIOTAP_EHT_KNOWN_GI);
		eht->data[0] |= cpu_to_le32
			(FIELD_PREP(IEEE80211_RADIOTAP_EHT_DATA0_LTF,
				    ltf) |
			 FIELD_PREP(IEEE80211_RADIOTAP_EHT_DATA0_GI,
				    rx_status->eht.gi));
	}

	if (!phy_data->with_data) {
		eht->known |= cpu_to_le32(IEEE80211_RADIOTAP_EHT_KNOWN_NSS_S |
					  IEEE80211_RADIOTAP_EHT_KNOWN_BEAMFORMED_S);
		eht->data[7] |=
			le32_encode_bits(le32_get_bits(phy_data->rx_vec[2],
						       RX_NO_DATA_RX_VEC2_EHT_NSTS_MSK),
					 IEEE80211_RADIOTAP_EHT_DATA7_NSS_S);
		if (rate_n_flags & RATE_MCS_BF_MSK)
			eht->data[7] |=
				cpu_to_le32(IEEE80211_RADIOTAP_EHT_DATA7_BEAMFORMED_S);
	} else {
		eht->user_info[0] |=
			cpu_to_le32(IEEE80211_RADIOTAP_EHT_USER_INFO_MCS_KNOWN |
				    IEEE80211_RADIOTAP_EHT_USER_INFO_CODING_KNOWN |
				    IEEE80211_RADIOTAP_EHT_USER_INFO_NSS_KNOWN_O |
				    IEEE80211_RADIOTAP_EHT_USER_INFO_BEAMFORMING_KNOWN_O |
				    IEEE80211_RADIOTAP_EHT_USER_INFO_DATA_FOR_USER);

		if (rate_n_flags & RATE_MCS_BF_MSK)
			eht->user_info[0] |=
				cpu_to_le32(IEEE80211_RADIOTAP_EHT_USER_INFO_BEAMFORMING_O);

		if (rate_n_flags & RATE_MCS_LDPC_MSK)
			eht->user_info[0] |=
				cpu_to_le32(IEEE80211_RADIOTAP_EHT_USER_INFO_CODING);

		eht->user_info[0] |= cpu_to_le32
			(FIELD_PREP(IEEE80211_RADIOTAP_EHT_USER_INFO_MCS,
				    u32_get_bits(rate_n_flags,
						 RATE_VHT_MCS_RATE_CODE_MSK)) |
			 FIELD_PREP(IEEE80211_RADIOTAP_EHT_USER_INFO_NSS_O,
				    u32_get_bits(rate_n_flags,
						 RATE_MCS_NSS_MSK)));
	}
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

	/* This may be overridden by iwl_mld_rx_he() to HE_RU */
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

	/* TODO: RX_FLAG_MACTIME_IS_RTAP_TS64 (task=ptp)*/

	/* must be before L-SIG data */
	if (format == RATE_MCS_HE_MSK)
		iwl_mld_rx_he(mld, skb, phy_data, queue);

	iwl_mld_decode_lsig(skb, phy_data);

	rx_status->device_timestamp = phy_data->gp2_on_air_rise;

	/* TODO: adj time (task=ptp) */

	/* using TLV format and must be after all fixed len fields */
	if (format == RATE_MCS_EHT_MSK)
		iwl_mld_rx_eht(skb, phy_data, queue);

	/* TODO: radtio tap sniffer config (task=sniffer) */

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
static int iwl_mld_build_rx_skb(struct iwl_mld *mld, struct sk_buff *skb,
				struct ieee80211_hdr *hdr, u16 len,
				u8 crypt_len, struct iwl_rx_cmd_buffer *rxb)
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
VISIBLE_IF_IWLWIFI_KUNIT
bool
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
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_mld_is_dup);

static void iwl_mld_update_last_rx_timestamp(struct iwl_mld *mld, u8 baid)
{
	unsigned long now = jiffies;
	unsigned long timeout;
	struct iwl_mld_baid_data *ba_data;

	ba_data = rcu_dereference(mld->fw_id_to_ba[baid]);
	if (IWL_FW_CHECK(mld, !ba_data, "BAID %d not found in map\n", baid))
		return;

	if (!ba_data->timeout)
		return;

	/* To minimize cache bouncing between RX queues, avoid frequent updates
	 * to last_rx_timestamp. update it only when the timeout period has
	 * passed. The worst-case scenario is the session expiring after
	 * approximately 2 * timeout, which is negligible (the update is
	 * atomic).
	 */
	timeout = TU_TO_JIFFIES(ba_data->timeout);
	if (time_is_before_jiffies(ba_data->last_rx_timestamp + timeout))
		ba_data->last_rx_timestamp = now;
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
	u8 baid;

	if (mpdu_desc->status & cpu_to_le32(IWL_RX_MPDU_STATUS_SRC_STA_FOUND)) {
		u8 sta_id = le32_get_bits(mpdu_desc->status,
					  IWL_RX_MPDU_STATUS_STA_ID);

		if (IWL_FW_CHECK(mld,
				 sta_id >= mld->fw->ucode_capa.num_stations,
				 "rx_mpdu: invalid sta_id %d\n", sta_id))
			return NULL;

		link_sta = rcu_dereference(mld->fw_id_to_link_sta[sta_id]);
		if (!IS_ERR_OR_NULL(link_sta))
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

	baid = le32_get_bits(mpdu_desc->reorder_data,
			     IWL_RX_MPDU_REORDER_BAID_MASK);
	if (baid != IWL_RX_REORDER_DATA_INVALID_BAID)
		iwl_mld_update_last_rx_timestamp(mld, baid);

	return sta;
}

#define KEY_IDX_LEN 2

static int iwl_mld_rx_mgmt_prot(struct ieee80211_sta *sta,
				struct ieee80211_hdr *hdr,
				struct ieee80211_rx_status *rx_status,
				u32 mpdu_status,
				u32 mpdu_len)
{
	struct wireless_dev *wdev;
	struct iwl_mld_sta *mld_sta;
	struct iwl_mld_vif *mld_vif;
	u8 keyidx;
	struct ieee80211_key_conf *key;
	const u8 *frame = (void *)hdr;

	if ((mpdu_status & IWL_RX_MPDU_STATUS_SEC_MASK) ==
	     IWL_RX_MPDU_STATUS_SEC_NONE)
		return 0;

	/* For non-beacon, we don't really care. But beacons may
	 * be filtered out, and we thus need the firmware's replay
	 * detection, otherwise beacons the firmware previously
	 * filtered could be replayed, or something like that, and
	 * it can filter a lot - though usually only if nothing has
	 * changed.
	 */
	if (!ieee80211_is_beacon(hdr->frame_control))
		return 0;

	if (!sta)
		return -1;

	mld_sta = iwl_mld_sta_from_mac80211(sta);
	mld_vif = iwl_mld_vif_from_mac80211(mld_sta->vif);

	/* key mismatch - will also report !MIC_OK but we shouldn't count it */
	if (!(mpdu_status & IWL_RX_MPDU_STATUS_KEY_VALID))
		goto report;

	/* good cases */
	if (likely(mpdu_status & IWL_RX_MPDU_STATUS_MIC_OK &&
		   !(mpdu_status & IWL_RX_MPDU_STATUS_REPLAY_ERROR))) {
		rx_status->flag |= RX_FLAG_DECRYPTED;
		return 0;
	}

	/* both keys will have the same cipher and MIC length, use
	 * whichever one is available
	 */
	key = rcu_dereference(mld_vif->bigtks[0]);
	if (!key) {
		key = rcu_dereference(mld_vif->bigtks[1]);
		if (!key)
			goto report;
	}

	if (mpdu_len < key->icv_len + IEEE80211_GMAC_PN_LEN + KEY_IDX_LEN)
		goto report;

	/* get the real key ID */
	keyidx = frame[mpdu_len - key->icv_len - IEEE80211_GMAC_PN_LEN - KEY_IDX_LEN];
	/* and if that's the other key, look it up */
	if (keyidx != key->keyidx) {
		/* shouldn't happen since firmware checked, but be safe
		 * in case the MIC length is wrong too, for example
		 */
		if (keyidx != 6 && keyidx != 7)
			return -1;

		key = rcu_dereference(mld_vif->bigtks[keyidx - 6]);
		if (!key)
			goto report;
	}

	/* Report status to mac80211 */
	if (!(mpdu_status & IWL_RX_MPDU_STATUS_MIC_OK))
		ieee80211_key_mic_failure(key);
	else if (mpdu_status & IWL_RX_MPDU_STATUS_REPLAY_ERROR)
		ieee80211_key_replay(key);
report:
	wdev = ieee80211_vif_to_wdev(mld_sta->vif);
	if (wdev->netdev)
		cfg80211_rx_unprot_mlme_mgmt(wdev->netdev, (void *)hdr,
					     mpdu_len);

	return -1;
}

static int iwl_mld_rx_crypto(struct iwl_mld *mld,
			     struct ieee80211_sta *sta,
			     struct ieee80211_hdr *hdr,
			     struct ieee80211_rx_status *rx_status,
			     struct iwl_rx_mpdu_desc *desc, int queue,
			     u32 pkt_flags, u8 *crypto_len)
{
	u32 status = le32_to_cpu(desc->status);

	/* Drop UNKNOWN frames, unless in monitor mode (where we don't
	 * have the keys).
	 */
	if ((status & IWL_RX_MPDU_STATUS_SEC_MASK) ==
	    IWL_RX_MPDU_STATUS_SEC_UNKNOWN && !mld->monitor_on) {
		IWL_DEBUG_DROP(mld, "Dropping packets, bad enc status\n");
		return -1;
	}

	if (unlikely(ieee80211_is_mgmt(hdr->frame_control) &&
		     !ieee80211_has_protected(hdr->frame_control)))
		return iwl_mld_rx_mgmt_prot(sta, hdr, rx_status, status,
					    le16_to_cpu(desc->mpdu_len));

	if (!ieee80211_has_protected(hdr->frame_control) ||
	    (status & IWL_RX_MPDU_STATUS_SEC_MASK) ==
	    IWL_RX_MPDU_STATUS_SEC_NONE)
		return 0;

	switch (status & IWL_RX_MPDU_STATUS_SEC_MASK) {
	case IWL_RX_MPDU_STATUS_SEC_CCM:
	case IWL_RX_MPDU_STATUS_SEC_GCM:
		BUILD_BUG_ON(IEEE80211_CCMP_PN_LEN != IEEE80211_GCMP_PN_LEN);
		if (!(status & IWL_RX_MPDU_STATUS_MIC_OK)) {
			IWL_DEBUG_DROP(mld,
				       "Dropping packet, bad MIC (CCM/GCM)\n");
			return -1;
		}

		rx_status->flag |= RX_FLAG_DECRYPTED | RX_FLAG_MIC_STRIPPED;
		*crypto_len = IEEE80211_CCMP_HDR_LEN;
		return 0;
	case IWL_RX_MPDU_STATUS_SEC_TKIP:
		if (!(status & IWL_RX_MPDU_STATUS_ICV_OK))
			return -1;

		if (!(status & RX_MPDU_RES_STATUS_MIC_OK))
			rx_status->flag |= RX_FLAG_MMIC_ERROR;

		if (pkt_flags & FH_RSCSR_RADA_EN) {
			rx_status->flag |= RX_FLAG_ICV_STRIPPED;
			rx_status->flag |= RX_FLAG_MMIC_STRIPPED;
		}

		*crypto_len = IEEE80211_TKIP_IV_LEN;
		rx_status->flag |= RX_FLAG_DECRYPTED;
		return 0;
	case RX_MPDU_RES_STATUS_SEC_CMAC_GMAC_ENC:
		break;
	default:
		/* Sometimes we can get frames that were not decrypted
		 * because the firmware didn't have the keys yet. This can
		 * happen after connection where we can get multicast frames
		 * before the GTK is installed. Silently drop those frames.
		 */
		if (!is_multicast_ether_addr(hdr->addr1) &&
		    !mld->monitor_on && net_ratelimit())
			IWL_WARN(mld, "Unhandled alg: 0x%x\n", status);
	}

	return 0;
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
	u8 crypto_len = 0;
	u32 pkt_len = iwl_rx_packet_payload_len(pkt);
	u32 mpdu_len;
	enum iwl_mld_reorder_result reorder_res;
	struct ieee80211_rx_status *rx_status;

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

	/* TODO: update aggregation data (task=sniffer) */
	iwl_mld_rx_fill_status(mld, skb, &phy_data, mpdu_desc, hdr, queue);

	rcu_read_lock();

	sta = iwl_mld_rx_with_sta(mld, hdr, skb, mpdu_desc, pkt, queue, &drop);
	if (drop)
		goto drop;

	rx_status = IEEE80211_SKB_RXCB(skb);

	if (iwl_mld_rx_crypto(mld, sta, hdr, rx_status, mpdu_desc, queue,
			      le32_to_cpu(pkt->len_n_flags), &crypto_len))
		goto drop;

	if (iwl_mld_build_rx_skb(mld, skb, hdr, mpdu_len, crypto_len, rxb))
		goto drop;

	reorder_res = iwl_mld_reorder(mld, napi, queue, sta, skb, mpdu_desc);
	switch (reorder_res) {
	case IWL_MLD_PASS_SKB:
		break;
	case IWL_MLD_DROP_SKB:
		goto drop;
	case IWL_MLD_BUFFERED_SKB:
		goto out;
	default:
		WARN_ON(1);
		goto drop;
	}

	/* TODO: verify the following before passing frames to mac80211:
	 * 1. time sync frame
	 * 2. FPGA valid packet channel
	 * 3. mei_scan_filter
	 */

	iwl_mld_pass_packet_to_mac80211(mld, napi, skb, queue, sta);

	goto out;

drop:
	kfree_skb(skb);
out:
	rcu_read_unlock();
}

#define SYNC_RX_QUEUE_TIMEOUT (HZ * CPTCFG_IWL_TIMEOUT_FACTOR)
void iwl_mld_sync_rx_queues(struct iwl_mld *mld,
			    enum iwl_mld_internal_rxq_notif_type type,
			    const void *notif_payload, u32 notif_payload_size)
{
	u8 num_rx_queues = mld->trans->num_rx_queues;
	struct {
		struct iwl_rxq_sync_cmd sync_cmd;
		struct iwl_mld_internal_rxq_notif notif;
	} __packed cmd = {
		.sync_cmd.rxq_mask = cpu_to_le32(BIT(num_rx_queues) - 1),
		.sync_cmd.count =
			cpu_to_le32(sizeof(struct iwl_mld_internal_rxq_notif) +
				    notif_payload_size),
		.notif.type = type,
		.notif.cookie = mld->rxq_sync.cookie,
	};
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(DATA_PATH_GROUP, TRIGGER_RX_QUEUES_NOTIF_CMD),
		.data[0] = &cmd,
		.len[0] = sizeof(cmd),
		.data[1] = notif_payload,
		.len[1] = notif_payload_size,
	};
	int ret;

	/* size must be a multiple of DWORD */
	if (WARN_ON(cmd.sync_cmd.count & cpu_to_le32(3)))
		return;

	mld->rxq_sync.state = (1 << num_rx_queues) - 1;

	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (ret) {
		IWL_ERR(mld, "Failed to trigger RX queues sync (%d)\n", ret);
		goto out;
	}

	ret = wait_event_timeout(mld->rxq_sync.waitq,
				 READ_ONCE(mld->rxq_sync.state) == 0,
				 SYNC_RX_QUEUE_TIMEOUT);
	WARN_ONCE(!ret, "RXQ sync failed: state=0x%lx, cookie=%d\n",
		  mld->rxq_sync.state, mld->rxq_sync.cookie);

out:
	mld->rxq_sync.state = 0;
	mld->rxq_sync.cookie++;
}

void iwl_mld_handle_rx_queues_sync_notif(struct iwl_mld *mld,
					 struct napi_struct *napi,
					 struct iwl_rx_packet *pkt, int queue)
{
	struct iwl_rxq_sync_notification *notif;
	struct iwl_mld_internal_rxq_notif *internal_notif;
	u32 len = iwl_rx_packet_payload_len(pkt);
	size_t combined_notif_len = sizeof(*notif) + sizeof(*internal_notif);

	notif = (void *)pkt->data;
	internal_notif = (void *)notif->payload;

	if (IWL_FW_CHECK(mld, len < combined_notif_len,
			 "invalid notification size %d (%ld)\n",
			 len, combined_notif_len))
		return;

	len -= combined_notif_len;

	if (IWL_FW_CHECK(mld, mld->rxq_sync.cookie != internal_notif->cookie,
			 "received expired RX queue sync message (cookie=%d expected=%d q[%d])\n",
			 internal_notif->cookie, mld->rxq_sync.cookie, queue))
		return;

	switch (internal_notif->type) {
	case IWL_MLD_RXQ_EMPTY:
		IWL_FW_CHECK(mld, len,
			     "invalid empty notification size %d\n", len);
		break;
	case IWL_MLD_RXQ_NOTIF_DEL_BA:
		if (IWL_FW_CHECK(mld, len != sizeof(struct iwl_mld_delba_data),
				 "invalid delba notification size %d (%ld)\n",
				 len, sizeof(struct iwl_mld_delba_data)))
			break;
		iwl_mld_del_ba(mld, queue, (void *)internal_notif->payload);
		break;
	default:
		WARN_ON_ONCE(1);
	}

	IWL_FW_CHECK(mld, !test_and_clear_bit(queue, &mld->rxq_sync.state),
		     "RXQ sync: queue %d responded a second time!\n", queue);

	if (READ_ONCE(mld->rxq_sync.state) == 0)
		wake_up(&mld->rxq_sync.waitq);
}
