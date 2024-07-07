// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "scan.h"
#include "hcmd.h"

#include "fw/api/scan.h"
#include "fw/dbg.h"

#define IWL_SCAN_DWELL_ACTIVE 10
#define IWL_SCAN_DWELL_PASSIVE 110
#define IWL_SCAN_NUM_OF_FRAGS 3

/* adaptive dwell max budget time [TU] for full scan */
#define IWL_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN 300

/* adaptive dwell max budget time [TU] for directed scan */
#define IWL_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN 100

/* adaptive dwell default high band APs number */
#define IWL_SCAN_ADWELL_DEFAULT_HB_N_APS 8

/* adaptive dwell default low band APs number */
#define IWL_SCAN_ADWELL_DEFAULT_LB_N_APS 2

/* adaptive dwell default APs number for P2P social channels (1, 6, 11) */
#define IWL_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL 10

/* adaptive dwell number of APs override for P2P friendly GO channels */
#define IWL_SCAN_ADWELL_N_APS_GO_FRIENDLY 10

/* adaptive dwell number of APs override for P2P social channels */
#define IWL_SCAN_ADWELL_N_APS_SOCIAL_CHS 2

enum iwl_mld_scan_type {
	IWL_SCAN_TYPE_NOT_SET,
	IWL_SCAN_TYPE_UNASSOC,
	IWL_SCAN_TYPE_WILD,
	IWL_SCAN_TYPE_MILD,
	IWL_SCAN_TYPE_FRAGMENTED,
	IWL_SCAN_TYPE_FAST_BALANCE,
};

struct iwl_mld_scan_timing_params {
	u32 suspend_time;
	u32 max_out_time;
};

static const struct iwl_mld_scan_timing_params scan_timing[] = {
	[IWL_SCAN_TYPE_UNASSOC] = {
		.suspend_time = 0,
		.max_out_time = 0,
	},
	[IWL_SCAN_TYPE_WILD] = {
		.suspend_time = 30,
		.max_out_time = 120,
	},
	[IWL_SCAN_TYPE_MILD] = {
		.suspend_time = 120,
		.max_out_time = 120,
	},
	[IWL_SCAN_TYPE_FRAGMENTED] = {
		.suspend_time = 95,
		.max_out_time = 44,
	},
	[IWL_SCAN_TYPE_FAST_BALANCE] = {
		.suspend_time = 30,
		.max_out_time = 37,
	},
};

struct iwl_mld_scan_params {
	enum iwl_mld_scan_type type;
	u32 n_channels;
	u16 delay;
	int n_ssids;
	struct cfg80211_ssid *ssids;
	struct ieee80211_channel **channels;
	u32 flags;
	u8 *mac_addr;
	u8 *mac_addr_mask;
	bool no_cck;
	bool pass_all;
	int n_match_sets;
	struct iwl_scan_probe_req preq;
	struct cfg80211_match_set *match_sets;
	int n_scan_plans;
	struct cfg80211_sched_scan_plan *scan_plans;
	bool iter_notif;
	/* TODO: respect_p2p_go (task=p2p)*/
	s8 tsf_report_link_id;
	u8 bssid[ETH_ALEN] __aligned(2);
};

static u8 *
iwl_mld_scan_add_2ghz_elems(struct iwl_mld *mld, const u8 *ies,
			    size_t len, u8 *const pos)
{
	static const u8 before_ds_params[] = {
	    WLAN_EID_SSID,
	    WLAN_EID_SUPP_RATES,
	    WLAN_EID_REQUEST,
	    WLAN_EID_EXT_SUPP_RATES,
	};
	size_t offs;
	u8 *newpos = pos;

	offs = ieee80211_ie_split(ies, len,
				  before_ds_params,
				  ARRAY_SIZE(before_ds_params),
				  0);

	memcpy(newpos, ies, offs);
	newpos += offs;

	/* Add a placeholder for DS Parameter Set element */
	*newpos++ = WLAN_EID_DS_PARAMS;
	*newpos++ = 1;
	*newpos++ = 0;

	memcpy(newpos, ies + offs, len - offs);
	newpos += len - offs;

	return newpos;
}

static void
iwl_mld_scan_add_tpc_report_elem(u8 *pos)
{
	pos[0] = WLAN_EID_VENDOR_SPECIFIC;
	pos[1] = WFA_TPC_IE_LEN - 2;
	pos[2] = (WLAN_OUI_MICROSOFT >> 16) & 0xff;
	pos[3] = (WLAN_OUI_MICROSOFT >> 8) & 0xff;
	pos[4] = WLAN_OUI_MICROSOFT & 0xff;
	pos[5] = WLAN_OUI_TYPE_MICROSOFT_TPC;
	pos[6] = 0;
	/* pos[7] - tx power will be inserted by the FW */
	pos[7] = 0;
	pos[8] = 0;
}

static u32
iwl_mld_scan_ooc_priority(enum iwl_mld_scan_status scan_status)
{
	if (scan_status == IWL_MLD_SCAN_REGULAR)
		return IWL_SCAN_PRIORITY_EXT_6;
	if (scan_status == IWL_MLD_SCAN_INT_MLO)
		return IWL_SCAN_PRIORITY_EXT_4;

	return IWL_SCAN_PRIORITY_EXT_2;
}

static inline bool
iwl_mld_scan_is_regular(struct iwl_mld_scan_params *params)
{
	return params->n_scan_plans == 1 &&
		params->scan_plans[0].iterations == 1;
}

static bool
iwl_mld_scan_is_fragmented(enum iwl_mld_scan_type type)
{
	return (type == IWL_SCAN_TYPE_FRAGMENTED ||
		type == IWL_SCAN_TYPE_FAST_BALANCE);
}

static int
iwl_mld_scan_uid_by_status(struct iwl_mld *mld, int status)
{
	for (int i = 0; i < ARRAY_SIZE(mld->scan.uid_status); i++)
		if (mld->scan.uid_status[i] == status)
			return i;

	return -ENOENT;
}

static const char *
iwl_mld_scan_ebs_status_str(enum iwl_scan_ebs_status status)
{
	switch (status) {
	case IWL_SCAN_EBS_SUCCESS:
		return "successful";
	case IWL_SCAN_EBS_INACTIVE:
		return "inactive";
	case IWL_SCAN_EBS_FAILED:
	case IWL_SCAN_EBS_CHAN_NOT_FOUND:
	default:
		return "failed";
	}
}

static int
iwl_mld_scan_ssid_exist(u8 *ssid, u8 ssid_len, struct iwl_ssid_ie *ssid_list)
{
	for (int i = 0; i < PROBE_OPTION_MAX; i++) {
		if (!ssid_list[i].len)
			return -1;
		if (ssid_list[i].len == ssid_len &&
		    !memcmp(ssid_list->ssid, ssid, ssid_len))
			return i;
	}

	return -1;
}

static inline bool
iwl_mld_scan_fits(struct iwl_mld *mld, int n_ssids,
		  struct ieee80211_scan_ies *ies, int n_channels)
{
	return ((n_ssids <= PROBE_OPTION_MAX) &&
		(n_channels <= mld->fw->ucode_capa.n_scan_channels) &
		(ies->common_ie_len + ies->len[NL80211_BAND_2GHZ] +
		 ies->len[NL80211_BAND_5GHZ] <=
		 iwl_mld_scan_max_template_size()));
}

static void
iwl_mld_scan_build_probe_req(struct iwl_mld *mld, struct ieee80211_vif *vif,
			     struct ieee80211_scan_ies *ies,
			     struct iwl_mld_scan_params *params)
{
	struct ieee80211_mgmt *frame = (void *)params->preq.buf;
	u8 *pos, *newpos;
	const u8 *mac_addr = params->flags & NL80211_SCAN_FLAG_RANDOM_ADDR ?
		params->mac_addr : NULL;

	if (mac_addr)
		get_random_mask_addr(frame->sa, mac_addr,
				     params->mac_addr_mask);
	else
		memcpy(frame->sa, vif->addr, ETH_ALEN);

	frame->frame_control = cpu_to_le16(IEEE80211_STYPE_PROBE_REQ);
	eth_broadcast_addr(frame->da);
	ether_addr_copy(frame->bssid, params->bssid);
	frame->seq_ctrl = 0;

	pos = frame->u.probe_req.variable;
	*pos++ = WLAN_EID_SSID;
	*pos++ = 0;

	params->preq.mac_header.offset = 0;
	params->preq.mac_header.len = cpu_to_le16(24 + 2);

	/* Insert DS parameter set element on 2.4 GHz band */
	newpos = iwl_mld_scan_add_2ghz_elems(mld,
					     ies->ies[NL80211_BAND_2GHZ],
					     ies->len[NL80211_BAND_2GHZ],
					     pos);
	params->preq.band_data[0].offset = cpu_to_le16(pos - params->preq.buf);
	params->preq.band_data[0].len = cpu_to_le16(newpos - pos);
	pos = newpos;

	memcpy(pos, ies->ies[NL80211_BAND_5GHZ],
	       ies->len[NL80211_BAND_5GHZ]);
	params->preq.band_data[1].offset = cpu_to_le16(pos - params->preq.buf);
	params->preq.band_data[1].len =
	    cpu_to_le16(ies->len[NL80211_BAND_5GHZ]);
	pos += ies->len[NL80211_BAND_5GHZ];

	/* TODO: add 6GHz IEs */

	memcpy(pos, ies->common_ies, ies->common_ie_len);
	params->preq.common_data.offset = cpu_to_le16(pos - params->preq.buf);

	iwl_mld_scan_add_tpc_report_elem(pos + ies->common_ie_len);
	params->preq.common_data.len = cpu_to_le16(ies->common_ie_len +
						   WFA_TPC_IE_LEN);
}

static u16
iwl_mld_scan_get_cmd_gen_flags(struct iwl_mld *mld,
			       struct iwl_mld_scan_params *params,
			       struct ieee80211_vif *vif,
			       enum iwl_mld_scan_status scan_status)
{
	u16 flags = 0;

	/* If no direct SSIDs are provided perform a passive scan. Otherwise,
	 * if there is a single SSID which is not the broadcast SSID, assume
	 * that the scan is intended for roaming purposes and thus enable Rx on
	 * all chains to improve chances of hearing the beacons/probe responses.
	 */
	if (params->n_ssids == 0)
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_FORCE_PASSIVE;
	else if (params->n_ssids == 1 && params->ssids[0].ssid_len)
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_USE_ALL_RX_CHAINS;

	if (params->pass_all)
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_PASS_ALL;
	else
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_MATCH;

	if (iwl_mld_scan_is_fragmented(params->type))
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_FRAGMENTED_LMAC1;

	if (!iwl_mld_scan_is_regular(params))
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_PERIODIC;

	/* TODO: check sched_scan_pass_all == SCHED_SCAN_PASS_ALL_ENABLED */
	if (params->iter_notif)
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_NTFY_ITER_COMPLETE;

	if (scan_status == IWL_MLD_SCAN_SCHED ||
	    scan_status == IWL_MLD_SCAN_NETDETECT)
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_PREEMPTIVE;

	if (params->flags & (NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP |
			     NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE |
			     NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME))
		flags |= IWL_UMAC_SCAN_GEN_FLAGS_V2_OCE;

	/* TODO: IWL_UMAC_SCAN_GEN_FLAGS_V2_TRIGGER_UHB_SCAN */

	/* TODO: IWL_UMAC_SCAN_GEN_FLAGS_V2_6GHZ_PASSIVE_SCAN */

	return flags;
}

static u8
iwl_mld_scan_get_cmd_gen_flags2(struct iwl_mld *mld,
				struct iwl_mld_scan_params *params,
				struct ieee80211_vif *vif, u16 gen_flags)
{
	u8 flags = 0;

	/* TODO: respect_p2p_go (task=p2p)
	 * IWL_UMAC_SCAN_GEN_PARAMS_FLAGS2_RESPECT_P2P_GO_LB |
	 * IWL_UMAC_SCAN_GEN_PARAMS_FLAGS2_RESPECT_P2P_GO_HB
	 */

	/* TODO: 6GHz: IWL_UMAC_SCAN_GEN_PARAMS_FLAGS2_DONT_TOGGLE_ANT */

	/* TODO: ACS IWL_UMAC_SCAN_GEN_FLAGS2_COLLECT_CHANNEL_STATS (task=AP/p2p) */

	return flags;
}

static void
iwl_mld_scan_cmd_set_dwell(struct iwl_mld *mld,
			   struct iwl_scan_general_params_v11 *gp,
			   struct iwl_mld_scan_params *params)
{
	const struct iwl_mld_scan_timing_params *timing =
		&scan_timing[params->type];

	gp->adwell_default_social_chn =
	    IWL_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL;
	gp->adwell_default_2g = IWL_SCAN_ADWELL_DEFAULT_LB_N_APS;
	gp->adwell_default_5g = IWL_SCAN_ADWELL_DEFAULT_HB_N_APS;

	if (params->n_ssids && params->ssids[0].ssid_len)
		gp->adwell_max_budget =
			cpu_to_le16(IWL_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN);
	else
		gp->adwell_max_budget =
			cpu_to_le16(IWL_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN);

	gp->scan_priority = cpu_to_le32(IWL_SCAN_PRIORITY_EXT_6);

	gp->max_out_of_time[SCAN_LB_LMAC_IDX] = cpu_to_le32(timing->max_out_time);
	gp->suspend_time[SCAN_LB_LMAC_IDX] = cpu_to_le32(timing->suspend_time);

	gp->active_dwell[SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
	gp->passive_dwell[SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
	gp->active_dwell[SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
	gp->passive_dwell[SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;

	IWL_DEBUG_SCAN(mld,
		       "Scan: adwell_max_budget=%d max_out_of_time=%d suspend_time=%d\n",
		       gp->adwell_max_budget,
		       gp->max_out_of_time[SCAN_LB_LMAC_IDX],
		       gp->suspend_time[SCAN_LB_LMAC_IDX]);
}

static void
iwl_mld_scan_cmd_set_gen_params(struct iwl_mld *mld,
				struct iwl_mld_scan_params *params,
				struct ieee80211_vif *vif,
				struct iwl_scan_general_params_v11 *gp,
				enum iwl_mld_scan_status scan_status)
{
	u16 gen_flags = iwl_mld_scan_get_cmd_gen_flags(mld, params, vif,
						       scan_status);
	u8 gen_flags2 = iwl_mld_scan_get_cmd_gen_flags2(mld, params, vif,
							gen_flags);

	IWL_DEBUG_SCAN(mld, "General: flags=0x%x, flags2=0x%x\n",
		       gen_flags, gen_flags2);

	gp->flags = cpu_to_le16(gen_flags);
	gp->flags2 = gen_flags2;

	iwl_mld_scan_cmd_set_dwell(mld, gp, params);

	if (gen_flags & IWL_UMAC_SCAN_GEN_FLAGS_V2_FRAGMENTED_LMAC1)
		gp->num_of_fragments[SCAN_LB_LMAC_IDX] = IWL_SCAN_NUM_OF_FRAGS;

	/* TODO: set gp->scan_start_mac_or_link_id based on link_info */
}

static int
iwl_mld_scan_cmd_set_sched_params(struct iwl_mld_scan_params *params,
				  struct iwl_scan_umac_schedule *schedule,
				  __le16 *delay)
{
	if (WARN_ON(!params->n_scan_plans ||
		    params->n_scan_plans > IWL_MAX_SCHED_SCAN_PLANS))
		return -EINVAL;

	for (int i = 0; i < params->n_scan_plans; i++) {
		struct cfg80211_sched_scan_plan *scan_plan =
		    &params->scan_plans[i];

		schedule[i].iter_count = scan_plan->iterations;
		schedule[i].interval =
		    cpu_to_le16(scan_plan->interval);
	}

	/* If the number of iterations of the last scan plan is set to zero,
	 * it should run infinitely. However, this is not always the case.
	 * For example, when regular scan is requested the driver sets one scan
	 * plan with one iteration.
	 */
	if (!schedule[params->n_scan_plans - 1].iter_count)
		schedule[params->n_scan_plans - 1].iter_count = 0xff;

	*delay = cpu_to_le16(params->delay);

	return 0;
}

/* We insert the SSIDs in an inverted order, because the FW will
 * invert it back.
 */
static void
iwl_mld_scan_cmd_build_ssids(struct iwl_mld_scan_params *params,
			     struct iwl_ssid_ie *ssids, u32 *ssid_bitmap)
{
	int i, j;
	int index;
	u32 tmp_bitmap = 0;

	/* copy SSIDs from match list. iwl_config_sched_scan_profiles()
	 * uses the order of these ssids to config match list.
	 */
	for (i = 0, j = params->n_match_sets - 1;
	     j >= 0 && i < PROBE_OPTION_MAX;
	     i++, j--) {
		/* skip empty SSID match_sets */
		if (!params->match_sets[j].ssid.ssid_len)
			continue;

		ssids[i].id = WLAN_EID_SSID;
		ssids[i].len = params->match_sets[j].ssid.ssid_len;
		memcpy(ssids[i].ssid, params->match_sets[j].ssid.ssid,
		       ssids[i].len);
	}

	/* add SSIDs from scan SSID list */
	for (j = params->n_ssids - 1;
	     j >= 0 && i < PROBE_OPTION_MAX;
	     i++, j--) {
		index = iwl_mld_scan_ssid_exist(params->ssids[j].ssid,
						params->ssids[j].ssid_len,
						ssids);
		if (index < 0) {
			ssids[i].id = WLAN_EID_SSID;
			ssids[i].len = params->ssids[j].ssid_len;
			memcpy(ssids[i].ssid, params->ssids[j].ssid,
			       ssids[i].len);
			tmp_bitmap |= BIT(i);
		} else {
			tmp_bitmap |= BIT(index);
		}
	}

	if (ssid_bitmap)
		*ssid_bitmap = tmp_bitmap;
}

static void
iwl_mld_scan_cmd_set_probe_params(struct iwl_mld_scan_params *params,
				  struct iwl_scan_probe_params_v4 *pp,
				  u32 *bitmap_ssid)
{
	pp->preq = params->preq;
	iwl_mld_scan_cmd_build_ssids(params, pp->direct_scan, bitmap_ssid);
}

static inline bool
iwl_mld_scan_use_ebs(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	const struct iwl_ucode_capabilities *capa = &mld->fw->ucode_capa;
	bool low_latency = false;

	/* TODO: get low_latency mode (task=low_latency) */

	/* We can only use EBS if:
	 *	1. the feature is supported.
	 *	2. the last EBS was successful.
	 *	3. it's not a p2p find operation.
	 *	4. we are not in low latency mode,
	 *	   or if fragmented ebs is supported by the FW
	 *	5. the VIF is not an AP interface (scan wants survey results)
	 */
	return ((capa->flags & IWL_UCODE_TLV_FLAGS_EBS_SUPPORT) &&
		!mld->scan.last_ebs_failed &&
		vif->type != NL80211_IFTYPE_P2P_DEVICE &&
		(!low_latency || fw_has_api(capa, IWL_UCODE_TLV_API_FRAG_EBS)) &&
		ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_AP);
}

static u8
iwl_mld_scan_cmd_set_chan_flags(struct iwl_mld *mld,
				struct iwl_mld_scan_params *params,
				struct ieee80211_vif *vif)
{
	u8 flags = 0;

	flags |= IWL_SCAN_CHANNEL_FLAG_ENABLE_CHAN_ORDER;

	if (iwl_mld_scan_use_ebs(mld, vif))
		flags |= IWL_SCAN_CHANNEL_FLAG_EBS |
			 IWL_SCAN_CHANNEL_FLAG_EBS_ACCURATE |
			 IWL_SCAN_CHANNEL_FLAG_CACHE_ADD;

	/* set fragmented ebs for fragmented scan */
	if (iwl_mld_scan_is_fragmented(params->type))
		flags |= IWL_SCAN_CHANNEL_FLAG_EBS_FRAG;

	/* TODO: IWL_SCAN_CHANNEL_FLAG_FORCE_EBS (task=p2p) */

	return flags;
}

static void
iwl_mld_scan_cmd_set_channels(struct iwl_mld *mld,
			      struct ieee80211_channel **channels,
			      struct iwl_scan_channel_params_v7 *cp,
			      int n_channels, u32 flags,
			      enum nl80211_iftype vif_type)
{
	for (int i = 0; i < n_channels; i++) {
		enum nl80211_band band = channels[i]->band;
		struct iwl_scan_channel_cfg_umac *cfg = &cp->channel_config[i];
		u8 iwl_band = iwl_mld_nl80211_band_to_fw(band);

		/* TODO: scan_ch_n_aps_flag (task=p2p) */
		cfg->flags = cpu_to_le32(flags);
		cfg->channel_num = channels[i]->hw_value;
		if (cfg80211_channel_is_psc(channels[i]))
			cfg->flags = 0;
		cfg->v2.iter_count = 1;
		cfg->v2.iter_interval = 0;
		cfg->flags |= cpu_to_le32(iwl_band <<
					  IWL_CHAN_CFG_FLAGS_BAND_POS);
	}
}

static void
iwl_mld_scan_cmd_set_chan_params(struct iwl_mld *mld,
				 struct iwl_mld_scan_params *params,
				 struct ieee80211_vif *vif,
				 struct iwl_scan_channel_params_v7 *cp,
				 u32 channel_cfg_flags)
{
	cp->flags = iwl_mld_scan_cmd_set_chan_flags(mld, params, vif);
	cp->count = params->n_channels;
	cp->n_aps_override[0] = IWL_SCAN_ADWELL_N_APS_GO_FRIENDLY;
	cp->n_aps_override[1] = IWL_SCAN_ADWELL_N_APS_SOCIAL_CHS;

	iwl_mld_scan_cmd_set_channels(mld, params->channels, cp,
				      params->n_channels, channel_cfg_flags,
				      vif->type);

	/* TODO: enable_6ghz_passive */
}

static int
iwl_mld_scan_build_cmd(struct iwl_mld *mld, struct ieee80211_vif *vif,
		       struct iwl_mld_scan_params *params,
		       enum iwl_mld_scan_status scan_status)
{
	struct iwl_scan_req_umac_v17 *cmd = mld->scan.cmd;
	struct iwl_scan_req_params_v17 *scan_p = &cmd->scan_params;
	u32 bitmap_ssid = 0;
	int uid, ret;

	memset(mld->scan.cmd, 0, mld->scan.cmd_size);

	/* TODO: scan filter (task=mei)*/

	uid = iwl_mld_scan_uid_by_status(mld, 0);
	if (uid < 0)
		return uid;

	cmd->uid = cpu_to_le32(uid);
	cmd->ooc_priority =
		cpu_to_le32(iwl_mld_scan_ooc_priority(scan_status));

	iwl_mld_scan_cmd_set_gen_params(mld, params, vif,
					&scan_p->general_params, scan_status);

	ret = iwl_mld_scan_cmd_set_sched_params(params,
						scan_p->periodic_params.schedule,
						&scan_p->periodic_params.delay);
	if (ret)
		return ret;

	iwl_mld_scan_cmd_set_probe_params(params, &scan_p->probe_params,
					  &bitmap_ssid);
	iwl_mld_scan_cmd_set_chan_params(mld, params, vif,
					 &scan_p->channel_params,
					 bitmap_ssid);
	/* TODO: 6GHz support */

	return uid;
}

static int
_iwl_mld_single_scan_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
			   struct cfg80211_scan_request *req,
			   struct ieee80211_scan_ies *ies,
			   enum iwl_mld_scan_status scan_status)
{
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LONG_GROUP, SCAN_REQ_UMAC),
		.len = { mld->scan.cmd_size, },
		.data = { mld->scan.cmd, },
		.dataflags = { IWL_HCMD_DFL_NOCOPY, },
	};
	struct cfg80211_sched_scan_plan scan_plan = {.iterations = 1};
	struct iwl_mld_scan_params params = {};
	int ret, uid;

	/* we should have failed registration if scan_cmd was NULL */
	if (WARN_ON(!mld->scan.cmd))
		return -ENOMEM;

	if (!iwl_mld_scan_fits(mld, req->n_ssids, ies, req->n_channels))
		return -ENOBUFS;

	/* TODO: fill scan type based on vif type/low latency/traffic load
	 * for now we can just assume TYPE_UNASSOC (task=low_latency)
	 */
	params.type = IWL_SCAN_TYPE_UNASSOC;
	params.n_ssids = req->n_ssids;
	params.flags = req->flags;
	params.n_channels = req->n_channels;
	params.delay = 0;
	params.ssids = req->ssids;
	params.channels = req->channels;
	params.mac_addr = req->mac_addr;
	params.mac_addr_mask = req->mac_addr_mask;
	params.no_cck = req->no_cck;
	params.pass_all = true;
	params.n_match_sets = 0;
	params.match_sets = NULL;
	params.scan_plans = &scan_plan;
	params.n_scan_plans = 1;

	ether_addr_copy(params.bssid, req->bssid);

	/* TODO: fill_respect_p2p_go (task=p2p)*/

	if (req->duration)
		params.iter_notif = true;

	params.tsf_report_link_id = req->tsf_report_link_id;
	if (params.tsf_report_link_id < 0) {
		if (vif->active_links)
			params.tsf_report_link_id = __ffs(vif->active_links);
		else
			params.tsf_report_link_id = 0;
	}

	iwl_mld_scan_build_probe_req(mld, vif, ies, &params);

	uid = iwl_mld_scan_build_cmd(mld, vif, &params, scan_status);
	if (uid < 0)
		return uid;

	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (ret) {
		IWL_ERR(mld, "Scan failed! ret %d\n", ret);
		return ret;
	}

	IWL_DEBUG_SCAN(mld, "Scan request send success: status=%u, uid=%u\n",
		       scan_status, uid);

	mld->scan.uid_status[uid] = scan_status;
	mld->scan.status |= scan_status;

	return 0;
}

static int
iwl_mld_scan_send_abort_cmd_status(struct iwl_mld *mld, int uid, u32 *status)
{
	struct iwl_umac_scan_abort abort_cmd = {
		.uid = cpu_to_le32(uid),
	};
	struct iwl_host_cmd cmd = {
		.id = WIDE_ID(LONG_GROUP, SCAN_ABORT_UMAC),
		.flags = CMD_WANT_SKB,
		.data = { &abort_cmd },
		.len[0] = sizeof(abort_cmd),
	};
	struct iwl_rx_packet *pkt;
	struct iwl_cmd_response *resp;
	u32 resp_len;
	int ret;

	ret = iwl_mld_send_cmd(mld, &cmd);
	if (ret)
		return ret;

	pkt = cmd.resp_pkt;

	resp_len = iwl_rx_packet_payload_len(pkt);
	if (IWL_FW_CHECK(mld, resp_len != sizeof(*resp),
			 "Scan Abort: unexpected response length %d\n",
			 resp_len)) {
		ret = -EIO;
		goto out;
	}

	resp = (void *)pkt->data;
	*status = le32_to_cpu(resp->status);

out:
	iwl_free_resp(&cmd);
	return ret;
}

static int
iwl_mld_scan_abort(struct iwl_mld *mld, int type, bool *wait)
{
	int uid, ret;
	enum iwl_umac_scan_abort_status status;

	*wait = true;

	/* We should always get a valid index here, because we already
	 * checked that this type of scan was running in the generic
	 * code.
	 */
	uid = iwl_mld_scan_uid_by_status(mld, type);
	if (WARN_ON_ONCE(uid < 0))
		return uid;

	IWL_DEBUG_SCAN(mld, "Sending scan abort, uid %u\n", uid);

	ret = iwl_mld_scan_send_abort_cmd_status(mld, uid, &status);

	mld->scan.uid_status[uid] = type << IWL_MLD_SCAN_STOPPING_SHIFT;

	IWL_DEBUG_SCAN(mld, "Scan abort: ret=%d status=%u\n", ret, status);

	/* We don't need to wait to scan complete in the following cases:
	 * 1. Driver failed to send the scan abort cmd.
	 * 2. The FW is no longer familiar with the scan that needs to be
	 *    stopped. It is expected that the scan complete notification was
	 *    already received but not yet processed.
	 *
	 * In both cases the flow should continue similar to the case that the
	 * scan was really aborted.
	 */
	if (ret || status == IWL_UMAC_SCAN_ABORT_STATUS_NOT_FOUND)
		*wait = false;

	return ret;
}

static int
iwl_mld_scan_stop_wait(struct iwl_mld *mld, int type)
{
	struct iwl_notification_wait wait_scan_done;
	static const u16 scan_comp_notif[] = { SCAN_COMPLETE_UMAC };
	bool wait = true;
	int ret;

	iwl_init_notification_wait(&mld->notif_wait, &wait_scan_done,
				   scan_comp_notif,
				   ARRAY_SIZE(scan_comp_notif),
				   NULL, NULL);

	IWL_DEBUG_SCAN(mld, "Preparing to stop scan, type=%x\n", type);

	ret = iwl_mld_scan_abort(mld, type, &wait);
	if (ret) {
		IWL_DEBUG_SCAN(mld, "couldn't stop scan type=%d\n", type);
		goto return_no_wait;
	}

	if (!wait) {
		IWL_DEBUG_SCAN(mld, "no need to wait for scan type=%d\n", type);
		goto return_no_wait;
	}

	return iwl_wait_notification(&mld->notif_wait, &wait_scan_done, HZ);

return_no_wait:
	iwl_remove_notification(&mld->notif_wait, &wait_scan_done);
	return ret;
}

int iwl_mld_scan_stop(struct iwl_mld *mld, int type, bool notify)
{
	int ret;

	IWL_DEBUG_SCAN(mld,
		       "Request to stop scan: type=0x%x, status=0x%x\n",
		       type, mld->scan.status);

	if (!(mld->scan.status & type))
		return 0;

	/* TODO: consider to return here in rfkill (task=rfkill) */

	ret = iwl_mld_scan_stop_wait(mld, type);
	if (!ret)
		mld->scan.status |= type << IWL_MLD_SCAN_STOPPING_SHIFT;
	else
		IWL_DEBUG_SCAN(mld, "Failed to stop scan\n");

	/* Clear the scan status so the next scan requests will
	 * succeed and mark the scan as stopping, so that the Rx
	 * handler doesn't do anything, as the scan was stopped from
	 * above.
	 */
	mld->scan.status &= ~type;

	if (type == IWL_MLD_SCAN_REGULAR) {
		if (notify) {
			struct cfg80211_scan_info info = {
			    .aborted = true,
			};

			ieee80211_scan_completed(mld->hw, &info);
		}
	}
	/* TODO: ieee80211_sched_scan_stopped */
	/* TODO: SCHED_SCAN_PASS_ALL_DISABLED */

	return ret;
}

int iwl_mld_regular_scan_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
			       struct cfg80211_scan_request *req,
			       struct ieee80211_scan_ies *ies)
{
	return _iwl_mld_single_scan_start(mld, vif, req, ies,
					  IWL_MLD_SCAN_REGULAR);
}

void iwl_mld_handle_scan_iter_complete_notif(struct iwl_mld *mld,
					     struct iwl_rx_packet *pkt)
{
	struct iwl_umac_scan_iter_complete_notif *notif = (void *)pkt->data;
	u32 uid = __le32_to_cpu(notif->uid);

	if (mld->scan.uid_status[uid] == IWL_MLD_SCAN_REGULAR)
		mld->scan.start_tsf = le64_to_cpu(notif->start_tsf);

	IWL_DEBUG_SCAN(mld,
		       "UMAC Scan iteration complete: status=0x%x scanned_channels=%d\n",
		       notif->status, notif->scanned_channels);

	IWL_DEBUG_SCAN(mld,
		       "UMAC Scan iteration complete: scan started at %llu (TSF)\n",
		       mld->scan.start_tsf);
}

void iwl_mld_handle_scan_complete_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt)
{
	struct iwl_umac_scan_complete *notif = (void *)pkt->data;
	bool aborted = (notif->status == IWL_SCAN_OFFLOAD_ABORTED);
	u32 uid = __le32_to_cpu(notif->uid);

	/* TODO: scan filter (task=mei)*/

	IWL_DEBUG_SCAN(mld,
		       "Scan completed: uid=%u type=%u, status=%s, EBS=%s\n",
		       uid, mld->scan.uid_status[uid],
		       notif->status == IWL_SCAN_OFFLOAD_COMPLETED ?
				"completed" : "aborted",
		       iwl_mld_scan_ebs_status_str(notif->ebs_status));
	IWL_DEBUG_SCAN(mld, "Scan completed: scan_status=0x%x\n",
		       mld->scan.status);
	IWL_DEBUG_SCAN(mld,
		       "Scan completed: line=%u, iter=%u, elapsed time=%u\n",
		       notif->last_schedule, notif->last_iter,
		       __le32_to_cpu(notif->time_from_last_iter));

	if (WARN_ON(!(mld->scan.uid_status[uid] & mld->scan.status)))
		return;

	/* if the scan is already stopping, we don't need to notify mac80211 */
	if (mld->scan.uid_status[uid] == IWL_MLD_SCAN_REGULAR) {
		struct cfg80211_scan_info info = {
			.aborted = aborted,
			.scan_start_tsf = mld->scan.start_tsf,
		};

		/* TODO: set info.tsf_bssid from link_info->bssid */

		ieee80211_scan_completed(mld->hw, &info);
	}

	/* TODO: mld->scan.uid_status[uid] == IWL_MLD_SCAN_SCHED */
	/* TODO: mld->scan.uid_status[uid] == IWL_MLD_SCAN_INT_MLO (task=mlo)*/

	mld->scan.status &= ~mld->scan.uid_status[uid];

	IWL_DEBUG_SCAN(mld, "Scan completed: after update: scan_status=0x%x\n",
		       mld->scan.status);

	mld->scan.uid_status[uid] = 0;

	if (notif->ebs_status != IWL_SCAN_EBS_SUCCESS &&
	    notif->ebs_status != IWL_SCAN_EBS_INACTIVE)
		mld->scan.last_ebs_failed = true;

	/* TODO: trig_link_selection_work (task=mlo)*/
}

int iwl_mld_alloc_scan_cmd(struct iwl_mld *mld)
{
	u8 scan_cmd_ver = iwl_fw_lookup_cmd_ver(mld->fw, SCAN_REQ_UMAC,
						IWL_FW_CMD_VER_UNKNOWN);
	size_t scan_cmd_size;

	if (scan_cmd_ver == 17) {
		scan_cmd_size = sizeof(struct iwl_scan_req_umac_v17);
	} else {
		IWL_ERR(mld, "Unexpected scan cmd version %d\n", scan_cmd_ver);
		return -EINVAL;
	}

	mld->scan.cmd = kmalloc(scan_cmd_size, GFP_KERNEL);
	if (!mld->scan.cmd)
		return -ENOMEM;

	mld->scan.cmd_size = scan_cmd_size;

	return 0;
}
