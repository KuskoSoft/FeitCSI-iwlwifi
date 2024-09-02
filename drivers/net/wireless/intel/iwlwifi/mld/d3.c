// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mld.h"

#include "d3.h"
#include "power.h"
#include "hcmd.h"
#include "iface.h"
#include "mcc.h"

#include "fw/api/d3.h"
#include "fw/api/offload.h"
#include "fw/dbg.h"

/**
 * enum iwl_mld_d3_notif - d3 notifications
 * @IWL_D3_NOTIF_WOWLAN_INFO: WOWLAN_INFO_NOTIF is expected/was received
 * @IWL_D3_NOTIF_WOWLAN_WAKE_PKT: WOWLAN_WAKE_PKT_NOTIF is expected/was received
 * @IWL_D3_NOTIF_PROT_OFFLOAD: PROT_OFFLOAD_NOTIF is expected/was received
 * @IWL_D3_ND_MATCH_INFO: OFFLOAD_MATCH_INFO_NOTIF is expected/was received
 * @IWL_D3_NOTIF_D3_END_NOTIF: D3_END_NOTIF is expected/was received
 */
enum iwl_mld_d3_notif {
	IWL_D3_NOTIF_WOWLAN_INFO =	BIT(0),
	IWL_D3_NOTIF_WOWLAN_WAKE_PKT =	BIT(1),
	IWL_D3_NOTIF_PROT_OFFLOAD =	BIT(2),
	IWL_D3_ND_MATCH_INFO      =     BIT(3),
	IWL_D3_NOTIF_D3_END_NOTIF =	BIT(4)
};

/**
 * struct iwl_mld_wowlan_status - contains wowlan status data from
 * all wowlan notifications
 * @wakeup_reasons: wakeup reasons, see &enum iwl_wowlan_wakeup_reason
 */
struct iwl_mld_wowlan_status {
	u32 wakeup_reasons;
};

#define NETDETECT_QUERY_BUF_LEN \
	(sizeof(struct iwl_scan_offload_profile_match) * \
	 IWL_SCAN_MAX_PROFILES_V2)

/**
 * struct iwl_mld_netdetect_res - contains netdetect results from
 * match_info_notif
 * @matched_profiles: bitmap of matched profiles, referencing the
 *	matches passed in the scan offload request
 * @matches: array of match information, one for each match
 */
struct iwl_mld_netdetect_res {
	u32 matched_profiles;
	u8 matches[NETDETECT_QUERY_BUF_LEN];
};

/**
 * struct iwl_mld_resume_data - d3 resume flow data
 * @notifs_expected: bitmap of expected notifications from fw,
 *	see &enum iwl_mld_d3_notif
 * @notifs_received: bitmap of received notifications from fw,
 *	see &enum iwl_mld_d3_notif
 * @d3_end_flags: bitmap of flags from d3_end_notif
 * @notif_handling_err: error handling one of the resume notifications
 * @wowlan_status: wowlan status data from all wowlan notifications
 * @netdetect_res: contains netdetect results from match_info_notif
 */
struct iwl_mld_resume_data {
	u32 notifs_expected;
	u32 notifs_received;
	u32 d3_end_flags;
	bool notif_handling_err;
	struct iwl_mld_wowlan_status *wowlan_status;
	struct iwl_mld_netdetect_res *netdetect_res;
};

static bool iwl_mld_check_err_tables(struct iwl_mld *mld,
				     struct ieee80211_vif *vif)
{
	u32 err_id;

	/* check for lmac1 error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.lmac_error_event_table[0],
				    &err_id)) {
		if (err_id == RF_KILL_INDICATOR_FOR_WOWLAN && vif) {
			struct cfg80211_wowlan_wakeup wakeup = {
				.rfkill_release = true,
			};
			ieee80211_report_wowlan_wakeup(vif, &wakeup,
						       GFP_KERNEL);
		}
		return true;
	}

	/* check if we have lmac2 set and check for error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.lmac_error_event_table[1],
				    NULL))
		return true;

	/* check for umac error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.umac_error_event_table,
				    NULL))
		return true;

	return false;
}

static
struct ieee80211_vif *iwl_mld_get_bss_vif(struct iwl_mld *mld)
{
	unsigned long fw_id_bitmap;
	int fw_id;

	fw_id_bitmap = iwl_mld_get_fw_bss_vifs_ids(mld);

	if (hweight8(fw_id_bitmap) != 1) {
		IWL_ERR(mld,
			"Must have exactly one bss vif for wowlan\n");
		return NULL;
	}

	fw_id = __ffs(fw_id_bitmap);

	return wiphy_dereference(mld->wiphy,
				 mld->fw_id_to_vif[fw_id]);
}

static int
iwl_mld_netdetect_config(struct iwl_mld *mld,
			 struct ieee80211_vif *vif,
			 const struct cfg80211_wowlan *wowlan)
{
	int ret;
	struct cfg80211_sched_scan_request *netdetect_cfg =
		wowlan->nd_config;
	struct ieee80211_scan_ies ies = {};

	ret = iwl_mld_scan_stop(mld, IWL_MLD_SCAN_SCHED, true);
	if (ret)
		return ret;

	ret = iwl_mld_sched_scan_start(mld, vif, netdetect_cfg, &ies,
				       IWL_MLD_SCAN_NETDETECT);
	return ret;
}

static bool
iwl_mld_handle_wowlan_info_notif(struct iwl_mld *mld,
				 struct iwl_mld_wowlan_status *wowlan_status,
				 struct iwl_rx_packet *pkt)
{
	const struct iwl_wowlan_info_notif *notif = (void *)pkt->data;
	u32 expected_len, len = iwl_rx_packet_payload_len(pkt);

	expected_len = sizeof(*notif);

	if (IWL_FW_CHECK(mld, len < expected_len,
			 "Invalid wowlan_info_notif (expected=%ud got=%ud)\n",
			 expected_len, len)) {
		return true;
	}

	/* TODO: parse the rest of the wowlan_info parameters (task=wowlan) */
	wowlan_status->wakeup_reasons = le32_to_cpu(notif->wakeup_reasons);
	return false;
}

static bool
iwl_mld_netdetect_match_info_handler(struct iwl_mld *mld,
				     struct iwl_mld_resume_data *resume_data,
				     struct iwl_rx_packet *pkt)
{
	struct iwl_mld_netdetect_res *results = resume_data->netdetect_res;
	const struct iwl_scan_offload_match_info *notif = (void *)pkt->data;
	u32 len = iwl_rx_packet_payload_len(pkt);

	if (IWL_FW_CHECK(mld, !mld->netdetect,
			 "Got scan match info notif when mld->netdetect==%d\n",
			 mld->netdetect))
		return true;

	if (IWL_FW_CHECK(mld, len < sizeof(*notif),
			 "Invalid scan offload match notif of length: %d\n",
			 len))
		return true;

	if (IWL_FW_CHECK(mld, resume_data->wowlan_status->wakeup_reasons !=
			 IWL_WOWLAN_WAKEUP_BY_NON_WIRELESS,
			 "Ignore scan match info: unexpected wakeup reason (expected=0x%x got=0x%x)\n",
			 IWL_WOWLAN_WAKEUP_BY_NON_WIRELESS,
			 resume_data->wowlan_status->wakeup_reasons))
		return true;

	results->matched_profiles = le32_to_cpu(notif->matched_profiles);
	IWL_DEBUG_WOWLAN(mld, "number of matched profiles=%u\n",
			 results->matched_profiles);

	if (results->matched_profiles)
		memcpy(results->matches, notif->matches,
		       NETDETECT_QUERY_BUF_LEN);

	/* No scan should be active at this point */
	mld->scan.status = 0;
	memset(mld->scan.uid_status, 0, sizeof(mld->scan.uid_status));
	return false;
}

static void
iwl_mld_set_netdetect_info(struct iwl_mld *mld,
			   const struct cfg80211_sched_scan_request *netdetect_cfg,
			   struct cfg80211_wowlan_nd_info *netdetect_info,
			   struct iwl_mld_netdetect_res *netdetect_res,
			   unsigned long matched_profiles)
{
	int i;

	for_each_set_bit(i, &matched_profiles, netdetect_cfg->n_match_sets) {
		struct cfg80211_wowlan_nd_match *match;
		int idx, j, n_channels = 0;
		struct iwl_scan_offload_profile_match *matches =
			(void *)netdetect_res->matches;

		for (int k = 0; k < SCAN_OFFLOAD_MATCHING_CHANNELS_LEN; k++)
			n_channels +=
				hweight8(matches[i].matching_channels[k]);
		match = kzalloc(struct_size(match, channels, n_channels),
				GFP_KERNEL);
		if (!match)
			return;

		netdetect_info->matches[netdetect_info->n_matches++] = match;

		/* We inverted the order of the SSIDs in the scan
		 * request, so invert the index here.
		 */
		idx = netdetect_cfg->n_match_sets - i - 1;
		match->ssid.ssid_len =
			netdetect_cfg->match_sets[idx].ssid.ssid_len;
		memcpy(match->ssid.ssid,
		       netdetect_cfg->match_sets[idx].ssid.ssid,
		       match->ssid.ssid_len);

		if (netdetect_cfg->n_channels < n_channels)
			continue;

		for_each_set_bit(j,
				 (unsigned long *)&matches[i].matching_channels[0],
				 sizeof(matches[i].matching_channels))
			match->channels[match->n_channels++] =
				netdetect_cfg->channels[j]->center_freq;
	}
}

static void
iwl_mld_process_netdetect_res(struct iwl_mld *mld,
			      struct ieee80211_vif *vif,
			      struct iwl_mld_resume_data *resume_data)
{
	struct cfg80211_wowlan_nd_info *netdetect_info = NULL;
	const struct cfg80211_sched_scan_request *netdetect_cfg;
	struct cfg80211_wowlan_wakeup wakeup = {
		.pattern_idx = -1,
	};
	struct cfg80211_wowlan_wakeup *wakeup_report = &wakeup;
	unsigned long matched_profiles;
	u32 wakeup_reasons;
	int n_matches;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld->wiphy->wowlan_config ||
		    !mld->wiphy->wowlan_config->nd_config)) {
		IWL_DEBUG_WOWLAN(mld,
				 "Netdetect isn't configured on resume flow\n");
		goto out;
	}

	netdetect_cfg = mld->wiphy->wowlan_config->nd_config;
	wakeup_reasons = resume_data->wowlan_status->wakeup_reasons;

	if (wakeup_reasons & IWL_WOWLAN_WAKEUP_BY_RFKILL_DEASSERTED)
		wakeup.rfkill_release = true;

	if (wakeup_reasons != IWL_WOWLAN_WAKEUP_BY_NON_WIRELESS)
		goto out;

	if (!resume_data->netdetect_res->matched_profiles) {
		IWL_DEBUG_WOWLAN(mld,
				 "Netdetect results aren't valid\n");
		wakeup_report = NULL;
		goto out;
	}

	matched_profiles = resume_data->netdetect_res->matched_profiles;
	if (!netdetect_cfg->n_match_sets) {
		IWL_DEBUG_WOWLAN(mld,
				 "No netdetect match sets are configured\n");
		goto out;
	}
	n_matches = hweight_long(matched_profiles);
	netdetect_info = kzalloc(struct_size(netdetect_info, matches,
					     n_matches), GFP_KERNEL);
	if (netdetect_info)
		iwl_mld_set_netdetect_info(mld, netdetect_cfg, netdetect_info,
					   resume_data->netdetect_res,
					   matched_profiles);

	wakeup.net_detect = netdetect_info;
 out:
	ieee80211_report_wowlan_wakeup(vif, wakeup_report, GFP_KERNEL);
	if (netdetect_info) {
		for (int i = 0; i < netdetect_info->n_matches; i++)
			kfree(netdetect_info->matches[i]);
		kfree(netdetect_info);
	}
}

static bool iwl_mld_handle_d3_notif(struct iwl_notif_wait_data *notif_wait,
				    struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mld_resume_data *resume_data = data;
	struct iwl_mld *mld =
		container_of(notif_wait, struct iwl_mld, notif_wait);

	switch (WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd)) {
	case WIDE_ID(PROT_OFFLOAD_GROUP, WOWLAN_INFO_NOTIFICATION): {
		if (resume_data->notifs_received & IWL_D3_NOTIF_WOWLAN_INFO) {
			IWL_DEBUG_WOWLAN(mld,
					 "got additional wowlan_info notif\n");
			break;
		}
		/* TODO: add wakeup reason notifs_expected (task=wowlan) */
		resume_data->notif_handling_err =
			iwl_mld_handle_wowlan_info_notif(mld,
							 resume_data->wowlan_status,
							 pkt);
		resume_data->notifs_received |= IWL_D3_NOTIF_WOWLAN_INFO;
		break;
	}
	case WIDE_ID(PROT_OFFLOAD_GROUP, WOWLAN_WAKE_PKT_NOTIFICATION): {
		if (resume_data->notifs_received &
		    IWL_D3_NOTIF_WOWLAN_WAKE_PKT) {
			/* We shouldn't get two wake packet notifications */
			IWL_DEBUG_WOWLAN(mld,
					 "Got additional wowlan wake packet notification\n");
		}
		/* TODO: parse wowlan_packet (task=wowlan) */
		resume_data->notifs_received |= IWL_D3_NOTIF_WOWLAN_WAKE_PKT;
		break;
	}
	case WIDE_ID(SCAN_GROUP, OFFLOAD_MATCH_INFO_NOTIF): {
		if (resume_data->notifs_received & IWL_D3_ND_MATCH_INFO) {
			IWL_ERR(mld,
				"Got additional netdetect match info\n");
			break;
		}

		resume_data->notif_handling_err =
			iwl_mld_netdetect_match_info_handler(mld, resume_data,
							     pkt);
		resume_data->notifs_received |= IWL_D3_ND_MATCH_INFO;
		break;
	}
	case WIDE_ID(PROT_OFFLOAD_GROUP, D3_END_NOTIFICATION): {
		struct iwl_d3_end_notif *notif = (void *)pkt->data;

		resume_data->d3_end_flags = le32_to_cpu(notif->flags);
		resume_data->notifs_received |= IWL_D3_NOTIF_D3_END_NOTIF;
		break;
	}
	default:
		WARN_ON(1);
	}

	return resume_data->notifs_received == resume_data->notifs_expected;
}

#define IWL_MLD_D3_NOTIF_TIMEOUT (HZ / 3 * CPTCFG_IWL_TIMEOUT_FACTOR)

static int iwl_mld_wait_d3_notif(struct iwl_mld *mld,
				 struct iwl_mld_resume_data *resume_data,
				 bool with_wowlan)
{
	static const u16 wowlan_resume_notif[] = {
		WIDE_ID(PROT_OFFLOAD_GROUP, WOWLAN_INFO_NOTIFICATION),
		WIDE_ID(PROT_OFFLOAD_GROUP, WOWLAN_WAKE_PKT_NOTIFICATION),
		WIDE_ID(SCAN_GROUP, OFFLOAD_MATCH_INFO_NOTIF),
		WIDE_ID(PROT_OFFLOAD_GROUP, D3_END_NOTIFICATION)
	};
	static const u16 d3_resume_notif[] = {
		WIDE_ID(PROT_OFFLOAD_GROUP, D3_END_NOTIFICATION)
	};
	struct iwl_notification_wait wait_d3_notif;
	enum iwl_d3_status d3_status;
	int ret;

	if (with_wowlan)
		iwl_init_notification_wait(&mld->notif_wait, &wait_d3_notif,
					   wowlan_resume_notif,
					   ARRAY_SIZE(wowlan_resume_notif),
					   iwl_mld_handle_d3_notif,
					   resume_data);
	else
		iwl_init_notification_wait(&mld->notif_wait, &wait_d3_notif,
					   d3_resume_notif,
					   ARRAY_SIZE(d3_resume_notif),
					   iwl_mld_handle_d3_notif,
					   resume_data);

	ret = iwl_trans_d3_resume(mld->trans, &d3_status, false, false);
	if (ret || d3_status != IWL_D3_STATUS_ALIVE) {
		if (d3_status != IWL_D3_STATUS_ALIVE) {
			IWL_INFO(mld, "Device was reset during suspend\n");
			ret = -ENOENT;
		} else {
			IWL_ERR(mld, "Transport resume failed\n");
		}
		iwl_remove_notification(&mld->notif_wait, &wait_d3_notif);
		return ret;
	}

	ret = iwl_wait_notification(&mld->notif_wait, &wait_d3_notif,
				    IWL_MLD_D3_NOTIF_TIMEOUT);
	if (ret)
		IWL_ERR(mld, "Couldn't get the d3 notif %d\n", ret);

	if (resume_data->notif_handling_err)
		ret = -EIO;

	return ret;
}

int iwl_mld_no_wowlan_suspend(struct iwl_mld *mld)
{
	struct iwl_d3_manager_config d3_cfg_cmd_data = {};
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	IWL_DEBUG_WOWLAN(mld, "Starting the no wowlan suspend flow\n");

	/* This will happen if iwl_mld_supsend failed with FW error */
	if (mld->trans->state == IWL_TRANS_NO_FW &&
	    test_bit(STATUS_FW_ERROR, &mld->trans->status))
		return -ENODEV;

	WARN_ON(iwl_mld_power_update_device(mld));
	ret = iwl_mld_send_cmd_pdu(mld, D3_CONFIG_CMD,
				   &d3_cfg_cmd_data);
	if (ret) {
		IWL_ERR(mld,
			"d3 suspend: couldn't send D3_CONFIG_CMD %d\n", ret);
		goto out;
	}

	ret = iwl_trans_d3_suspend(mld->trans, false, false);
	if (ret) {
		IWL_ERR(mld, "d3 suspend: trans_d3_suspend failed %d\n", ret);
	} else {
		mld->trans->system_pm_mode = IWL_PLAT_PM_MODE_D3;
		mld->fw_status.in_d3 = true;
	}

 out:
	if (ret) {
		mld->trans->state = IWL_TRANS_NO_FW;
		set_bit(STATUS_FW_ERROR, &mld->trans->status);
	}

	return ret;
}

int iwl_mld_no_wowlan_resume(struct iwl_mld *mld)
{
	struct iwl_mld_resume_data resume_data = {
		.notifs_expected =
			IWL_D3_NOTIF_D3_END_NOTIF,
	};
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	IWL_DEBUG_WOWLAN(mld, "Starting the no wowlan resume flow\n");

	mld->trans->system_pm_mode = IWL_PLAT_PM_MODE_DISABLED;
	mld->fw_status.in_d3 = false;
	iwl_fw_dbg_read_d3_debug_data(&mld->fwrt);

	if (iwl_mld_check_err_tables(mld, NULL))
		ret = -ENODEV;
	else
		ret = iwl_mld_wait_d3_notif(mld, &resume_data, false);

	if (!ret && (resume_data.d3_end_flags & IWL_D0I3_RESET_REQUIRE))
		return -ENODEV;

	if (ret) {
		mld->trans->state = IWL_TRANS_NO_FW;
		set_bit(STATUS_FW_ERROR, &mld->trans->status);
	}

	/* TODO: iwl_mld_power_update_mac() (task=power) */

	return ret;
}

int
iwl_mld_wowlan_suspend(struct iwl_mld *mld, struct cfg80211_wowlan *wowlan)
{
	struct ieee80211_vif *bss_vif;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!wowlan))
		return 1;

	IWL_DEBUG_WOWLAN(mld, "Starting the wowlan suspend flow\n");

	bss_vif = iwl_mld_get_bss_vif(mld);
	if (WARN_ON(!bss_vif))
		return 1;

	if (!bss_vif->cfg.assoc) {
		int ret;
		/* If we're not associated, this must be netdetect */
		if (WARN_ON(!wowlan->nd_config))
			return 1;

		ret = iwl_mld_netdetect_config(mld, bss_vif, wowlan);
		if (!ret)
			mld->netdetect = true;

		return ret;
	}

	return 0;
}

/* Returns 0 on success, 1 if an error occurred in firmware during d3,
 * A negative value is expected only in unrecovreable cases.
 */
int iwl_mld_wowlan_resume(struct iwl_mld *mld)
{
	struct ieee80211_vif *bss_vif;
	struct iwl_mld_wowlan_status wowlan_status;
	struct iwl_mld_netdetect_res netdetect_res;
	struct iwl_mld_resume_data resume_data = {
		.notifs_expected =
			IWL_D3_NOTIF_WOWLAN_INFO |
			IWL_D3_NOTIF_D3_END_NOTIF,
		.netdetect_res = &netdetect_res,
		.wowlan_status = &wowlan_status,
	};
	int ret;
	bool fw_err = false;

	lockdep_assert_wiphy(mld->wiphy);

	IWL_DEBUG_WOWLAN(mld, "Starting the wowlan resume flow\n");

	mld->trans->system_pm_mode = IWL_PLAT_PM_MODE_DISABLED;
	if (!mld->fw_status.in_d3) {
		IWL_DEBUG_WOWLAN(mld,
				 "Device_powered_off() was called during wowlan\n");
		goto err;
	}

	mld->fw_status.in_d3 = false;
	mld->scan.last_start_time_jiffies = jiffies;

	bss_vif = iwl_mld_get_bss_vif(mld);
	if (WARN_ON(!bss_vif))
		goto err;

	iwl_fw_dbg_read_d3_debug_data(&mld->fwrt);

	if (iwl_mld_check_err_tables(mld, bss_vif)) {
		fw_err = true;
		goto err;
	}

	if (mld->netdetect)
		resume_data.notifs_expected |= IWL_D3_ND_MATCH_INFO;

	ret = iwl_mld_wait_d3_notif(mld, &resume_data, true);
	if (ret) {
		IWL_ERR(mld, "Couldn't get the d3 notifs %d\n", ret);
		fw_err = true;
		goto err;
	}

	if (resume_data.d3_end_flags & IWL_D0I3_RESET_REQUIRE) {
		mld->fw_status.in_hw_restart = true;
		goto process_wakeup_results;
	}

	iwl_mld_update_changed_regdomain(mld);
	/* TODO: add power_update_mac() (task=power) */

	if (mld->netdetect)
		ret = iwl_mld_scan_stop(mld, IWL_MLD_SCAN_NETDETECT, false);

 process_wakeup_results:
	if (mld->netdetect) {
		iwl_mld_process_netdetect_res(mld, bss_vif, &resume_data);
		mld->netdetect = false;
	}

	return ret;

 err:
	if (fw_err) {
		mld->trans->state = IWL_TRANS_NO_FW;
		set_bit(STATUS_FW_ERROR, &mld->trans->status);
	}

	mld->fw_status.in_hw_restart = true;
	return 1;
}
