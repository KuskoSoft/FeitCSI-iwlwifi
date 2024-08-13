// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_scan_h__
#define __iwl_mld_scan_h__

int iwl_mld_alloc_scan_cmd(struct iwl_mld *mld);

int iwl_mld_regular_scan_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
			       struct cfg80211_scan_request *req,
			       struct ieee80211_scan_ies *ies);

void iwl_mld_handle_scan_iter_complete_notif(struct iwl_mld *mld,
					     struct iwl_rx_packet *pkt);

int iwl_mld_scan_stop(struct iwl_mld *mld, int type, bool notify);

int iwl_mld_sched_scan_start(struct iwl_mld *mld,
			     struct ieee80211_vif *vif,
			     struct cfg80211_sched_scan_request *req,
			     struct ieee80211_scan_ies *ies,
			     int type);

void iwl_mld_handle_match_found_notif(struct iwl_mld *mld,
				      struct iwl_rx_packet *pkt);

void iwl_mld_handle_scan_complete_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt);

#define WFA_TPC_IE_LEN 9

static inline int iwl_mld_scan_max_template_size(void)
{
#define MAC_HDR_LEN 24
#define DS_IE_LEN 3
#define SSID_IE_LEN 2

/* driver create the 802.11 header, WFA TPC IE, DS parameter and SSID IE */
#define DRIVER_TOTAL_IES_LEN \
	(MAC_HDR_LEN + WFA_TPC_IE_LEN + DS_IE_LEN + SSID_IE_LEN)

	BUILD_BUG_ON(SCAN_OFFLOAD_PROBE_REQ_SIZE < DRIVER_TOTAL_IES_LEN);

	return SCAN_OFFLOAD_PROBE_REQ_SIZE - DRIVER_TOTAL_IES_LEN;
}

void iwl_mld_report_scan_aborted(struct iwl_mld *mld);

#define IWL_MLD_SCAN_STOPPING_SHIFT	8

enum iwl_mld_scan_status {
	IWL_MLD_SCAN_REGULAR		= BIT(0),
	IWL_MLD_SCAN_SCHED		= BIT(1),
	IWL_MLD_SCAN_NETDETECT		= BIT(2),
	IWL_MLD_SCAN_INT_MLO		= BIT(3),

	IWL_MLD_SCAN_STOPPING_REGULAR	= BIT(IWL_MLD_SCAN_STOPPING_SHIFT),
	IWL_MLD_SCAN_STOPPING_SCHED	= BIT(IWL_MLD_SCAN_STOPPING_SHIFT + 1),
	IWL_MLD_SCAN_STOPPING_NETDETECT	= BIT(IWL_MLD_SCAN_STOPPING_SHIFT + 2),
	IWL_MLD_SCAN_STOPPING_INT_MLO	= BIT(IWL_MLD_SCAN_STOPPING_SHIFT + 3),

	IWL_MLD_SCAN_REGULAR_MASK	= IWL_MLD_SCAN_REGULAR |
					  IWL_MLD_SCAN_STOPPING_REGULAR,
	IWL_MLD_SCAN_SCHED_MASK		= IWL_MLD_SCAN_SCHED |
					  IWL_MLD_SCAN_STOPPING_SCHED,
	IWL_MLD_SCAN_NETDETECT_MASK	= IWL_MLD_SCAN_NETDETECT |
					  IWL_MLD_SCAN_STOPPING_NETDETECT,
	IWL_MLD_SCAN_INT_MLO_MASK	= IWL_MLD_SCAN_INT_MLO |
					  IWL_MLD_SCAN_STOPPING_INT_MLO,

	IWL_MLD_SCAN_STOPPING_MASK	= 0xff << IWL_MLD_SCAN_STOPPING_SHIFT,
	IWL_MLD_SCAN_MASK		= 0xff,
};

/* enum iwl_mld_pass_all_sched_results_states - Defines the states for
 * handling/passing scheduled scan results to mac80211
 * @SCHED_SCAN_PASS_ALL_STATE_DISABLED: Don't pass all scan results, only when
 *	a match found.
 * @SCHED_SCAN_PASS_ALL_STATE_ENABLED: Pass all scan results is enabled
 *	(no filtering).
 * @SCHED_SCAN_PASS_ALL_STATE_FOUND: A scan result is found, pass it on the
 *	next scan iteration complete notification.
 */
enum iwl_mld_pass_all_sched_results_states {
	SCHED_SCAN_PASS_ALL_STATE_DISABLED,
	SCHED_SCAN_PASS_ALL_STATE_ENABLED,
	SCHED_SCAN_PASS_ALL_STATE_FOUND,
};

/**
 * struct iwl_mld_scan - Scan data
 * @status: scan status, a combination of %enum iwl_mld_scan_status,
 *	reflects the %scan.uid_status array.
 * @uid_status: array to track the scan status per uid.
 * @start_tsf: start time of last scan in TSF of the link that requested
 *	the scan.
 * @last_ebs_failed: true if the last EBS (Energy Based Scan) failed.
 * @pass_all_sched_res: see %enum iwl_mld_pass_all_sched_results_states.
 * @fw_link_id: the current (regular) scan fw link id, used by scan
 *	complete notif.
 * @cmd_size: size of %cmd.
 * @cmd: pointer to scan cmd buffer (allocated once in op mode start).
 * @last_6ghz_passive_jiffies: stores the last 6GHz passive scan time
 *	in jiffies.
 * @last_start_time_jiffies: stores the last start time in jiffies
 *	(interface up/reset/resume).
 */
struct iwl_mld_scan {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		unsigned int status;
		u32 uid_status[IWL_MAX_UMAC_SCANS];
		u64 start_tsf;
		bool last_ebs_failed;
		enum iwl_mld_pass_all_sched_results_states pass_all_sched_res;
		u8 fw_link_id;
	);
	/* And here fields that survive a fw restart */
	size_t cmd_size;
	void *cmd;
	unsigned long last_6ghz_passive_jiffies;
	unsigned long last_start_time_jiffies;
};

#endif /* __iwl_mld_scan_h__ */
