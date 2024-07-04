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

#endif /* __iwl_mld_scan_h__ */
