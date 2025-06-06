// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_ftm_initiator_h__
#define __iwl_mld_ftm_initiator_h__

/**
 * struct ftm_initiator_data - FTM initiator data
 *
 * @req: a pointer to cfg80211 FTM request
 * @req_wdev: a pointer to the wdev that requested the current FTM request
 * @responses: the number of responses received for the current FTM session.
 *	Used for tracking the burst index in a periodic request.
 * @pasn_list: a list of PASN stations with security configurations for each
 *	station. Used for secured ranging.
 * @loc_list: list of LCI/CIVIC information for the current FTM request.
 */
struct ftm_initiator_data {
		struct cfg80211_pmsr_request *req;
		struct wireless_dev *req_wdev;
		int responses[IWL_TOF_MAX_APS];
		struct list_head pasn_list;
		struct list_head loc_list;
};

int iwl_mld_ftm_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
		      struct cfg80211_pmsr_request *req);

void iwl_mld_handle_ftm_resp_notif(struct iwl_mld *mld,
				   struct iwl_rx_packet *pkt);
void iwl_mld_ftm_restart_cleanup(struct iwl_mld *mld);
void iwl_mld_ftm_remove_pasn_sta(struct iwl_mld *mld, u8 *addr);
int iwl_mld_ftm_add_pasn_sta(struct iwl_mld *mld, struct ieee80211_vif *vif,
			     u8 *addr, u32 cipher, u8 *tk, u32 tk_len,
			     u8 *hltk, u32 hltk_len);
void iwl_mld_ftm_initiator_stop(struct iwl_mld *mld);
void iwl_mld_ftm_initiator_init(struct iwl_mld *mld);
void iwl_mld_handle_lci_civic_notif(struct iwl_mld *mld,
				    struct iwl_rx_packet *pkt);
void iwl_mld_ftm_abort(struct iwl_mld *mld, struct cfg80211_pmsr_request *req);

#endif /* __iwl_mld_ftm_initiator_h__ */
