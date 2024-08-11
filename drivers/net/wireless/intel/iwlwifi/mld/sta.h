// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#ifndef __iwl_mld_sta_h__
#define __iwl_mld_sta_h__

#include <net/mac80211.h>

#include "mld.h"
#include "tx.h"

/**
 * struct iwl_mld_rxq_dup_data - Duplication detection data, per STA & Rx queue
 * @last_seq: last sequence per tid.
 * @last_sub_frame_idx: the index of the last subframe in an A-MSDU. This value
 *	will be zero if the packet is not part of an A-MSDU.
 */
struct iwl_mld_rxq_dup_data {
	__le16 last_seq[IWL_MAX_TID_COUNT + 1];
	u8 last_sub_frame_idx[IWL_MAX_TID_COUNT + 1];
} ____cacheline_aligned_in_smp;

/**
 * struct iwl_mld_sta - representation of a station in the driver.
 *
 * This represent the MLD-level sta, and will not be added to the FW.
 * Embedded in ieee80211_sta.
 *
 * @vif: pointer the vif object.
 * @sta_state: station state according to enum %ieee80211_sta_state
 * @sta_type: type of this station. See &enum iwl_fw_sta_type
 * @dup_data: per queue duplicate packet detection data
 * @tid_to_baid: a simple map of TID to Block-Ack fw id
 */
struct iwl_mld_sta {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		enum ieee80211_sta_state sta_state;
		enum iwl_fw_sta_type sta_type;
	);
	struct ieee80211_vif *vif;
	/* And here fields that survive a fw restart */
	struct iwl_mld_rxq_dup_data *dup_data;
	u8 tid_to_baid[IWL_MAX_TID_COUNT];
};

static inline struct iwl_mld_sta *
iwl_mld_sta_from_mac80211(struct ieee80211_sta *sta)
{
	return (void *)sta->drv_priv;
}

static inline void
iwl_mld_cleanup_sta(void *data, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	for (int i = 0; i < ARRAY_SIZE(sta->txq); i++)
		CLEANUP_STRUCT(iwl_mld_txq_from_mac80211(sta->txq[i]));

	CLEANUP_STRUCT(mld_sta);
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif, enum iwl_fw_sta_type type);
void iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta);
u32 iwl_mld_fw_sta_id_mask(struct iwl_mld *mld, struct ieee80211_sta *sta);
int iwl_mld_update_all_link_stations(struct iwl_mld *mld,
				     struct ieee80211_sta *sta);
void iwl_mld_flush_sta_txqs(struct iwl_mld *mld, struct ieee80211_sta *sta);
void iwl_mld_wait_sta_txqs_empty(struct iwl_mld *mld,
				struct ieee80211_sta *sta);
int iwl_mld_sta_ampdu_rx_start(struct iwl_mld *mld, struct ieee80211_sta *sta,
			       int tid, u16 ssn, u16 buf_size, u16 timeout);
int iwl_mld_sta_ampdu_rx_stop(struct iwl_mld *mld, struct ieee80211_sta *sta,
			      int tid);

#endif /* __iwl_mld_sta_h__ */
