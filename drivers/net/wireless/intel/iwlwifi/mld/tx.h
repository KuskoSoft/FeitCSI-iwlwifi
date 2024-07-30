// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_tx_h__
#define __iwl_mld_tx_h__

#include "mld.h"

/**
 * struct iwl_mld_txq - TX Queue data
 *
 * @fw_id: the fw id of this txq. Only valid when &status.allocated is true.
 * @list: list pointer, for &mld::txqs_to_add
 * @status: bitmap of the txq status
 * @status.allocated: Indicates that the queue was allocated.
 * @tx_request: makes sure that if there are multiple threads that want to tx
 *	from this txq, only one of them will do all the TXing.
 *	This is needed to avoid spinning the trans txq lock, which is expensive
 */
struct iwl_mld_txq {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u16 fw_id;
		struct list_head list;
		struct {
			u8 allocated:1;
		} status;
		atomic_t tx_request;
	);
	/* And here fields that survive a fw restart */
};

static inline void iwl_mld_init_txq(struct iwl_mld_txq *mld_txq)
{
	INIT_LIST_HEAD(&mld_txq->list);
	atomic_set(&mld_txq->tx_request, 0);
}

static inline struct iwl_mld_txq *
iwl_mld_txq_from_mac80211(struct ieee80211_txq *txq)
{
	return (void *)txq->drv_priv;
}

void iwl_mld_add_txqs_wk(struct wiphy *wiphy, struct wiphy_work *wk);
void iwl_mld_remove_txq(struct iwl_mld *mld, struct ieee80211_txq *txq);
void iwl_mld_tx_from_txq(struct iwl_mld *mld, struct ieee80211_txq *txq);
void iwl_mld_handle_tx_resp_notif(struct iwl_mld *mld,
				 struct iwl_rx_packet *pkt);
int iwl_mld_flush_link_sta_txqs(struct iwl_mld *mld, u32 fw_sta_id);
#endif /* __iwl_mld_tx_h__ */
