// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "tx.h"

void iwl_mld_add_txqs_wk(struct wiphy *wiphy, struct wiphy_work *wk)
{
	struct iwl_mld *mld = container_of(wk, struct iwl_mld,
					   add_txqs_wk);

	lockdep_assert_wiphy(mld->wiphy);

	while (!list_empty(&mld->txqs_to_add)) {
		struct iwl_mld_txq *mld_txq =
			list_first_entry(&mld->txqs_to_add, struct iwl_mld_txq,
					 list);

		/* TODO: allocate the queue */

		local_bh_disable();
		spin_lock(&mld->add_txqs_lock);
		list_del_init(&mld_txq->list);
		spin_unlock(&mld->add_txqs_lock);
		/* TODO: iwl_mvm_mac_itxq_xmit if queue was allocated successfully */
		local_bh_enable();
	}
}

void iwl_mld_remove_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{}
