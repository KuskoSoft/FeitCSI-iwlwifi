// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "tx.h"
#include "sta.h"
#include "hcmd.h"

#include "fw/api/txq.h"
#include "fw/api/datapath.h"

static int
iwl_mld_get_queue_size(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	struct ieee80211_sta *sta = txq->sta;
	struct ieee80211_link_sta *link_sta;
	unsigned int link_id;
	int max_size = IWL_DEFAULT_QUEUE_SIZE;

	lockdep_assert_wiphy(mld->wiphy);

	for_each_sta_active_link(txq->vif, sta, link_sta, link_id) {
		if (link_sta->eht_cap.has_eht) {
			max_size = IWL_DEFAULT_QUEUE_SIZE_EHT;
			break;
		}

		if (link_sta->he_cap.has_he)
			max_size = IWL_DEFAULT_QUEUE_SIZE_HE;
	}

	return max_size;
}

static int iwl_mld_allocate_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	u8 tid = txq->tid == IEEE80211_NUM_TIDS ? IWL_MGMT_TID : txq->tid;
	u32 fw_sta_mask = iwl_mld_fw_sta_id_mask(mld, txq->sta);
	/* We can't know when the station is asleep or awake, so we
	 * must disable the queue hang detection.
	 */
	unsigned int watchdog_timeout = txq->vif->type == NL80211_IFTYPE_AP ?
				IWL_WATCHDOG_DISABLED :
				mld->trans->trans_cfg->base_params->wd_timeout;
	int queue, size;

	lockdep_assert_wiphy(mld->wiphy);

	if (tid == IWL_MGMT_TID)
		size = max_t(u32, IWL_MGMT_QUEUE_SIZE,
			     mld->trans->cfg->min_txq_size);
	else
		size = iwl_mld_get_queue_size(mld, txq);

	queue = iwl_trans_txq_alloc(mld->trans, 0, fw_sta_mask, tid, size,
				    watchdog_timeout);

	if (queue >= 0)
		IWL_DEBUG_TX_QUEUES(mld,
				    "Enabling TXQ #%d for sta mask 0x%x tid %d\n",
				    queue, fw_sta_mask, tid);
	return queue;
}

static int iwl_mld_add_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	struct iwl_mld_txq *mld_txq = iwl_mld_txq_from_mac80211(txq);
	int id;

	lockdep_assert_wiphy(mld->wiphy);

	/* This will alse send the SCD_QUEUE_CONFIG_CMD */
	id = iwl_mld_allocate_txq(mld, txq);
	if (id < 0)
		return id;

	mld_txq->fw_id = id;
	mld_txq->status.allocated = true;

	rcu_assign_pointer(mld->fw_id_to_txq[id], txq);

	return 0;
}

void iwl_mld_add_txqs_wk(struct wiphy *wiphy, struct wiphy_work *wk)
{
	struct iwl_mld *mld = container_of(wk, struct iwl_mld,
					   add_txqs_wk);
	int failed;

	lockdep_assert_wiphy(mld->wiphy);

	while (!list_empty(&mld->txqs_to_add)) {
		struct ieee80211_txq *txq;
		struct iwl_mld_txq *mld_txq =
			list_first_entry(&mld->txqs_to_add, struct iwl_mld_txq,
					 list);

		txq = container_of((void *)mld_txq, struct ieee80211_txq,
				   drv_priv);

		failed = iwl_mld_add_txq(mld, txq);

		local_bh_disable();
		spin_lock(&mld->add_txqs_lock);
		list_del_init(&mld_txq->list);
		spin_unlock(&mld->add_txqs_lock);
		/* If the queue allocation failed, we can't transmit. Leave the
		 * frames on the txq, maybe the attempt to allocate the queue
		 * will succeed.
		 */
		if (!failed)
			iwl_mld_tx_from_txq(mld, txq);
		local_bh_enable();
	}
}

static void iwl_mld_free_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	struct iwl_mld_txq *mld_txq = iwl_mld_txq_from_mac80211(txq);
	u32 fw_sta_mask = iwl_mld_fw_sta_id_mask(mld, txq->sta);
	struct iwl_scd_queue_cfg_cmd remove_cmd = {
		.operation = cpu_to_le32(IWL_SCD_QUEUE_REMOVE),
		.u.remove.tid = cpu_to_le32(txq->tid == IEEE80211_NUM_TIDS ?
							IWL_MGMT_TID :
							txq->tid),
		.u.remove.sta_mask = cpu_to_le32(fw_sta_mask),
	};

	iwl_mld_send_cmd_pdu(mld,
			     WIDE_ID(DATA_PATH_GROUP, SCD_QUEUE_CONFIG_CMD),
			     &remove_cmd);

	iwl_trans_txq_free(mld->trans, mld_txq->fw_id);
}

void iwl_mld_remove_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	struct iwl_mld_txq *mld_txq = iwl_mld_txq_from_mac80211(txq);

	lockdep_assert_wiphy(mld->wiphy);

	/* Have all pending allocations done */
	wiphy_work_flush(mld->wiphy, &mld->add_txqs_wk);

	if (!mld_txq->status.allocated ||
	    WARN_ON(mld_txq->fw_id >= ARRAY_SIZE(mld->fw_id_to_txq)))
		return;

	iwl_mld_free_txq(mld, txq);
	RCU_INIT_POINTER(mld->fw_id_to_txq[mld_txq->fw_id], NULL);
	mld_txq->status.allocated = false;
}

void iwl_mld_tx_from_txq(struct iwl_mld *mld, struct ieee80211_txq *txq)
{
	struct iwl_mld_txq *mld_txq = iwl_mld_txq_from_mac80211(txq);
	struct sk_buff *skb = NULL;
	u8 zero_addr[ETH_ALEN] = {};

	/*
	 * No need for threads to be pending here, they can leave the first
	 * taker all the work.
	 *
	 * mld_txq->tx_request logic:
	 *
	 * If 0, no one is currently TXing, set to 1 to indicate current thread
	 * will now start TX and other threads should quit.
	 *
	 * If 1, another thread is currently TXing, set to 2 to indicate to
	 * that thread that there was another request. Since that request may
	 * have raced with the check whether the queue is empty, the TXing
	 * thread should check the queue's status one more time before leaving.
	 * This check is done in order to not leave any TX hanging in the queue
	 * until the next TX invocation (which may not even happen).
	 *
	 * If 2, another thread is currently TXing, and it will already double
	 * check the queue, so do nothing.
	 */
	if (atomic_fetch_add_unless(&mld_txq->tx_request, 1, 2))
		return;

	rcu_read_lock();
	do {
		while ((skb = ieee80211_tx_dequeue(mld->hw, txq))) {
			/* TODO: iwl_mvm_tx_skb(mvm, skb, txq->sta); */
		}
	} while (atomic_dec_return(&mld_txq->tx_request));

	IWL_DEBUG_TX(mld, "TXQ of sta %pM tid %d is now empty\n",
		     txq->sta ? txq->sta->addr : zero_addr, txq->tid);

	rcu_read_unlock();
}
