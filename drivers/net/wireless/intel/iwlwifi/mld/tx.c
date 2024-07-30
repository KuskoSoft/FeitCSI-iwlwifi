// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <net/ip.h>

#include "tx.h"
#include "sta.h"
#include "hcmd.h"

#include "fw/dbg.h"

#include "fw/api/tx.h"
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

#define OPT_HDR(type, skb, off) \
	(type *)(skb_network_header(skb) + (off))

static __le32
iwl_mld_get_offload_assist(struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	u16 mh_len = ieee80211_hdrlen(hdr->frame_control);
	u16 offload_assist = 0;
	bool amsdu = false;
#if IS_ENABLED(CONFIG_INET)
	u8 protocol = 0;

	/* Do not compute checksum if already computed */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		goto out;

	/* We do not expect to be requested to csum stuff we do not support */

	/* TBD: do we also need to check
	 * !(mvm->hw->netdev_features & IWL_TX_CSUM_NETIF_FLAGS) now that all
	 * the devices we support has this flags?
	 */
	if (WARN_ONCE(skb->protocol != htons(ETH_P_IP) &&
		      skb->protocol != htons(ETH_P_IPV6),
		      "No support for requested checksum\n")) {
		skb_checksum_help(skb);
		goto out;
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		protocol = ip_hdr(skb)->protocol;
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		struct ipv6hdr *ipv6h =
			(struct ipv6hdr *)skb_network_header(skb);
		unsigned int off = sizeof(*ipv6h);

		protocol = ipv6h->nexthdr;
		while (protocol != NEXTHDR_NONE && ipv6_ext_hdr(protocol)) {
			struct ipv6_opt_hdr *hp;

			/* only supported extension headers */
			if (protocol != NEXTHDR_ROUTING &&
			    protocol != NEXTHDR_HOP &&
			    protocol != NEXTHDR_DEST) {
				skb_checksum_help(skb);
				goto out;
			}

			hp = OPT_HDR(struct ipv6_opt_hdr, skb, off);
			protocol = hp->nexthdr;
			off += ipv6_optlen(hp);
		}
		/* if we get here - protocol now should be TCP/UDP */
#endif
	}

	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
		WARN_ON_ONCE(1);
		skb_checksum_help(skb);
		goto out;
	}

	/* enable L4 csum */
	offload_assist |= BIT(TX_CMD_OFFLD_L4_EN);

	/* Set offset to IP header (snap).
	 * We don't support tunneling so no need to take care of inner header.
	 * Size is in words.
	 */
	offload_assist |= (4 << TX_CMD_OFFLD_IP_HDR);

	/* Do IPv4 csum for AMSDU only (no IP csum for Ipv6) */
	if (skb->protocol == htons(ETH_P_IP) && amsdu) {
		ip_hdr(skb)->check = 0;
		offload_assist |= BIT(TX_CMD_OFFLD_L3_EN);
	}

	/* reset UDP/TCP header csum */
	if (protocol == IPPROTO_TCP)
		tcp_hdr(skb)->check = 0;
	else
		udp_hdr(skb)->check = 0;

out:
#endif
	mh_len /= 2;
	offload_assist |= mh_len << TX_CMD_OFFLD_MH_SIZE;

	if (ieee80211_is_data_qos(hdr->frame_control)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);

		amsdu = *qc & IEEE80211_QOS_CTL_A_MSDU_PRESENT;
	}

	if (amsdu)
		offload_assist |= BIT(TX_CMD_OFFLD_AMSDU);
	else if (ieee80211_hdrlen(hdr->frame_control) % 4)
		/* padding is inserted later in transport */
		offload_assist |= BIT(TX_CMD_OFFLD_PAD);

	return cpu_to_le32(offload_assist);
}

static void
iwl_mld_fill_tx_cmd(struct iwl_mld *mld, struct sk_buff *skb,
		    struct iwl_device_tx_cmd *dev_tx_cmd,
		    struct ieee80211_sta *sta)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (void *)skb->data;
	struct iwl_mld_sta *mld_sta = sta ? iwl_mld_sta_from_mac80211(sta) :
					    NULL;
	struct iwl_tx_cmd_gen3 *tx_cmd;
	u16 flags = 0;

	dev_tx_cmd->hdr.cmd = TX_CMD;

	/* TODO: set rate_n_flags for non sta or injected frames */

	if (!info->control.hw_key)
		flags |= IWL_TX_FLAGS_ENCRYPT_DIS;

	if (!ieee80211_is_data(hdr->frame_control) ||
	    (mld_sta && mld_sta->sta_state < IEEE80211_STA_AUTHORIZED)) {
		/* These are important frames */
		flags |= IWL_TX_FLAGS_HIGH_PRI;
	}

	tx_cmd = (void *)dev_tx_cmd->payload;

	tx_cmd->offload_assist = iwl_mld_get_offload_assist(skb);

	/* Total # bytes to be transmitted */
	tx_cmd->len = cpu_to_le16((u16)skb->len);

	/* Copy MAC header from skb into command buffer */
	memcpy(tx_cmd->hdr, hdr, ieee80211_hdrlen(hdr->frame_control));

	tx_cmd->flags = cpu_to_le16(flags);
}

/* This function must be called with BHs disabled */
static int iwl_mld_tx_mpdu(struct iwl_mld *mld, struct sk_buff *skb,
			   struct ieee80211_txq *txq)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_sta *sta = txq ? txq->sta : NULL;
	struct iwl_device_tx_cmd *dev_tx_cmd;
	int txq_id = -1;

	/* to be removed when non-txq tx is implemented */
	if (WARN_ON(!txq || !sta))
		return -1;

	if (unlikely(ieee80211_is_any_nullfunc(hdr->frame_control)))
		return -1;

	dev_tx_cmd = iwl_trans_alloc_tx_cmd(mld->trans);
	if (unlikely(!dev_tx_cmd))
		return -1;

	/* TODO: iwl_mvm_probe_resp_set_noa */

	iwl_mld_fill_tx_cmd(mld, skb, dev_tx_cmd, sta);

	if (txq)
		txq_id = iwl_mld_txq_from_mac80211(txq)->fw_id;

	/* TODO: get_internal_txq_id for non-txq*/

	if (WARN_ONCE(txq_id < 0, "Invalid TXQ id"))
		goto err;

	/* TODO: get_internal_sta_id (task=soft_ap)*/
	IWL_DEBUG_TX(mld, "TX to sta mask: 0x%x, from Q:%d. Len %d\n",
		     iwl_mld_fw_sta_id_mask(mld, sta),
		     txq_id, skb->len);

	/* From now on, we cannot access info->control */
	memset(&info->status, 0, sizeof(info->status));
	memset(info->driver_data, 0, sizeof(info->driver_data));

	info->driver_data[1] = dev_tx_cmd;

	if (iwl_trans_tx(mld->trans, skb, dev_tx_cmd, txq_id))
		goto err;

	return 0;

err:
	iwl_trans_free_tx_cmd(mld->trans, dev_tx_cmd);
	/* TODO: get_internal_sta_id */
	IWL_DEBUG_TX(mld, "TX to sta 0x%x, from Q:%d dropped\n",
		     iwl_mld_fw_sta_id_mask(mld, sta),
		     txq_id);
	return -1;
}

static void iwl_mld_tx_skb(struct iwl_mld *mld, struct sk_buff *skb,
			   struct ieee80211_txq *txq)
{
	if (skb_is_gso(skb)) {
		IWL_ERR(mld, "GSO is not implemented\n");
		goto err;
	}

	if (likely(!iwl_mld_tx_mpdu(mld, skb, txq)))
		return;

err:
	ieee80211_free_txskb(mld->hw, skb);
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
		while ((skb = ieee80211_tx_dequeue(mld->hw, txq)))
			iwl_mld_tx_skb(mld, skb, txq);
	} while (atomic_dec_return(&mld_txq->tx_request));

	IWL_DEBUG_TX(mld, "TXQ of sta %pM tid %d is now empty\n",
		     txq->sta ? txq->sta->addr : zero_addr, txq->tid);

	rcu_read_unlock();
}

void iwl_mld_handle_tx_resp_notif(struct iwl_mld *mld,
				 struct iwl_rx_packet *pkt)
{
	struct iwl_tx_resp *tx_resp = (void *)pkt->data;
	int txq_id = le16_to_cpu(tx_resp->tx_queue);
	struct agg_tx_status *agg_status = &tx_resp->status;
	u32 status = le16_to_cpu(agg_status->status);
	u16 ssn = le32_to_cpup((__le32 *)agg_status + tx_resp->frame_count)
				& 0xFFFF;
	struct sk_buff_head skbs;
	u8 skb_freed = 0;

	WARN_ON(tx_resp->frame_count != 1);

	/* TODO: validate the size of the variable part of the notif */

	__skb_queue_head_init(&skbs);

	/* we can free until ssn % q.n_bd not inclusive */
	iwl_trans_reclaim(mld->trans, txq_id, ssn, &skbs, false);

	while (!skb_queue_empty(&skbs)) {
		struct sk_buff *skb = __skb_dequeue(&skbs);
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

		skb_freed++;

		iwl_trans_free_tx_cmd(mld->trans, info->driver_data[1]);

		memset(&info->status, 0, sizeof(info->status));

		info->flags &= ~(IEEE80211_TX_STAT_ACK | IEEE80211_TX_STAT_TX_FILTERED);

		/* inform mac80211 about what happened with the frame */
		switch (status & TX_STATUS_MSK) {
		case TX_STATUS_SUCCESS:
		case TX_STATUS_DIRECT_DONE:
			info->flags |= IEEE80211_TX_STAT_ACK;
			break;
		default:
			break;
		}

		/* If we are freeing multiple frames, mark all the frames
		 * but the first one as acked, since they were acknowledged
		 * before
		 */
		if (skb_freed > 1)
			info->flags |= IEEE80211_TX_STAT_ACK;

		/* TODO: iwl_mvm_tx_status_check_trigger (task=DP) */
		/* TODO: iwl_mvm_hwrate_to_tx_rate (task=DP)*/

		ieee80211_tx_status_skb(mld->hw, skb);
	}

	IWL_DEBUG_TX_REPLY(mld,
			   "TXQ %d status 0x%08x ssn=%d\n",
			   txq_id, status, ssn);

	/* TODO: print more info here */
}

static void iwl_mld_tx_reclaim_txq(struct iwl_mld *mld, int txq, int index)
{
	struct sk_buff_head reclaimed_skbs;

	__skb_queue_head_init(&reclaimed_skbs);

	iwl_trans_reclaim(mld->trans, txq, index, &reclaimed_skbs, true);

	while (!skb_queue_empty(&reclaimed_skbs)) {
		struct sk_buff *skb = __skb_dequeue(&reclaimed_skbs);
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

		iwl_trans_free_tx_cmd(mld->trans, info->driver_data[1]);

		memset(&info->status, 0, sizeof(info->status));

		info->flags &= ~IEEE80211_TX_STAT_ACK;
		ieee80211_tx_status_skb(mld->hw, skb);
	}
}

int iwl_mld_flush_link_sta_txqs(struct iwl_mld *mld, u32 fw_sta_id)
{
	struct iwl_tx_path_flush_cmd_rsp *rsp;
	struct iwl_tx_path_flush_cmd flush_cmd = {
		.sta_id = cpu_to_le32(fw_sta_id),
		.tid_mask = cpu_to_le16(0xffff),
	};
	struct iwl_host_cmd cmd = {
		.id = TXPATH_FLUSH,
		.len = { sizeof(flush_cmd), },
		.data = { &flush_cmd, },
		.flags = CMD_WANT_SKB,
	};
	int ret, num_flushed_queues;
	u32 resp_len;

	IWL_DEBUG_TX_QUEUES(mld, "flush for sta id %d tid mask 0x%x\n",
			    fw_sta_id, 0xffff);

	ret = iwl_mld_send_cmd(mld, &cmd);
	if (ret) {
		IWL_ERR(mld, "Failed to send flush command (%d)\n", ret);
		return ret;
	}

	resp_len = iwl_rx_packet_payload_len(cmd.resp_pkt);
	if (IWL_FW_CHECK(mld, resp_len != sizeof(*rsp),
			 "Invalid TXPATH_FLUSH response len: %d\n",
			 resp_len)) {
		ret = -EIO;
		goto free_rsp;
	}

	rsp = (void *)cmd.resp_pkt->data;

	if (IWL_FW_CHECK(mld, le16_to_cpu(rsp->sta_id) != fw_sta_id,
			 "sta_id %d != rsp_sta_id %d\n", fw_sta_id,
			 le16_to_cpu(rsp->sta_id))) {
		ret = -EIO;
		goto free_rsp;
	}

	num_flushed_queues = le16_to_cpu(rsp->num_flushed_queues);
	if (IWL_FW_CHECK(mld, num_flushed_queues > IWL_TX_FLUSH_QUEUE_RSP,
			 "num_flushed_queues %d\n", num_flushed_queues)) {
		ret = -EIO;
		goto free_rsp;
	}

	for (int i = 0; i < num_flushed_queues; i++) {
		struct iwl_flush_queue_info *queue_info = &rsp->queues[i];
		int read_after = le16_to_cpu(queue_info->read_after_flush);
		int txq_id = le16_to_cpu(queue_info->queue_num);

		if (IWL_FW_CHECK(mld,
				 txq_id >= ARRAY_SIZE(mld->fw_id_to_txq),
				 "Invalid txq id %d\n", txq_id))
			continue;

		IWL_DEBUG_TX_QUEUES(mld,
				    "tid %d txq_id %d read-before %d read-after %d\n",
				    le16_to_cpu(queue_info->tid), txq_id,
				    le16_to_cpu(queue_info->read_before_flush),
				    read_after);

		iwl_mld_tx_reclaim_txq(mld, txq_id, read_after);
	}

free_rsp:
	iwl_free_resp(&cmd);
	return ret;
}
