// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mld.h"
#include "iface.h"
#include "low_latency.h"
#include "hcmd.h"
#include "power.h"

#define MLD_LL_WK_INTERVAL_MSEC 500
#define MLD_LL_PERIOD (HZ * MLD_LL_WK_INTERVAL_MSEC / 1000)

static void iwl_mld_low_latency_wk(struct wiphy *wiphy, struct wiphy_work *wk)
{
  /* TODO */
}

static void iwl_mld_low_latency_setup_timestamps(struct iwl_mld *mld)
{
	struct iwl_mld_low_latency *ll = &mld->low_latency;
	unsigned long ts = jiffies;

	ll->timestamp = jiffies;
	for (int mac_id = 0; mac_id < NUM_MAC_INDEX_DRIVER; mac_id++)
		ll->window_start[mac_id] = ts;
}

int iwl_mld_low_latency_init(struct iwl_mld *mld)
{
	struct iwl_mld_low_latency *ll = &mld->low_latency;

	ll->pkts_counters = kcalloc(mld->trans->num_rx_queues,
				    sizeof(*ll->pkts_counters), GFP_KERNEL);
	if (!ll->pkts_counters)
		return -ENOMEM;

	for (int q = 0; q < mld->trans->num_rx_queues; q++)
		spin_lock_init(&ll->pkts_counters[q].lock);

	wiphy_delayed_work_init(&ll->work, iwl_mld_low_latency_wk);

	iwl_mld_low_latency_setup_timestamps(mld);

	return 0;
}

void iwl_mld_low_latency_free(struct iwl_mld *mld)
{
	struct iwl_mld_low_latency *ll = &mld->low_latency;

	kfree(ll->pkts_counters);
	ll->pkts_counters = NULL;
}

void iwl_mld_low_latency_exit(struct iwl_mld *mld)
{
	lockdep_assert_wiphy(mld->wiphy);

	wiphy_delayed_work_cancel(mld->wiphy, &mld->low_latency.work);

	iwl_mld_low_latency_free(mld);
}

void iwl_mld_low_latency_restart_cleanup(struct iwl_mld *mld)
{
	struct iwl_mld_low_latency *ll = &mld->low_latency;

	memset(ll->result, 0, sizeof(ll->result));

	for (int q = 0; q < mld->trans->num_rx_queues; q++)
		memset(ll->pkts_counters[q].vo_vi, 0,
		       sizeof(ll->pkts_counters[q].vo_vi));

	iwl_mld_low_latency_setup_timestamps(mld);
}

static int iwl_mld_send_low_latency_cmd(struct iwl_mld *mld, bool low_latency,
					u16 mac_id)
{
	struct iwl_mac_low_latency_cmd cmd = {
		.mac_id = cpu_to_le32(mac_id)
	};
	u16 cmd_id = WIDE_ID(MAC_CONF_GROUP, LOW_LATENCY_CMD);
	int ret;

	if (low_latency) {
		/* Currently we don't care about the direction */
		cmd.low_latency_rx = 1;
		cmd.low_latency_tx = 1;
	}

	ret = iwl_mld_send_cmd_pdu(mld, cmd_id, &cmd);
	if (ret)
		IWL_ERR(mld, "Failed to send low latency command\n");

	return ret;
}

static void iwl_mld_vif_set_low_latency(struct iwl_mld_vif *mld_vif, bool set,
					enum iwl_mld_low_latency_cause cause)
{
	if (set)
		mld_vif->low_latency_causes |= cause;
	else
		mld_vif->low_latency_causes &= ~cause;
}

void iwl_mld_vif_update_low_latency(struct iwl_mld *mld,
				    struct ieee80211_vif *vif,
				    bool low_latency,
				    enum iwl_mld_low_latency_cause cause)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	bool prev;

	prev = iwl_mld_vif_low_latency(mld_vif);
	iwl_mld_vif_set_low_latency(mld_vif, low_latency, cause);

	low_latency = iwl_mld_vif_low_latency(mld_vif);
	if (low_latency == prev)
		return;

	if (iwl_mld_send_low_latency_cmd(mld, low_latency, mld_vif->fw_id)) {
		/* revert to previous low-latency state */
		iwl_mld_vif_set_low_latency(mld_vif, prev, cause);
		return;
	}

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_P2P_CLIENT)
		return;

	iwl_mld_update_mac_power(mld, vif, false);
}

static bool iwl_mld_is_vo_vi_pkt(struct ieee80211_hdr *hdr)
{
	u8 tid;
	static const u8 tid_to_mac80211_ac[] = {
		IEEE80211_AC_BE,
		IEEE80211_AC_BK,
		IEEE80211_AC_BK,
		IEEE80211_AC_BE,
		IEEE80211_AC_VI,
		IEEE80211_AC_VI,
		IEEE80211_AC_VO,
		IEEE80211_AC_VO,
	};

	if (!hdr || !ieee80211_is_data_qos(hdr->frame_control))
		return false;

	tid = ieee80211_get_tid(hdr);
	if (tid >= IWL_MAX_TID_COUNT)
		return false;

	return tid_to_mac80211_ac[tid] < IEEE80211_AC_VI;
}

void iwl_mld_low_latency_update_counters(struct iwl_mld *mld,
					 struct ieee80211_hdr *hdr,
					 u8 mac_id, u8 queue)
{
	struct iwl_mld_low_latency_packets_counters *counters;

	/* we should have failed op mode init if NULL */
	if (WARN_ON_ONCE(!mld->low_latency.pkts_counters))
		return;

	if (WARN_ON_ONCE(mac_id >= ARRAY_SIZE(counters->vo_vi) ||
			 queue >= mld->trans->num_rx_queues))
		return;

	if (!iwl_mld_is_vo_vi_pkt(hdr))
		return;

	counters = &mld->low_latency.pkts_counters[queue];

	spin_lock_bh(&counters->lock);
	counters->vo_vi[mac_id]++;
	spin_unlock_bh(&counters->lock);

	if (time_is_before_jiffies(mld->low_latency.timestamp + MLD_LL_PERIOD))
		wiphy_delayed_work_queue(mld->wiphy, &mld->low_latency.work,
					 0);
}
