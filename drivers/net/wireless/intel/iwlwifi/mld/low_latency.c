// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mld.h"
#include "low_latency.h"

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
