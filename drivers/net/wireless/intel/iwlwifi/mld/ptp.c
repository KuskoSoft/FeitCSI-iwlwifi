// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#include "mld.h"
#include "iwl-debug.h"
#include "ptp.h"
#include <linux/timekeeping.h>

static int iwl_mld_get_systime(struct iwl_mld *mld, u32 *gp2)
{
	*gp2 = iwl_read_prph(mld->trans, mld->trans->cfg->gp2_reg_addr);

	if (*gp2 == 0x5a5a5a5a)
		return -EINVAL;

	return 0;
}

static u64 iwl_mld_ptp_get_adj_time(struct iwl_mld *mld, u64 base_time_ns)
{
	struct ptp_data *data = &mld->ptp_data;

	lockdep_assert_held(&data->lock);

	return base_time_ns + data->delta;
}

static int iwl_mld_ptp_gettime(struct ptp_clock_info *ptp,
			       struct timespec64 *ts)
{
	struct iwl_mld *mld = container_of(ptp, struct iwl_mld,
					   ptp_data.ptp_clock_info);
	struct ptp_data *data = &mld->ptp_data;
	u32 gp2;
	u64 ns;

	if (iwl_mld_get_systime(mld, &gp2)) {
		IWL_DEBUG_PTP(mld, "PTP: gettime: failed to read systime\n");
		return -EIO;
	}

	spin_lock_bh(&data->lock);
	ns = iwl_mld_ptp_get_adj_time(mld, (u64)gp2 * NSEC_PER_USEC);
	spin_unlock_bh(&data->lock);

	*ts = ns_to_timespec64(ns);
	return 0;
}

static int iwl_mld_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct iwl_mld *mld = container_of(ptp, struct iwl_mld,
					   ptp_data.ptp_clock_info);
	struct ptp_data *data = &mld->ptp_data;

	spin_lock_bh(&data->lock);
	data->delta += delta;
	IWL_DEBUG_PTP(mld, "delta=%lld, new delta=%lld\n", (long long)delta,
		      (long long)data->delta);
	spin_unlock_bh(&data->lock);
	return 0;
}

void iwl_mld_ptp_init(struct iwl_mld *mld)
{
	if (WARN_ON(mld->ptp_data.ptp_clock))
		return;

	spin_lock_init(&mld->ptp_data.lock);

	mld->ptp_data.ptp_clock_info.owner = THIS_MODULE;
	mld->ptp_data.ptp_clock_info.gettime64 = iwl_mld_ptp_gettime;
	mld->ptp_data.ptp_clock_info.max_adj = 0x7fffffff;
	mld->ptp_data.ptp_clock_info.adjtime = iwl_mld_ptp_adjtime;

	/* Give a short 'friendly name' to identify the PHC clock */
	snprintf(mld->ptp_data.ptp_clock_info.name,
		 sizeof(mld->ptp_data.ptp_clock_info.name),
		 "%s", "iwlwifi-PTP");

	mld->ptp_data.ptp_clock =
		ptp_clock_register(&mld->ptp_data.ptp_clock_info, mld->dev);

	if (IS_ERR_OR_NULL(mld->ptp_data.ptp_clock)) {
		IWL_ERR(mld, "Failed to register PHC clock (%ld)\n",
			PTR_ERR(mld->ptp_data.ptp_clock));
		mld->ptp_data.ptp_clock = NULL;
	} else {
		IWL_INFO(mld, "Registered PHC clock: %s, with index: %d\n",
			 mld->ptp_data.ptp_clock_info.name,
			 ptp_clock_index(mld->ptp_data.ptp_clock));
	}
}

void iwl_mld_ptp_remove(struct iwl_mld *mld)
{
	if (mld->ptp_data.ptp_clock) {
		IWL_INFO(mld, "Unregistering PHC clock: %s, with index: %d\n",
			 mld->ptp_data.ptp_clock_info.name,
			 ptp_clock_index(mld->ptp_data.ptp_clock));

		ptp_clock_unregister(mld->ptp_data.ptp_clock);
		mld->ptp_data.ptp_clock = NULL;
	}
}
