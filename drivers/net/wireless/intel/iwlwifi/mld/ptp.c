// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#include "mld.h"
#include "iwl-debug.h"
#include "ptp.h"
#include <linux/timekeeping.h>

/* The scaled_ppm parameter is ppm (parts per million) with a 16-bit fractional
 * part, which means that a value of 1 in one of those fields actually means
 * 2^-16 ppm, and 2^16=65536 is 1 ppm.
 */
#define PTP_SCALE_FACTOR	65536000000ULL

#define IWL_PTP_GP2_WRAP	0x100000000ULL
#define IWL_PTP_WRAP_TIME	(3600 * HZ)
#define IWL_PTP_WRAP_THRESHOLD_USEC	(5000)

static int iwl_mld_get_systime(struct iwl_mld *mld, u32 *gp2)
{
	*gp2 = iwl_read_prph(mld->trans, mld->trans->cfg->gp2_reg_addr);

	if (*gp2 == 0x5a5a5a5a)
		return -EINVAL;

	return 0;
}

static void iwl_mld_ptp_update_new_read(struct iwl_mld *mld, u32 gp2)
{
	IWL_DEBUG_PTP(mld, "PTP: last_gp2=%u, new gp2 read=%u\n",
		      mld->ptp_data.last_gp2, gp2);

	/* If the difference is above the threshold, assume it's a wraparound.
	 * Otherwise assume it's an old read and ignore it.
	 */
	if (gp2 < mld->ptp_data.last_gp2) {
		if (mld->ptp_data.last_gp2 - gp2 <
		    IWL_PTP_WRAP_THRESHOLD_USEC) {
			IWL_DEBUG_PTP(mld,
				      "PTP: ignore old read (gp2=%u, last_gp2=%u)\n",
				      gp2, mld->ptp_data.last_gp2);
			return;
		}

		mld->ptp_data.wrap_counter++;
		IWL_DEBUG_PTP(mld,
			      "PTP: wraparound detected (new counter=%u)\n",
			      mld->ptp_data.wrap_counter);
	}

	mld->ptp_data.last_gp2 = gp2;
	schedule_delayed_work(&mld->ptp_data.dwork, IWL_PTP_WRAP_TIME);
}

static u64 iwl_mld_ptp_get_adj_time(struct iwl_mld *mld, u64 base_time_ns)
{
	struct ptp_data *data = &mld->ptp_data;
	u64 scale_time_gp2_ns = mld->ptp_data.scale_update_gp2 * NSEC_PER_USEC;
	u64 res;
	u64 diff;
	s64 scaled_diff;

	lockdep_assert_held(&data->lock);

	iwl_mld_ptp_update_new_read(mld,
				    div64_u64(base_time_ns, NSEC_PER_USEC));

	base_time_ns = base_time_ns +
		(data->wrap_counter * IWL_PTP_GP2_WRAP * NSEC_PER_USEC);

	/* It is possible that a GP2 timestamp was received from fw before the
	 * last scale update.
	 */
	if (base_time_ns < scale_time_gp2_ns) {
		diff = scale_time_gp2_ns - base_time_ns;
		scaled_diff = -mul_u64_u64_div_u64(diff,
						   data->scaled_freq,
						   PTP_SCALE_FACTOR);
	} else {
		diff = base_time_ns - scale_time_gp2_ns;
		scaled_diff = mul_u64_u64_div_u64(diff,
						  data->scaled_freq,
						  PTP_SCALE_FACTOR);
	}

	IWL_DEBUG_PTP(mld, "base_time=%llu diff ns=%llu scaled_diff_ns=%lld\n",
		      (unsigned long long)base_time_ns,
		      (unsigned long long)diff, (long long)scaled_diff);

	res = data->scale_update_adj_time_ns + data->delta + scaled_diff;

	IWL_DEBUG_PTP(mld, "scale_update_ns=%llu delta=%lld adj=%llu\n",
		      (unsigned long long)data->scale_update_adj_time_ns,
		      (long long)data->delta, (unsigned long long)res);
	return res;
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

static int iwl_mld_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct iwl_mld *mld = container_of(ptp, struct iwl_mld,
					   ptp_data.ptp_clock_info);
	struct ptp_data *data = &mld->ptp_data;
	u32 gp2;

	/* Must call iwl_mld_ptp_get_adj_time() before updating
	 * data->scale_update_gp2 or data->scaled_freq since
	 * scale_update_adj_time_ns should reflect the previous scaled_freq.
	 */
	if (iwl_mld_get_systime(mld, &gp2)) {
		IWL_DEBUG_PTP(mld, "adjfine: failed to read systime\n");
		return -EBUSY;
	}

	spin_lock_bh(&data->lock);
	data->scale_update_adj_time_ns =
		iwl_mld_ptp_get_adj_time(mld, gp2 * NSEC_PER_USEC);
	data->scale_update_gp2 = gp2;

	/* scale_update_adj_time_ns now relects the configured delta, the
	 * wrap_counter and the previous scaled frequency. Thus delta and
	 * wrap_counter should be reset, and the scale frequency is updated
	 * to the new frequency.
	 */
	data->delta = 0;
	data->wrap_counter = 0;
	data->scaled_freq = PTP_SCALE_FACTOR + scaled_ppm;
	IWL_DEBUG_PTP(mld, "adjfine: scaled_ppm=%ld new=%llu\n",
		      scaled_ppm, (unsigned long long)data->scaled_freq);
	spin_unlock_bh(&data->lock);
	return 0;
}

static void iwl_mld_ptp_work(struct work_struct *wk)
{
	struct iwl_mld *mld = container_of(wk, struct iwl_mld,
					   ptp_data.dwork.work);
	struct ptp_data *data = &mld->ptp_data;
	u32 gp2;

	spin_lock_bh(&data->lock);
	if (!iwl_mld_get_systime(mld, &gp2))
		iwl_mld_ptp_update_new_read(mld, gp2);
	else
		IWL_DEBUG_PTP(mld, "PTP work: failed to read GP2\n");
	spin_unlock_bh(&data->lock);
}

void iwl_mld_ptp_init(struct iwl_mld *mld)
{
	if (WARN_ON(mld->ptp_data.ptp_clock))
		return;

	spin_lock_init(&mld->ptp_data.lock);
	INIT_DELAYED_WORK(&mld->ptp_data.dwork, iwl_mld_ptp_work);

	mld->ptp_data.ptp_clock_info.owner = THIS_MODULE;
	mld->ptp_data.ptp_clock_info.gettime64 = iwl_mld_ptp_gettime;
	mld->ptp_data.ptp_clock_info.max_adj = 0x7fffffff;
	mld->ptp_data.ptp_clock_info.adjtime = iwl_mld_ptp_adjtime;
	mld->ptp_data.ptp_clock_info.adjfine = iwl_mld_ptp_adjfine;
	mld->ptp_data.scaled_freq = PTP_SCALE_FACTOR;

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
		mld->ptp_data.last_gp2 = 0;
		mld->ptp_data.wrap_counter = 0;
		cancel_delayed_work_sync(&mld->ptp_data.dwork);
	}
}
