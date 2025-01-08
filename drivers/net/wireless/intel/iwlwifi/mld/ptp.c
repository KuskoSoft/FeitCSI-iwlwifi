// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#include "mld.h"
#include "iwl-debug.h"
#include "ptp.h"
#include <linux/timekeeping.h>

void iwl_mld_ptp_init(struct iwl_mld *mld)
{
	if (WARN_ON(mld->ptp_data.ptp_clock))
		return;

	mld->ptp_data.ptp_clock_info.owner = THIS_MODULE;

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
