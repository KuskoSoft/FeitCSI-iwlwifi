// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "thermal.h"
#include "mld.h"

#define IWL_MLD_CT_KILL_DURATION (5 * HZ)

void iwl_mld_handle_ct_kill_notif(struct iwl_mld *mld,
				  struct iwl_rx_packet *pkt)
{
	const struct ct_kill_notif *notif = (const void *)pkt->data;

	IWL_ERR(mld,
		"CT Kill notification: temp = %d, DTS = 0x%x, Scheme 0x%x - Enter CT Kill\n",
		le16_to_cpu(notif->temperature), notif->dts,
		notif->scheme);

	iwl_mld_set_ctkill(mld, true);

	wiphy_delayed_work_queue(mld->wiphy, &mld->ct_kill_exit_wk,
				 round_jiffies_relative(IWL_MLD_CT_KILL_DURATION));
}

static void iwl_mld_exit_ctkill(struct wiphy *wiphy, struct wiphy_work *wk)
{
	struct iwl_mld *mld;

	mld = container_of(wk, struct iwl_mld, ct_kill_exit_wk.work);

	IWL_ERR(mld, "Exit CT Kill\n");
	iwl_mld_set_ctkill(mld, false);
}

void iwl_mld_thermal_initialize(struct iwl_mld *mld)
{
	wiphy_delayed_work_init(&mld->ct_kill_exit_wk, iwl_mld_exit_ctkill);
}

void iwl_mld_thermal_exit(struct iwl_mld *mld)
{
	wiphy_delayed_work_cancel(mld->wiphy, &mld->ct_kill_exit_wk);
}
