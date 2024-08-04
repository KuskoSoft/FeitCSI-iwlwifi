// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mld.h"

#include "d3.h"
#include "power.h"
#include "hcmd.h"

#include "fw/api/d3.h"
#include "fw/api/offload.h"
#include "fw/dbg.h"

/**
 * enum iwl_mld_d3_notif - d3 notifications
 * @IWL_D3_NOTIF_D3_END_NOTIF: D3_END_NOTIF is expected/was received
 */
enum iwl_mld_d3_notif {
	IWL_D3_NOTIF_D3_END_NOTIF =	BIT(0)
};

/**
 * struct iwl_mld_resume_data - d3 resume flow data
 * @notifs_expected: bitmap of expected notifications from fw,
 *	see &enum iwl_mld_d3_notif
 * @notifs_received: bitmap of received notifications from fw,
 *	see &enum iwl_mld_d3_notif
 * @d3_end_flags: bitmap of flags from d3_end_notif
 */
struct iwl_mld_resume_data {
	u32 notifs_expected;
	u32 notifs_received;
	u32 d3_end_flags;
};

static bool iwl_mld_check_err_tables(struct iwl_mld *mld,
				     struct ieee80211_vif *vif)
{
	u32 err_id;

	/* check for lmac1 error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.lmac_error_event_table[0],
				    &err_id)) {
		if (err_id == RF_KILL_INDICATOR_FOR_WOWLAN && vif) {
			struct cfg80211_wowlan_wakeup wakeup = {
				.rfkill_release = true,
			};
			ieee80211_report_wowlan_wakeup(vif, &wakeup,
						       GFP_KERNEL);
		}
		return true;
	}

	/* check if we have lmac2 set and check for error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.lmac_error_event_table[1],
				    NULL))
		return true;

	/* check for umac error */
	if (iwl_fwrt_read_err_table(mld->trans,
				    mld->trans->dbg.umac_error_event_table,
				    NULL))
		return true;

	return false;
}

static bool iwl_mld_handle_d3_notif(struct iwl_notif_wait_data *notif_wait,
				    struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mld_resume_data *resume_data = data;

	switch (WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd)) {
	case WIDE_ID(PROT_OFFLOAD_GROUP, D3_END_NOTIFICATION): {
		struct iwl_d3_end_notif *notif = (void *)pkt->data;

		resume_data->d3_end_flags = le32_to_cpu(notif->flags);
		resume_data->notifs_received |= IWL_D3_NOTIF_D3_END_NOTIF;
		break;
	}
	default:
		WARN_ON(1);
	}

	return resume_data->notifs_received == resume_data->notifs_expected;
}

#define IWL_MLD_D3_NOTIF_TIMEOUT (HZ / 3 * CPTCFG_IWL_TIMEOUT_FACTOR)

static int iwl_mld_wait_d3_notif(struct iwl_mld *mld,
				 struct iwl_mld_resume_data *resume_data)
{
	static const u16 d3_resume_notif[] = {
		WIDE_ID(PROT_OFFLOAD_GROUP, D3_END_NOTIFICATION)
	};
	struct iwl_notification_wait wait_d3_notif;
	enum iwl_d3_status d3_status;
	int ret;

	/* TODO: handle wowlan notifications */
	iwl_init_notification_wait(&mld->notif_wait, &wait_d3_notif,
				   d3_resume_notif,
				   ARRAY_SIZE(d3_resume_notif),
				   iwl_mld_handle_d3_notif, resume_data);

	ret = iwl_trans_d3_resume(mld->trans, &d3_status, false, false);
	if (ret || d3_status != IWL_D3_STATUS_ALIVE) {
		if (d3_status != IWL_D3_STATUS_ALIVE) {
			IWL_INFO(mld, "Device was reset during suspend\n");
			ret = -ENOENT;
		} else {
			IWL_ERR(mld, "Transport resume failed\n");
		}
		iwl_remove_notification(&mld->notif_wait, &wait_d3_notif);
		return ret;
	}

	ret = iwl_wait_notification(&mld->notif_wait, &wait_d3_notif,
				    IWL_MLD_D3_NOTIF_TIMEOUT);
	if (ret)
		IWL_ERR(mld, "Couldn't get the d3 notif %d\n", ret);

	return ret;
}

int iwl_mld_no_wowlan_suspend(struct iwl_mld *mld)
{
	struct iwl_d3_manager_config d3_cfg_cmd_data = {};
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	IWL_DEBUG_WOWLAN(mld, "Starting the no wowlan suspend flow\n");

	/* This will happen if iwl_mld_supsend failed with FW error */
	if (mld->trans->state == IWL_TRANS_NO_FW &&
	    test_bit(STATUS_FW_ERROR, &mld->trans->status))
		return -ENODEV;

	WARN_ON(iwl_mld_power_update_device(mld));
	ret = iwl_mld_send_cmd_pdu(mld, D3_CONFIG_CMD,
				   &d3_cfg_cmd_data);
	if (ret) {
		IWL_ERR(mld,
			"d3 suspend: couldn't send D3_CONFIG_CMD %d\n", ret);
		goto out;
	}

	/* TODO: task power iwl_mld_power_update_mac() */

	ret = iwl_trans_d3_suspend(mld->trans, false, false);
	if (ret) {
		IWL_ERR(mld, "d3 suspend: trans_d3_suspend failed %d\n", ret);
	} else {
		mld->trans->system_pm_mode = IWL_PLAT_PM_MODE_D3;
		mld->fw_status.in_d3 = true;
	}

 out:
	if (ret) {
		mld->trans->state = IWL_TRANS_NO_FW;
		set_bit(STATUS_FW_ERROR, &mld->trans->status);
	}

	return ret;
}

int iwl_mld_no_wowlan_resume(struct iwl_mld *mld)
{
	struct iwl_mld_resume_data resume_data = {
		.notifs_expected =
			IWL_D3_NOTIF_D3_END_NOTIF,
	};
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	IWL_DEBUG_WOWLAN(mld, "Starting the no wowlan resume flow\n");

	mld->trans->system_pm_mode = IWL_PLAT_PM_MODE_DISABLED;
	mld->fw_status.in_d3 = false;
	iwl_fw_dbg_read_d3_debug_data(&mld->fwrt);

	if (iwl_mld_check_err_tables(mld, NULL))
		ret = -ENODEV;
	else
		ret = iwl_mld_wait_d3_notif(mld, &resume_data);

	if (!ret && (resume_data.d3_end_flags & IWL_D0I3_RESET_REQUIRE))
		return -ENODEV;

	if (ret) {
		mld->trans->state = IWL_TRANS_NO_FW;
		set_bit(STATUS_FW_ERROR, &mld->trans->status);
	}

	return ret;
}
