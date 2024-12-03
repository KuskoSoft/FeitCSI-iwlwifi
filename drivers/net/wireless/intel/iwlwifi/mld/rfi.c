// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "hcmd.h"
#include "rfi.h"
#include "fw/api/rfi.h"

struct iwl_rfi_freq_table_resp_cmd *
iwl_mld_rfi_get_freq_table(struct iwl_mld *mld)
{
	struct iwl_host_cmd cmd = {
		.id = WIDE_ID(SYSTEM_GROUP, RFI_GET_FREQ_TABLE_CMD),
		.flags = CMD_WANT_SKB,
	};
	struct iwl_rfi_freq_table_resp_cmd *resp = NULL;
	int ret;

	/* TODO: Check if DDR is supported before proceeding (task=RFI) */
	ret = iwl_mld_send_cmd(mld, &cmd);
	if (ret)
		return ERR_PTR(ret);

	if (IWL_FW_CHECK(mld,
			 iwl_rx_packet_payload_len(cmd.resp_pkt) !=
				sizeof(*resp),
			 "Unexpected RFI_GET_FREQ_TABLE_CMD response size %d (expected %ld)\n",
			 iwl_rx_packet_payload_len(cmd.resp_pkt),
			 sizeof(*resp))) {
		iwl_free_resp(&cmd);
		return ERR_PTR(-EIO);
	}

	resp = kmemdup(cmd.resp_pkt->data, sizeof(*resp), GFP_KERNEL);
	iwl_free_resp(&cmd);

	if (!resp)
		return ERR_PTR(-ENOMEM);

	return resp;
}

void iwl_mld_handle_rfi_support_notif(struct iwl_mld *mld,
				      struct iwl_rx_packet *pkt)
{
	const struct iwl_rfi_support_notif *notif = (void *)pkt->data;

	switch (le32_to_cpu(notif->reason)) {
	case IWL_RFI_DDR_SUBSET_TABLE_READY:
		IWL_DEBUG_FW(mld, "RFIm, DDR subset table ready\n");
		break;
	case IWL_RFI_PMC_SUPPORTED:
		IWL_DEBUG_FW(mld, "RFIm, PMC supported\n");
		break;
	case IWL_RFI_PMC_NOT_SUPPORTED:
		IWL_DEBUG_FW(mld, "RFIm, PMC not supported\n");
		break;
	default:
		IWL_DEBUG_FW(mld, "RFIm is deactivated, reason = %d\n",
			     le32_to_cpu(notif->reason));
	}
}
