// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "rfi.h"
#include "fw/api/rfi.h"

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
