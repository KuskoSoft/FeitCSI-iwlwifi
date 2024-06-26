// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mld.h"
#include "hcmd.h"
#include "power.h"

int iwl_mld_power_update_device(struct iwl_mld *mld)
{
	struct iwl_device_power_cmd cmd = {};

	/* TODO: CAM MODE, DEVICE_POWER_FLAGS_POWER_SAVE_ENA_MSK */

	/* TODO: DEVICE_POWER_FLAGS_32K_CLK_VALID_MSK */

	/* TODO: DEVICE_POWER_FLAGS_NO_SLEEP_TILL_D3_MSK */

	IWL_DEBUG_POWER(mld,
			"Sending device power command with flags = 0x%X\n",
			cmd.flags);

	return iwl_mld_send_cmd_pdu(mld, POWER_TABLE_CMD, sizeof(cmd), &cmd);
}
