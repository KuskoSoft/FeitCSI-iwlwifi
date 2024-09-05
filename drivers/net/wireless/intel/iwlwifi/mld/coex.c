// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "fw/api/coex.h"

#include "coex.h"
#include "mld.h"
#include "hcmd.h"

int iwl_mld_send_bt_init_conf(struct iwl_mld *mld)
{
	struct iwl_bt_coex_cmd cmd = {
		.mode = cpu_to_le32(BT_COEX_NW),
		.enabled_modules = cpu_to_le32(BT_COEX_MPLUT_ENABLED |
					       BT_COEX_HIGH_BAND_RET),
	};

	return iwl_mld_send_cmd_pdu(mld, BT_CONFIG, &cmd);
}
