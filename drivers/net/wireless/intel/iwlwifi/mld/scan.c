// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "scan.h"

#include "fw/api/scan.h"

int iwl_mld_alloc_scan_cmd(struct iwl_mld *mld)
{
	u8 scan_cmd_ver = iwl_fw_lookup_cmd_ver(mld->fw, SCAN_REQ_UMAC,
						IWL_FW_CMD_VER_UNKNOWN);
	size_t scan_cmd_size;

	if (scan_cmd_ver == 17) {
		scan_cmd_size = sizeof(struct iwl_scan_req_umac_v17);
	} else {
		IWL_ERR(mld, "Unexpected scan cmd version %d\n", scan_cmd_ver);
		return -EINVAL;
	}

	mld->scan.cmd = kmalloc(scan_cmd_size, GFP_KERNEL);
	if (!mld->scan.cmd)
		return -ENOMEM;

	mld->scan.cmd_size = scan_cmd_size;

	return 0;
}
