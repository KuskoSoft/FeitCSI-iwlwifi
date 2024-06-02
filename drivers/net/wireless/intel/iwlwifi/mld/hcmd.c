// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "hcmd.h"

int iwl_mld_send_cmd_with_flags_pdu(struct iwl_mld *mld, u32 id,
				    u32 flags, u16 len, const void *data)
{
	struct iwl_host_cmd cmd = {
		.id = id,
		.len = { len, },
		.data = { data, },
		.flags = flags,
	};

	return iwl_mld_send_cmd(mld, &cmd);
}

int iwl_mld_send_cmd_pdu(struct iwl_mld *mld, u32 id,
			 u16 len, const void *data)
{
	return iwl_mld_send_cmd_with_flags_pdu(mld, id, 0, len, data);
}
