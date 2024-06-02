// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_hcmd_h__
#define __iwl_mld_hcmd_h__

static inline int iwl_mld_send_cmd(struct iwl_mld *mld, struct iwl_host_cmd *cmd)
{
	int ret;

	/* Devices that need to shutdown immediately on rfkill are not
	 * supported, so we can send all the cmds in rfkill
	 */
	cmd->flags |= CMD_SEND_IN_RFKILL;

	ret = iwl_trans_send_cmd(mld->trans, cmd);

	return ret;
}

int iwl_mld_send_cmd_with_flags_pdu(struct iwl_mld *mld, u32 id,
				    u32 flags, u16 len, const void *data);

int iwl_mld_send_cmd_pdu(struct iwl_mld *mld, u32 id,
			 u16 len, const void *data);

#endif /* __iwl_mld_hcmd_h__ */
