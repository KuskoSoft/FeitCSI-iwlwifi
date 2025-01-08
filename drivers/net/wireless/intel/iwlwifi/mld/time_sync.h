/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_time_sync_h__
#define __iwl_mld_time_sync_h__

struct iwl_mld_time_sync_data {
	struct rcu_head rcu_head;
	u8 peer_addr[ETH_ALEN];
	u32 active_protocols;
};

int iwl_mld_time_sync_config(struct iwl_mld *mld, const u8 *addr,
			     u32 protocols);
int iwl_mld_time_sync_fw_config(struct iwl_mld *mld);
void iwl_mld_deinit_time_sync(struct iwl_mld *mld);

#endif /* __iwl_mld_time_sync_h__ */
