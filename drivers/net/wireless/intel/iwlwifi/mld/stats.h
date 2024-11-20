/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_stats_h__
#define __iwl_mld_stats_h__

int iwl_mld_request_fw_stats(struct iwl_mld *mld, bool clear);
int iwl_mld_request_periodic_fw_stats(struct iwl_mld *mld, bool enable);

void iwl_mld_handle_stats_oper_notif(struct iwl_mld *mld,
				     struct iwl_rx_packet *pkt);
void iwl_mld_handle_stats_oper_part1_notif(struct iwl_mld *mld,
					   struct iwl_rx_packet *pkt);

#endif /* __iwl_mld_stats_h__ */
