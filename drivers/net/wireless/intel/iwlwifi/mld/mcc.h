/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_mcc_h__
#define __iwl_mld_mcc_h__

int iwl_mld_init_mcc(struct iwl_mld *mld);
void iwl_mld_handle_update_mcc(struct iwl_mld *mld, struct iwl_rx_packet *pkt);

#endif /* __iwl_mld_mcc_h__ */
