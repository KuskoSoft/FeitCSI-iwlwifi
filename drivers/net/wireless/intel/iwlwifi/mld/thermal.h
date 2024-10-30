/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_thermal_h__
#define __iwl_mld_thermal_h__

#include "mld.h"
#include "iwl-trans.h"

void iwl_mld_handle_ct_kill_notif(struct iwl_mld *mld,
				  struct iwl_rx_packet *pkt);
void iwl_mld_thermal_initialize(struct iwl_mld *mld);
void iwl_mld_thermal_exit(struct iwl_mld *mld);

#endif /* __iwl_mld_thermal_h__ */
