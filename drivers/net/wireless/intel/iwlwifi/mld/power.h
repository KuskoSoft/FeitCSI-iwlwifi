/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_power_h__
#define __iwl_mld_power_h__

int iwl_mld_power_update_device(struct iwl_mld *mld);

int iwl_mld_disable_beacon_filter(struct iwl_mld *mld,
				  struct ieee80211_vif *vif);

void
iwl_mld_send_ap_tx_power_constraint_cmd(struct iwl_mld *mld,
					struct ieee80211_vif *vif,
					struct ieee80211_bss_conf *link);

#endif /* __iwl_mld_power_h__ */
