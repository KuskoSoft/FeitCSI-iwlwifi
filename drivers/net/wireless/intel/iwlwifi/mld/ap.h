
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_ap_h__
#define __iwl_ap_h__

#include "mld.h"

int iwl_mld_update_beacon_template(struct iwl_mld *mld,
				   struct ieee80211_vif *vif,
				   struct ieee80211_bss_conf *link_conf);

#endif /* __iwl_ap_h__ */
