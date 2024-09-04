// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_tlc_h__
#define __iwl_mld_tlc_h__

#include "mld.h"

void iwl_mld_send_tlc_cmd(struct iwl_mld *mld, struct ieee80211_vif *vif,
			  struct ieee80211_link_sta *link_sta,
			  enum nl80211_band band);

#endif /* __iwl_mld_tlc_h__ */
