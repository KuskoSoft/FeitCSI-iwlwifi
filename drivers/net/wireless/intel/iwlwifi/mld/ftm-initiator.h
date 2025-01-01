// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_ftm_initiator_h__
#define __iwl_mld_ftm_initiator_h__

int iwl_mld_ftm_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
		      struct cfg80211_pmsr_request *req);

#endif /* __iwl_mld_ftm_initiator_h__ */
