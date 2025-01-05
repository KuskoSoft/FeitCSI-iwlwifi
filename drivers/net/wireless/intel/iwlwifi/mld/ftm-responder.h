/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_ftm_responder_h__
#define __iwl_mld_ftm_responder_h__

int iwl_mld_ftm_start_responder(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *bss_conf);

#endif /* __iwl_mld_ftm_responder_h__ */
