// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#ifndef __iwl_mld_kunit_utils_h__
#define __iwl_mld_kunit_utils_h__

struct iwl_mld;

int kunit_test_init(struct kunit *test);

enum nl80211_iftype;

struct ieee80211_vif *kunit_add_vif(bool mlo, enum nl80211_iftype type);

struct ieee80211_bss_conf *kunit_add_link(struct ieee80211_vif *vif,
					  int link_id);
#endif /* __iwl_mld_kunit_utils_h__ */
