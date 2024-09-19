/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_d3_h__
#define __iwl_mld_d3_h__

#include "fw/api/d3.h"

/**
 * struct iwl_mld_wowlan_data - data used by the wowlan suspend flow
 *
 * @target_ipv6_addrs: IPv6 addresses on this interface for offload
 * @tentative_addrs: bitmap of tentative IPv6 addresses in @target_ipv6_addrs
 * @num_target_ipv6_addrs: number of @target_ipv6_addrs
 */
struct iwl_mld_wowlan_data {
	struct in6_addr target_ipv6_addrs[IWL_PROTO_OFFLOAD_NUM_IPV6_ADDRS_MAX];
	unsigned long tentative_addrs[BITS_TO_LONGS(IWL_PROTO_OFFLOAD_NUM_IPV6_ADDRS_MAX)];
	int num_target_ipv6_addrs;
};

int iwl_mld_no_wowlan_resume(struct iwl_mld *mld);
int iwl_mld_no_wowlan_suspend(struct iwl_mld *mld);
int iwl_mld_wowlan_suspend(struct iwl_mld *mld,
			   struct cfg80211_wowlan *wowlan);
int iwl_mld_wowlan_resume(struct iwl_mld *mld);

#endif /* __iwl_mld_d3_h__ */
