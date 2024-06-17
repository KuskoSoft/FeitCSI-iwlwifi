// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_link_h__
#define __iwl_mld_link_h__

#include <net/mac80211.h>

#include "mld.h"

/**
 * struct iwl_mld_link - link configuration parameters
 *
 * @fw_id: the fw id of the link.
 */
struct iwl_mld_link {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u8 fw_id;
	);
	/* And here fields that survive a fw restart */
};

/* Constructor function for struct iwl_mld_link */
static inline void
iwl_mld_init_link(struct iwl_mld *mld, struct iwl_mld_link *link, u8 fw_id)
{
	/* TODO: use a 'find_free_fw_id' here instead of a parameter */
	link->fw_id = fw_id;
}

/* Cleanup function for struct iwl_mld_phy, will be called in restart */
static inline void
iwl_mld_cleanup_link(struct iwl_mld_link *link)
{
	CLEANUP_STRUCT(link);
}

#endif /* __iwl_mld_link_h__ */
