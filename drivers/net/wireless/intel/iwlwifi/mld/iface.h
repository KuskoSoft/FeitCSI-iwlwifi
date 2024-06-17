// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_iface_h__
#define __iwl_mld_iface_h__

#include "mld.h"

/**
 * struct iwl_mld_vif - virtual interface (MAC context) configuration parameters
 *
 * @id: fw id of the mac context.
 */
struct iwl_mld_vif {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u8 id;
	);
	/* And here fields that survive a fw restart */
};

static inline struct iwl_mld_vif *
iwl_mld_vif_from_mac80211(struct ieee80211_vif *vif)
{
	return (void *)vif->drv_priv;
}

/* Constructor function for struct iwl_mld_vif */
static inline void
iwl_mld_init_vif(struct iwl_mld *mld, struct iwl_mld_vif *mld_vif, u8 id)
{
	/* TODO: use 'find_free_vif' here instead of a parameter */
	mld_vif->id = id;
}

/* Cleanup function for struct iwl_mld_vif, will be called in restart */
static inline void
iwl_mld_cleanup_vif(void *data, u8 *mac, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	CLEANUP_STRUCT(mld_vif);
}

#endif /* __iwl_mld_iface_h__ */
