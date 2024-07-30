// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_iface_h__
#define __iwl_mld_iface_h__

#include "mld.h"
#include "link.h"
#include "session-protect.h"

/**
 * struct iwl_mld_vif - virtual interface (MAC context) configuration parameters
 *
 * @fw_id: fw id of the mac context.
 * @ap_sta: pointer to AP sta, for easier access to it.
 *	Relevant only for STA vifs.
 * @authorized: indicates the AP station was set to authorized
 * @mld: pointer to the mld structure.
 * @deflink: default link data, for use in non-MLO,
 * @link: reference to link data for each valid link, for use in MLO.
 * @session_protect: session protection parameters
 */
struct iwl_mld_vif {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u8 fw_id;
		struct iwl_mld_session_protect session_protect;
		struct ieee80211_sta *ap_sta;
		bool authorized;
	);
	/* And here fields that survive a fw restart */
	struct iwl_mld *mld;
	struct iwl_mld_link deflink;
	struct iwl_mld_link __rcu *link[IEEE80211_MLD_MAX_NUM_LINKS];
};

static inline struct iwl_mld_vif *
iwl_mld_vif_from_mac80211(struct ieee80211_vif *vif)
{
	return (void *)vif->drv_priv;
}

#define iwl_mld_link_dereference_check(mld_vif, link_id)		\
	rcu_dereference_check((mld_vif)->link[link_id],			\
			      lockdep_is_held(&mld_vif->mld->wiphy->mtx))

#define for_each_mld_vif_valid_link(mld_vif, link)			\
	for (int link_id = 0; link_id < ARRAY_SIZE((mld_vif)->link);	\
	     link_id++)							\
		if ((link = iwl_mld_link_dereference_check(mld_vif, link_id)))

/* Retrieve pointer to mld link from mac80211 structures */
static inline struct iwl_mld_link *
iwl_mld_link_from_mac80211(struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(bss_conf->vif);

	return iwl_mld_link_dereference_check(mld_vif, bss_conf->link_id);
}

int iwl_mld_mac80211_iftype_to_fw(const struct ieee80211_vif *vif);

/* Cleanup function for struct iwl_mld_vif, will be called in restart */
void iwl_mld_cleanup_vif(void *data, u8 *mac, struct ieee80211_vif *vif);
int iwl_mld_mac_fw_action(struct iwl_mld *mld, struct ieee80211_vif *vif,
			  u32 action);
int iwl_mld_add_vif(struct iwl_mld *mld, struct ieee80211_vif *vif);
int iwl_mld_rm_vif(struct iwl_mld *mld, struct ieee80211_vif *vif);
void iwl_mld_set_vif_associated(struct iwl_mld *mld,
				struct ieee80211_vif *vif);
#endif /* __iwl_mld_iface_h__ */
