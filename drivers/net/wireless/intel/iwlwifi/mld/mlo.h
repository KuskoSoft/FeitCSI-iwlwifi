// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_mlo_h__
#define __iwl_mld_mlo_h__

#include <linux/ieee80211.h>
#include <linux/types.h>
#include <net/mac80211.h>
#include "iwl-config.h"
#include "iwl-trans.h"
#include "iface.h"

struct iwl_mld;

void iwl_mld_emlsr_prevent_done_wk(struct wiphy *wiphy, struct wiphy_work *wk);

static inline bool iwl_mld_emlsr_active(struct ieee80211_vif *vif)
{
	/* Set on phy context activation, so should be a good proxy */
	return !!(vif->driver_flags & IEEE80211_VIF_EML_ACTIVE);
}

static inline bool iwl_mld_vif_has_emlsr(struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	/* We only track/permit EMLSR state once authorized */
	if (!mld_vif->authorized)
		return false;

	/* No EMLSR on dual radio devices */
	return ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION &&
	       ieee80211_vif_is_mld(vif) &&
	       vif->cfg.eml_cap & IEEE80211_EML_CAP_EMLSR_SUPP &&
	       !CSR_HW_RFID_IS_CDB(mld_vif->mld->trans->hw_rf_id);
}

static inline int
iwl_mld_max_active_links(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	if (vif->type == NL80211_IFTYPE_AP)
		return mld->fw->ucode_capa.num_beacons;

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION)
		return IWL_FW_MAX_ACTIVE_LINKS_NUM;

	/* For now, do not accept more links on other interface types */
	return 1;
}

static inline int
iwl_mld_count_active_links(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *mld_link;
	int n_active = 0;

	for_each_mld_vif_valid_link(mld_vif, mld_link) {
		if (rcu_access_pointer(mld_link->chan_ctx))
			n_active++;
	}

	return n_active;
}

static inline u8 iwl_mld_get_primary_link(struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	lockdep_assert_wiphy(mld_vif->mld->wiphy);

	if (!ieee80211_vif_is_mld(vif) || WARN_ON(!vif->active_links))
		return 0;

	/* In AP mode, there is no primary link */
	if (vif->type == NL80211_IFTYPE_AP)
		return __ffs(vif->active_links);

	if (iwl_mld_emlsr_active(vif) &&
	    !WARN_ON(!(BIT(mld_vif->emlsr.primary) & vif->active_links)))
		return mld_vif->emlsr.primary;

	return __ffs(vif->active_links);
}

/*
 * For non-MLO/single link, this will return the deflink/single active link,
 * respectively
 */
static inline u8 iwl_mld_get_other_link(struct ieee80211_vif *vif, u8 link_id)
{
	switch (hweight16(vif->active_links)) {
	case 0:
		return 0;
	default:
		WARN_ON(1);
		fallthrough;
	case 1:
		return __ffs(vif->active_links);
	case 2:
		return __ffs(vif->active_links & ~BIT(link_id));
	}
}

/* EMLSR block/unblock and exit */
void iwl_mld_block_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			 enum iwl_mld_emlsr_blocked reason, u8 link_to_keep);
int iwl_mld_block_emlsr_sync(struct iwl_mld *mld, struct ieee80211_vif *vif,
			     enum iwl_mld_emlsr_blocked reason, u8 link_to_keep);
void iwl_mld_unblock_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			   enum iwl_mld_emlsr_blocked reason);
void iwl_mld_exit_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			enum iwl_mld_emlsr_exit exit, u8 link_to_keep);

void iwl_mld_select_links(struct iwl_mld *mld);

#endif /* __iwl_mld_mlo_h__ */
