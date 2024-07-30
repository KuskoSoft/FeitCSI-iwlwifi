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
 * @active: if the link is active or not.
 * @queue_params: QoS data from mac80211. This is updated with a call to
 *	drv_conf_tx per each AC, and then notified once with BSS_CHANGED_QOS.
 *	So we store it here and then send one link cmd for all the ACs.
 * @chan_ctx: pointer to the channel context assigned to the link. If a link
 *	has an assigned channel context it means that it is active.
 * @he_ru_2mhz_block: 26-tone RU OFDMA transmissions should be blocked.
 */
struct iwl_mld_link {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u8 fw_id;
		bool active;
		struct ieee80211_tx_queue_params queue_params[IEEE80211_NUM_ACS];
		struct ieee80211_chanctx_conf __rcu *chan_ctx;
		bool he_ru_2mhz_block;
	);
	/* And here fields that survive a fw restart */
};

/* Cleanup function for struct iwl_mld_phy, will be called in restart */
static inline void
iwl_mld_cleanup_link(struct iwl_mld_link *link)
{
	CLEANUP_STRUCT(link);
}

int iwl_mld_add_link(struct iwl_mld *mld,
		     struct ieee80211_bss_conf *bss_conf);
int iwl_mld_remove_link(struct iwl_mld *mld,
			struct ieee80211_bss_conf *bss_conf);
int iwl_mld_activate_link(struct iwl_mld *mld,
			  struct ieee80211_bss_conf *link);
int iwl_mld_deactivate_link(struct iwl_mld *mld,
			    struct ieee80211_bss_conf *link);
int iwl_mld_change_link_in_fw(struct iwl_mld *mld,
			      struct ieee80211_bss_conf *link, u32 changes);
void iwl_mld_handle_missed_beacon_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt);
int iwl_mld_link_set_associated(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *link);
#endif /* __iwl_mld_link_h__ */
