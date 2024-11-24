// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_iface_h__
#define __iwl_mld_iface_h__

#include "mld.h"
#include "link.h"
#include "session-protect.h"
#include "d3.h"

enum iwl_mld_cca_40mhz_wa_status {
	CCA_40_MHZ_WA_NONE,
	CCA_40_MHZ_WA_RESET,
	CCA_40_MHZ_WA_RECONNECT,
};

/**
 * struct iwl_mld_vif - virtual interface (MAC context) configuration parameters
 *
 * @fw_id: fw id of the mac context.
 * @session_protect: session protection parameters
 * @ap_sta: pointer to AP sta, for easier access to it.
 *	Relevant only for STA vifs.
 * @authorized: indicates the AP station was set to authorized
 * @bigtks: BIGTKs of the AP, for beacon protection.
 *	Only valid for STA. (FIXME: needs to be per link)
 * @num_associated_stas: number of associated STAs. Relevant only for AP mode.
 * @ap_ibss_active: whether the AP/IBSS was started
 * @roc_activity: the id of the roc_activity running. Relevant for p2p device
 *	only. Set to %ROC_NUM_ACTIVITIES when not in use.
 * @cca_40mhz_workaround: When we are connected in 2.4 GHz and 40 MHz, and the
 *	environment is too loaded, we work around this by reconnecting to the
 *	same AP with 20 MHz. This manages the status of the workaround.
 * @beacon_inject_active: indicates an active debugfs beacon ie injection
 * @low_latency_causes: bit flags, indicating the causes for low-latency,
 *	see @iwl_mld_low_latency_cause.
 * @mld: pointer to the mld structure.
 * @deflink: default link data, for use in non-MLO,
 * @link: reference to link data for each valid link, for use in MLO.
 * @wowlan_data: data used by the wowlan suspend flow
 * @use_ps_poll: use ps_poll frames
 * @disable_bf: disable beacon filter
 * @dbgfs_slink: debugfs symlink for this interface
 * @dbgfs_slink_mvm: debugfs symlink for legacy tests support
 */
struct iwl_mld_vif {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u8 fw_id;
		struct iwl_mld_session_protect session_protect;
		struct ieee80211_sta *ap_sta;
		bool authorized;
		struct ieee80211_key_conf __rcu *bigtks[2];
		u8 num_associated_stas;
		bool ap_ibss_active;
		u32 roc_activity;
		enum iwl_mld_cca_40mhz_wa_status cca_40mhz_workaround;
#ifdef CPTCFG_IWLWIFI_DEBUGFS
		bool beacon_inject_active;
#endif
		u8 low_latency_causes;
	);
	/* And here fields that survive a fw restart */
	struct iwl_mld *mld;
	struct iwl_mld_link deflink;
	struct iwl_mld_link __rcu *link[IEEE80211_MLD_MAX_NUM_LINKS];

#if CONFIG_PM_SLEEP
	struct iwl_mld_wowlan_data wowlan_data;
#endif
#ifdef CPTCFG_IWLWIFI_DEBUGFS
	bool use_ps_poll;
	bool disable_bf;
	struct dentry *dbgfs_slink;
#ifdef HACK_IWLWIFI_DEBUGFS_IWLMVM_SYMLINK
	struct dentry *dbgfs_slink_mvm;
#endif
#endif
};

static inline struct iwl_mld_vif *
iwl_mld_vif_from_mac80211(struct ieee80211_vif *vif)
{
	return (void *)vif->drv_priv;
}

#define iwl_mld_link_dereference_check(mld_vif, link_id)		\
	rcu_dereference_check((mld_vif)->link[link_id],			\
			      lockdep_is_held(&mld_vif->mld->wiphy->mtx))

#define for_each_mld_vif_valid_link(mld_vif, mld_link)			\
	for (int link_id = 0; link_id < ARRAY_SIZE((mld_vif)->link);	\
	     link_id++)							\
		if ((mld_link = iwl_mld_link_dereference_check(mld_vif, link_id)))

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
u8 iwl_mld_get_fw_bss_vifs_ids(struct iwl_mld *mld);
void iwl_mld_handle_probe_resp_data_notif(struct iwl_mld *mld,
					  struct iwl_rx_packet *pkt);

void iwl_mld_handle_datapath_monitor_notif(struct iwl_mld *mld,
					   struct iwl_rx_packet *pkt);

void iwl_mld_reset_cca_40mhz_workaround(struct iwl_mld *mld,
					struct ieee80211_vif *vif);

static inline bool iwl_mld_vif_low_latency(const struct iwl_mld_vif *mld_vif)
{
	return !!mld_vif->low_latency_causes;
}

#endif /* __iwl_mld_iface_h__ */
