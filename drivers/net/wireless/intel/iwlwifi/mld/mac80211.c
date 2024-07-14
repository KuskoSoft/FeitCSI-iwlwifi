// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"
#include "mac80211.h"
#include "phy.h"
#include "iface.h"
#include "power.h"
#include "fw/api/scan.h"
#ifdef CONFIG_PM_SLEEP
#include "fw/api/d3.h"
#endif /* CONFIG_PM_SLEEP */

#define IWL_MLD_LIMITS(ap)					\
	{							\
		.max = 1,					\
		.types = BIT(NL80211_IFTYPE_STATION),		\
	},							\
	{							\
		.max = 1,					\
		.types = ap |					\
			 BIT(NL80211_IFTYPE_P2P_CLIENT) |	\
			 BIT(NL80211_IFTYPE_P2P_GO),		\
	},							\
	{							\
		.max = 1,					\
		.types = BIT(NL80211_IFTYPE_P2P_DEVICE),	\
	}

static const struct ieee80211_iface_limit iwl_mld_limits[] = {
	IWL_MLD_LIMITS(0)
};

static const struct ieee80211_iface_limit iwl_mld_limits_ap[] = {
	IWL_MLD_LIMITS(BIT(NL80211_IFTYPE_AP))
};

static const struct ieee80211_iface_combination
iwl_mld_iface_combinations[] = {
	{
		.num_different_channels = 2,
		.max_interfaces = 3,
		.limits = iwl_mld_limits,
		.n_limits = ARRAY_SIZE(iwl_mld_limits),
	},
	{
		.num_different_channels = 1,
		.max_interfaces = 3,
		.limits = iwl_mld_limits_ap,
		.n_limits = ARRAY_SIZE(iwl_mld_limits_ap),
	},
};

/* Each capability added here should also be add to tm_if_types_ext_capa_sta */
static const u8 if_types_ext_capa_sta[] = {
	 [0] = WLAN_EXT_CAPA1_EXT_CHANNEL_SWITCHING,
	 [2] = WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT,
	 [7] = WLAN_EXT_CAPA8_OPMODE_NOTIF |
	       WLAN_EXT_CAPA8_MAX_MSDU_IN_AMSDU_LSB,
	 [8] = WLAN_EXT_CAPA9_MAX_MSDU_IN_AMSDU_MSB,
};

#define IWL_MLD_EMLSR_CAPA	(IEEE80211_EML_CAP_EMLSR_SUPP | \
				 IEEE80211_EML_CAP_EMLSR_PADDING_DELAY_32US << \
					__bf_shf(IEEE80211_EML_CAP_EMLSR_PADDING_DELAY) | \
				 IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY_64US << \
					__bf_shf(IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY))
#define IWL_MLD_CAPA_OPS FIELD_PREP_CONST( \
			IEEE80211_MLD_CAP_OP_TID_TO_LINK_MAP_NEG_SUPP, \
			IEEE80211_MLD_CAP_OP_TID_TO_LINK_MAP_NEG_SUPP_SAME)

/* TODO:
 * 1. AX_SOFTAP_TESTMODE
 * 2. tm (time measurement)
 */
static const struct wiphy_iftype_ext_capab iftypes_ext_capa[] = {
	{
		.iftype = NL80211_IFTYPE_STATION,
		.extended_capabilities = if_types_ext_capa_sta,
		.extended_capabilities_mask = if_types_ext_capa_sta,
		.extended_capabilities_len = sizeof(if_types_ext_capa_sta),
		/* relevant only if EHT is supported */
		.eml_capabilities = IWL_MLD_EMLSR_CAPA,
		.mld_capa_and_ops = IWL_MLD_CAPA_OPS,
	},
};

static void iwl_mld_hw_set_addresses(struct iwl_mld *mld)
{
	struct wiphy *wiphy = mld->wiphy;
	int num_addrs = 1;

	/* Extract MAC address */
	memcpy(mld->addresses[0].addr, mld->nvm_data->hw_addr, ETH_ALEN);
	wiphy->addresses = mld->addresses;
	wiphy->n_addresses = 1;

	/* Extract additional MAC addresses if available */
	if (mld->nvm_data->n_hw_addrs > 1)
		num_addrs = min(mld->nvm_data->n_hw_addrs,
				IWL_MLD_MAX_ADDRESSES);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (mld->trans->dbg_cfg.hw_address.len)
		num_addrs = IWL_MLD_MAX_ADDRESSES;
#endif

	for (int i = 1; i < num_addrs; i++) {
		memcpy(mld->addresses[i].addr,
		       mld->addresses[i - 1].addr,
		       ETH_ALEN);
		mld->addresses[i].addr[ETH_ALEN - 1]++;
		wiphy->n_addresses++;
	}
}

static void iwl_mld_hw_set_channels(struct iwl_mld *mld)
{
	struct wiphy *wiphy = mld->wiphy;
	struct ieee80211_supported_band *bands = mld->nvm_data->bands;

	wiphy->bands[NL80211_BAND_2GHZ] = &bands[NL80211_BAND_2GHZ];
	wiphy->bands[NL80211_BAND_5GHZ] = &bands[NL80211_BAND_5GHZ];

	if (bands[NL80211_BAND_6GHZ].n_channels)
		wiphy->bands[NL80211_BAND_6GHZ] = &bands[NL80211_BAND_6GHZ];
}

static void iwl_mld_hw_set_security(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;
	static const u32 mld_ciphers[] = {
		WLAN_CIPHER_SUITE_WEP40,
		WLAN_CIPHER_SUITE_WEP104,
		WLAN_CIPHER_SUITE_TKIP,
		WLAN_CIPHER_SUITE_CCMP,
		WLAN_CIPHER_SUITE_GCMP,
		WLAN_CIPHER_SUITE_GCMP_256,
		WLAN_CIPHER_SUITE_AES_CMAC,
		WLAN_CIPHER_SUITE_BIP_GMAC_128,
		WLAN_CIPHER_SUITE_BIP_GMAC_256
	};

	hw->wiphy->n_cipher_suites = ARRAY_SIZE(mld_ciphers);
	hw->wiphy->cipher_suites = mld_ciphers;

	ieee80211_hw_set(hw, MFP_CAPABLE);
	wiphy_ext_feature_set(hw->wiphy,
			      NL80211_EXT_FEATURE_BEACON_PROTECTION);
}

static void iwl_mld_hw_set_regulatory(struct iwl_mld *mld)
{
	struct wiphy *wiphy = mld->wiphy;

	wiphy->regulatory_flags |= REGULATORY_WIPHY_SELF_MANAGED;
	wiphy->regulatory_flags |= REGULATORY_ENABLE_RELAX_NO_IR;
}

static void iwl_mld_hw_set_antennas(struct iwl_mld *mld)
{
	struct wiphy *wiphy = mld->wiphy;

	wiphy->available_antennas_tx = iwl_mld_get_valid_tx_ant(mld);
	wiphy->available_antennas_rx = iwl_mld_get_valid_rx_ant(mld);
}

static void iwl_mld_hw_set_pm(struct iwl_mld *mld)
{
#ifdef CONFIG_PM_SLEEP
	struct wiphy *wiphy = mld->wiphy;

	if (!device_can_wakeup(mld->trans->dev))
		return;

	mld->wowlan.flags |= WIPHY_WOWLAN_MAGIC_PKT |
			     WIPHY_WOWLAN_DISCONNECT |
			     WIPHY_WOWLAN_EAP_IDENTITY_REQ |
			     WIPHY_WOWLAN_RFKILL_RELEASE |
			     WIPHY_WOWLAN_NET_DETECT |
			     WIPHY_WOWLAN_SUPPORTS_GTK_REKEY |
			     WIPHY_WOWLAN_GTK_REKEY_FAILURE |
			     WIPHY_WOWLAN_4WAY_HANDSHAKE;

	mld->wowlan.n_patterns = IWL_WOWLAN_MAX_PATTERNS;
	mld->wowlan.pattern_min_len = IWL_WOWLAN_MIN_PATTERN_LEN;
	mld->wowlan.pattern_max_len = IWL_WOWLAN_MAX_PATTERN_LEN;
	mld->wowlan.max_nd_match_sets = IWL_SCAN_MAX_PROFILES_V2;

	wiphy->wowlan = &mld->wowlan;
#endif /* CONFIG_PM_SLEEP */
}

static void iwl_mac_hw_set_radiotap(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;

	hw->radiotap_mcs_details |= IEEE80211_RADIOTAP_MCS_HAVE_FEC |
				    IEEE80211_RADIOTAP_MCS_HAVE_STBC;

	hw->radiotap_vht_details |= IEEE80211_RADIOTAP_VHT_KNOWN_STBC |
				    IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED;

	hw->radiotap_timestamp.units_pos =
		IEEE80211_RADIOTAP_TIMESTAMP_UNIT_US |
		IEEE80211_RADIOTAP_TIMESTAMP_SPOS_PLCP_SIG_ACQ;

	/* this is the case for CCK frames, it's better (only 8) for OFDM */
	hw->radiotap_timestamp.accuracy = 22;
}

static void iwl_mac_hw_set_flags(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;

	ieee80211_hw_set(hw, USES_RSS);
	ieee80211_hw_set(hw, HANDLES_QUIET_CSA);
	ieee80211_hw_set(hw, AP_LINK_PS);
	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, SPECTRUM_MGMT);
	ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(hw, WANT_MONITOR_VIF);
	ieee80211_hw_set(hw, SUPPORTS_PS);
	ieee80211_hw_set(hw, SUPPORTS_DYNAMIC_PS);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, CONNECTION_MONITOR);
	ieee80211_hw_set(hw, CHANCTX_STA_CSA);
	ieee80211_hw_set(hw, SUPPORT_FAST_XMIT);
	ieee80211_hw_set(hw, SUPPORTS_CLONED_SKBS);
	ieee80211_hw_set(hw, NEEDS_UNIQUE_STA_ADDR);
	ieee80211_hw_set(hw, SUPPORTS_VHT_EXT_NSS_BW);
	ieee80211_hw_set(hw, BUFF_MMPDU_TXQ);
	ieee80211_hw_set(hw, STA_MMPDU_TXQ);
	ieee80211_hw_set(hw, TX_AMSDU);
	ieee80211_hw_set(hw, TX_FRAG_LIST);
	ieee80211_hw_set(hw, TX_AMPDU_SETUP_IN_HW);
	ieee80211_hw_set(hw, HAS_RATE_CONTROL);
	ieee80211_hw_set(hw, SUPPORTS_REORDERING_BUFFER);
	ieee80211_hw_set(hw, DISALLOW_PUNCTURING_5GHZ);
	ieee80211_hw_set(hw, SINGLE_SCAN_ON_ALL_BANDS);
	ieee80211_hw_set(hw, SUPPORTS_AMSDU_IN_AMPDU);
	ieee80211_hw_set(hw, TDLS_WIDER_BW);
}

static void iwl_mac_hw_set_wiphy(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;
	struct wiphy *wiphy = hw->wiphy;
	const struct iwl_ucode_capabilities *ucode_capa = &mld->fw->ucode_capa;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				 BIT(NL80211_IFTYPE_P2P_CLIENT) |
				 BIT(NL80211_IFTYPE_AP) |
				 BIT(NL80211_IFTYPE_P2P_GO) |
				 BIT(NL80211_IFTYPE_P2P_DEVICE) |
				 BIT(NL80211_IFTYPE_ADHOC);

	wiphy->features |= NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR |
			   NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR |
			   NL80211_FEATURE_ND_RANDOM_MAC_ADDR |
			   NL80211_FEATURE_HT_IBSS |
			   NL80211_FEATURE_P2P_GO_CTWIN |
			   NL80211_FEATURE_LOW_PRIORITY_SCAN |
			   NL80211_FEATURE_P2P_GO_OPPPS |
			   NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE |
			   NL80211_FEATURE_DYNAMIC_SMPS |
			   NL80211_FEATURE_STATIC_SMPS |
			   NL80211_FEATURE_SUPPORTS_WMM_ADMISSION |
			   NL80211_FEATURE_TX_POWER_INSERTION |
			   NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES;

	wiphy->flags |= WIPHY_FLAG_IBSS_RSN |
			WIPHY_FLAG_AP_UAPSD |
			WIPHY_FLAG_HAS_CHANNEL_SWITCH |
			WIPHY_FLAG_SPLIT_SCAN_6GHZ |
			WIPHY_FLAG_SUPPORTS_TDLS |
			WIPHY_FLAG_SUPPORTS_EXT_KEK_KCK;

	if (mld->nvm_data->sku_cap_11be_enable &&
	    !iwlwifi_mod_params.disable_11ax &&
	    !iwlwifi_mod_params.disable_11be)
		wiphy->flags |= WIPHY_FLAG_SUPPORTS_MLO;

	/* the firmware uses u8 for num of iterations, but 0xff is saved for
	 * infinite loop, so the maximum number of iterations is actually 254.
	 */
	wiphy->max_sched_scan_plan_iterations = 254;

	/* driver create the 802.11 header (24 bytes), DS parameter (3 bytes)
	 * and SSID IE (2 bytes).
	 */
	wiphy->max_sched_scan_ie_len = SCAN_OFFLOAD_PROBE_REQ_SIZE - 24 - 3 - 2;
	wiphy->max_scan_ie_len = SCAN_OFFLOAD_PROBE_REQ_SIZE - 24 - 3 - 2;
	wiphy->max_sched_scan_ssids = PROBE_OPTION_MAX;
	wiphy->max_scan_ssids = PROBE_OPTION_MAX;
	wiphy->max_sched_scan_plans = IWL_MAX_SCHED_SCAN_PLANS;
	wiphy->max_sched_scan_reqs = 1;
	wiphy->max_sched_scan_plan_interval = U16_MAX;
	wiphy->max_match_sets = IWL_SCAN_MAX_PROFILES_V2;

	wiphy->max_remain_on_channel_duration = 10000;

	wiphy->hw_version = mld->trans->hw_id;

	wiphy->hw_timestamp_max_peers = 1;

	wiphy->iface_combinations = iwl_mld_iface_combinations;
	wiphy->n_iface_combinations = ARRAY_SIZE(iwl_mld_iface_combinations);

	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_VHT_IBSS);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_DFS_CONCURRENT);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_BEACON_RATE_LEGACY);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_SCAN_START_TIME);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_BSS_PARENT_TSF);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_SCAN_MIN_PREQ_CONTENT);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_ACCEPT_BCAST_PROBE_RESP);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_FILS_MAX_CHANNEL_TIME);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_OCE_PROBE_REQ_HIGH_TX_RATE);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER);

	if (fw_has_capa(ucode_capa, IWL_UCODE_TLV_CAPA_PROTECTED_TWT))
		wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_PROTECTED_TWT);

	wiphy->iftype_ext_capab = NULL;
	wiphy->num_iftype_ext_capab = 0;

	if (!iwlwifi_mod_params.disable_11ax) {
		wiphy->iftype_ext_capab = iftypes_ext_capa;
		wiphy->num_iftype_ext_capab = ARRAY_SIZE(iftypes_ext_capa);

		ieee80211_hw_set(hw, SUPPORTS_MULTI_BSSID);
		ieee80211_hw_set(hw, SUPPORTS_ONLY_HE_MULTI_BSSID);
	}

	/* TODO:
	 * 1. iwlmld_mod_params CAM MODE (WIPHY_FLAG_PS_ON_BY_DEFAULT)
	 * 2. tm (time measurement) ext capab
	 * 3. eml_capabilities debug override
	 *
	 * location:
	 * 1. NL80211_EXT_FEATURE_PROT_RANGE_NEGO_AND_MEASURE
	 * 2. NL80211_EXT_FEATURE_SECURE_LTF
	 * 3. NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER
	 * 4. wiphy->pmsr_capa
	 */
}

static void iwl_mac_hw_set_misc(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;

	hw->queues = IEEE80211_NUM_ACS;

	hw->netdev_features = NETIF_F_HIGHDMA | NETIF_F_SG;
	hw->netdev_features |= mld->cfg->features;

	hw->max_tx_fragments = mld->trans->max_skb_frags;
	hw->max_listen_interval = 10;

	hw->uapsd_max_sp_len = IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL;
	hw->uapsd_queues = IEEE80211_WMM_IE_STA_QOSINFO_AC_VO |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_VI |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_BK |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_BE;

	hw->chanctx_data_size = sizeof(struct iwl_mld_phy);
	hw->vif_data_size = sizeof(struct iwl_mld_vif);
	/* TODO set:
	 * 1. hw->sta_data_size
	 * 2. hw->txq_data_size
	 */
}

static int iwl_mld_hw_verify_preconditions(struct iwl_mld *mld)
{
	/* 11ax is expected to be enabled for all supported devices */
	if (WARN_ON(!mld->nvm_data->sku_cap_11ax_enable))
		return -EINVAL;

	/* LAR is expected to be enabled for all supported devices */
	if (WARN_ON(!mld->nvm_data->lar_enabled))
		return -EINVAL;

	/* All supported devices are currently using version 3 of the cmd.
	 * Since version 3, IWL_SCAN_MAX_PROFILES_V2 shall be used where
	 * necessary.
	 */
	if (WARN_ON(iwl_fw_lookup_cmd_ver(mld->fw,
					  SCAN_OFFLOAD_UPDATE_PROFILES_CMD,
					  IWL_FW_CMD_VER_UNKNOWN) != 3))
		return -EINVAL;

	return 0;
}

int iwl_mld_register_hw(struct iwl_mld *mld)
{
	/* verify once essential preconditions required for setting
	 * the hw capabilities
	 */
	if (iwl_mld_hw_verify_preconditions(mld))
		return -EINVAL;

	iwl_mld_hw_set_addresses(mld);
	iwl_mld_hw_set_channels(mld);
	iwl_mld_hw_set_security(mld);
	iwl_mld_hw_set_regulatory(mld);
	iwl_mld_hw_set_pm(mld);
	iwl_mld_hw_set_antennas(mld);
	iwl_mac_hw_set_radiotap(mld);
	iwl_mac_hw_set_flags(mld);
	iwl_mac_hw_set_wiphy(mld);
	iwl_mac_hw_set_misc(mld);

	SET_IEEE80211_DEV(mld->hw, mld->trans->dev);

	/* TODO:
	 * 1. leds_init
	 * 2. register vendor cmds
	 */

	return ieee80211_register_hw(mld->hw);
}

static void
iwl_mld_mac80211_tx(struct ieee80211_hw *hw,
		    struct ieee80211_tx_control *control, struct sk_buff *skb)
{
	WARN_ON("Not supported yet\n");
}

static void
iwl_mld_restart_cleanup(struct iwl_mld *mld)
{
	iwl_cleanup_mld(mld);

	ieee80211_iterate_interfaces(mld->hw, IEEE80211_IFACE_ITER_ACTIVE,
				     iwl_mld_cleanup_vif, NULL);
}

static
int iwl_mld_mac80211_start(struct ieee80211_hw *hw)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	/* TODO:
	 * 1. fast resume
	 */

	if (mld->fw_status.in_hw_restart) {
		iwl_mld_stop_fw(mld);
		iwl_mld_restart_cleanup(mld);
	}

	ret = iwl_mld_start_fw(mld);
	if (ret)
		goto error;

	iwl_dbg_tlv_time_point(&mld->fwrt, IWL_FW_INI_TIME_POINT_POST_INIT,
			       NULL);
	iwl_dbg_tlv_time_point(&mld->fwrt, IWL_FW_INI_TIME_POINT_PERIODIC,
			       NULL);

	return 0;

error:
	/* If we failed to restart the hw, there is nothing useful
	 * we can do but indicate we are no longer in restart.
	 */
	mld->fw_status.in_hw_restart = false;

	return ret;
}

static
void iwl_mld_mac80211_stop(struct ieee80211_hw *hw, bool suspend)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	lockdep_assert_wiphy(mld->wiphy);

	/* execute all pending notifications (async handlers)*/
	wiphy_work_flush(mld->wiphy, &mld->async_handlers_wk);

	/* TODO:
	 * 1. suspend
	 * 2. ftm_initiator_smooth_stop
	 */

	if (suspend)
		WARN_ON(1);
	else
		iwl_mld_stop_fw(mld);

	/* the work might have been scheduled again - cancel it now as the hw
	 * is stopped.
	 */
	wiphy_work_cancel(mld->wiphy, &mld->async_handlers_wk);

	/* Clear in_hw_restart flag when stopping the hw, as mac80211 won't
	 * execute the restart.
	 */
	mld->fw_status.in_hw_restart = false;
}

static
int iwl_mld_mac80211_config(struct ieee80211_hw *hw, u32 changed)
{
	return 0;
}

static
int iwl_mld_mac80211_add_interface(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return 0;
	}

	/* Construct mld_vif, add it to fw, and map its ID to ieee80211_vif */
	ret = iwl_mld_add_vif(mld, vif);
	if (ret)
		return ret;

	/* Add the default link (now pointed to by link[0]) */
	ret = iwl_mld_add_link(mld, &vif->bss_conf);
	if (ret)
		goto err_rm_vif;

	/* beacon filtering */
	ret = iwl_mld_disable_beacon_filter(mld, vif);
	if (ret)
		goto err_rm_link;

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION)
		vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER |
				     IEEE80211_VIF_SUPPORTS_CQM_RSSI;

	if (vif->p2p || iwl_fw_lookup_cmd_ver(mld->fw, PHY_CONTEXT_CMD, 0) < 5)
		vif->driver_flags |= IEEE80211_VIF_IGNORE_OFDMA_WIDER_BW;

	/* TODO: power considerations */

	return 0;

err_rm_link:
	iwl_mld_remove_link(mld, &vif->bss_conf);
err_rm_vif:
	iwl_mld_rm_vif(mld, vif);
	return ret;
}

static
void iwl_mld_mac80211_remove_interface(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	lockdep_assert_wiphy(mld->wiphy);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return;
	}

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION)
		vif->driver_flags &= ~(IEEE80211_VIF_BEACON_FILTER |
				       IEEE80211_VIF_SUPPORTS_CQM_RSSI);

	/* TODO: power considerations */

	iwl_mld_remove_link(mld, &vif->bss_conf);

	iwl_mld_rm_vif(mld, vif);
}

static
void iwl_mld_mac80211_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *total_flags,
				       u64 multicast)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* TODO: for now just log the function is not implemented
	 * and set total_flags = 0 to avoid mac80211 warning
	 */
	IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);

	*total_flags = 0;
}

static
void iwl_mld_mac80211_wake_tx_queue(struct ieee80211_hw *hw,
				    struct ieee80211_txq *txq)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_add_chanctx(struct ieee80211_hw *hw,
			struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_remove_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
}

static
void iwl_mld_change_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx, u32 changed)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_assign_vif_chanctx(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ieee80211_bss_conf *link_conf,
			       struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_unassign_vif_chanctx(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_bss_conf *link_conf,
				  struct ieee80211_chanctx_conf *ctx)
{
	WARN_ON("Not supported yet\n");
}

#ifdef CONFIG_PM_SLEEP
static
int iwl_mld_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
int iwl_mld_resume(struct ieee80211_hw *hw)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}
#endif /* CONFIG_PM_SLEEP */

static
int iwl_mld_mac80211_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	return -EOPNOTSUPP;
}

static
void iwl_mld_mac80211_link_info_changed(struct ieee80211_hw *hw,
					struct ieee80211_vif *vif,
					struct ieee80211_bss_conf *link_conf,
					u64 changes)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* TODO: for now just log the function is not implemented */
	IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);

	return;
}

static
void iwl_mld_mac80211_vif_cfg_changed(struct ieee80211_hw *hw,
				      struct ieee80211_vif *vif,
				      u64 changes)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	IWL_ERR(mld, "NOT IMPLEMENTED YET\n");
}

static
int iwl_mld_mac80211_set_key(struct ieee80211_hw *hw,
			     enum set_key_cmd cmd,
			     struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta,
			     struct ieee80211_key_conf *key)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
int iwl_mld_mac80211_hw_scan(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_scan_request *hw_req)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static void
iwl_mld_mac80211_reconfig_complete(struct ieee80211_hw *hw,
				   enum ieee80211_reconfig_type reconfig_type)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	switch (reconfig_type) {
	case IEEE80211_RECONFIG_TYPE_RESTART:
		mld->fw_status.in_hw_restart = false;
		/* TODO: send recovery cmd */
		break;
	case IEEE80211_RECONFIG_TYPE_SUSPEND:
		break;
	}
}

const struct ieee80211_ops iwl_mld_hw_ops = {
	.tx = iwl_mld_mac80211_tx,
	.start = iwl_mld_mac80211_start,
	.stop = iwl_mld_mac80211_stop,
	.config = iwl_mld_mac80211_config,
	.add_interface = iwl_mld_mac80211_add_interface,
	.remove_interface = iwl_mld_mac80211_remove_interface,
	.configure_filter = iwl_mld_mac80211_configure_filter,
	.reconfig_complete = iwl_mld_mac80211_reconfig_complete,
	.wake_tx_queue = iwl_mld_mac80211_wake_tx_queue,
	.add_chanctx = iwl_mld_add_chanctx,
	.remove_chanctx = iwl_mld_remove_chanctx,
	.change_chanctx = iwl_mld_change_chanctx,
	.assign_vif_chanctx = iwl_mld_assign_vif_chanctx,
	.unassign_vif_chanctx = iwl_mld_unassign_vif_chanctx,
	.set_rts_threshold = iwl_mld_mac80211_set_rts_threshold,
	.link_info_changed = iwl_mld_mac80211_link_info_changed,
	.vif_cfg_changed = iwl_mld_mac80211_vif_cfg_changed,
	.set_key = iwl_mld_mac80211_set_key,
	.hw_scan = iwl_mld_mac80211_hw_scan,
#ifdef CONFIG_PM_SLEEP
	.suspend = iwl_mld_suspend,
	.resume = iwl_mld_resume,
#endif /* CONFIG_PM_SLEEP */
};
