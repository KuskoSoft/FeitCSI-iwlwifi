// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>
#include <linux/ip.h>

#include "mld.h"
#include "mac80211.h"
#include "phy.h"
#include "iface.h"
#include "power.h"
#include "sta.h"
#include "agg.h"
#include "scan.h"
#include "d3.h"
#include "tlc.h"
#include "fw/api/scan.h"
#include "fw/api/context.h"
#ifdef CONFIG_PM_SLEEP
#include "fw/api/d3.h"
#endif /* CONFIG_PM_SLEEP */
#ifdef CPTCFG_IWL_VENDOR_CMDS
#include "vendor-cmd.h"
#endif
#include "iwl-trans.h"

#define IWL_MLD_LIMITS(ap)					\
	{							\
		.max = 2,					\
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
		.max_interfaces = 4,
		.limits = iwl_mld_limits,
		.n_limits = ARRAY_SIZE(iwl_mld_limits),
	},
	{
		.num_different_channels = 1,
		.max_interfaces = 4,
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
	wiphy->max_sched_scan_ie_len = iwl_mld_scan_max_template_size();
	wiphy->max_scan_ie_len = iwl_mld_scan_max_template_size();
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

	if (iwlmld_mod_params.power_scheme != IWL_POWER_SCHEME_CAM)
		wiphy->flags |= WIPHY_FLAG_PS_ON_BY_DEFAULT;
	else
		wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;

	/* TODO:
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
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (mld->trans->dbg_cfg.HW_CSUM_DISABLE)
		hw->netdev_features &= ~IWL_CSUM_NETIF_FLAGS_MASK;
#endif

	hw->max_tx_fragments = mld->trans->max_skb_frags;
	hw->max_listen_interval = 10;

	hw->uapsd_max_sp_len = IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL;
	hw->uapsd_queues = IEEE80211_WMM_IE_STA_QOSINFO_AC_VO |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_VI |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_BK |
			   IEEE80211_WMM_IE_STA_QOSINFO_AC_BE;

	hw->chanctx_data_size = sizeof(struct iwl_mld_phy);
	hw->vif_data_size = sizeof(struct iwl_mld_vif);
	hw->sta_data_size = sizeof(struct iwl_mld_sta);
	hw->txq_data_size = sizeof(struct iwl_mld_txq);
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

#ifdef CPTCFG_IWL_VENDOR_CMDS
	iwl_mld_vendor_cmds_register(mld);
#endif

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

	ieee80211_iterate_stations_atomic(mld->hw,
					  iwl_mld_cleanup_sta, NULL);
}

static
int iwl_mld_mac80211_start(struct ieee80211_hw *hw)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;
	bool in_d3 = false;

	lockdep_assert_wiphy(mld->wiphy);

#ifdef CONFIG_PM_SLEEP
	/* Unless the host goes into hibernate the FW always stays on and
	 * the d3_resume flow is used. When wowlan is configured, mac80211
	 * would call it's resume callback and the wowlan_resume flow
	 * would be used.
	 */

	in_d3 = mld->fw_status.in_d3;
	if (in_d3) {
		/* mac80211 already cleaned up the state, no need for cleanup */
		ret = iwl_mld_no_wowlan_resume(mld);
		if (ret)
			iwl_mld_stop_fw(mld);
	}
#endif /* CONFIG_PM_SLEEP */

	if (mld->fw_status.in_hw_restart) {
		iwl_mld_stop_fw(mld);
		iwl_mld_restart_cleanup(mld);
	}

	if (!in_d3 || ret) {
		ret = iwl_mld_start_fw(mld);
		if (ret)
			goto error;
	}

	mld->scan.last_start_time_jiffies = jiffies;

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

	wiphy_work_cancel(mld->wiphy, &mld->add_txqs_wk);

	/* TODO:
	 * ftm_initiator_smooth_stop
	 */

	/* if the suspend flow fails the fw is in error. Stop it here, and it
	 * will be started upon wakeup
	 */
	if (!suspend || iwl_mld_no_wowlan_suspend(mld))
		iwl_mld_stop_fw(mld);

	/* the work might have been scheduled again - cancel it now as the hw
	 * is stopped.
	 */
	wiphy_work_cancel(mld->wiphy, &mld->async_handlers_wk);

	/* Clear in_hw_restart flag when stopping the hw, as mac80211 won't
	 * execute the restart.
	 */
	mld->fw_status.in_hw_restart = false;

	/* We shouldn't have any UIDs still set. Loop over all the UIDs to
	 * make sure there's nothing left there and warn if any is found.
	 */
	for (int i = 0; i < ARRAY_SIZE(mld->scan.uid_status); i++)
		if (WARN_ONCE(mld->scan.uid_status[i],
			      "UMAC scan UID %d status was not cleaned (0x%x 0x%x)\n",
			      i, mld->scan.uid_status[i], mld->scan.status))
			mld->scan.uid_status[i] = 0;
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
				     IEEE80211_VIF_SUPPORTS_CQM_RSSI |
				     IEEE80211_VIF_REMOVE_AP_AFTER_DISASSOC;

	if (vif->p2p || iwl_fw_lookup_cmd_ver(mld->fw, PHY_CONTEXT_CMD, 0) < 5)
		vif->driver_flags |= IEEE80211_VIF_IGNORE_OFDMA_WIDER_BW;

	if (vif->type == NL80211_IFTYPE_STATION)
		iwl_mld_update_mac_power(mld, vif, false);

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
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_txq *mld_txq = iwl_mld_txq_from_mac80211(txq);

	if (likely(mld_txq->status.allocated) || !txq->sta) {
		iwl_mld_tx_from_txq(mld, txq);
		return;
	}

	/* We don't support TSPEC tids. %IEEE80211_NUM_TIDS is for mgmt */
	if (txq->tid != IEEE80211_NUM_TIDS && txq->tid >= IWL_MAX_TID_COUNT) {
		IWL_DEBUG_MAC80211(mld, "TID %d is not supported\n", txq->tid);
		return;
	}

	/* The worker will handle any packets we leave on the txq now */

	spin_lock_bh(&mld->add_txqs_lock);
	/* The list is being deleted only after the queue is fully allocated. */
	if (list_empty(&mld_txq->list) &&
	    /* recheck under lock, otherwise it can be added twice */
	    !mld_txq->status.allocated) {
		list_add_tail(&mld_txq->list, &mld->txqs_to_add);
		wiphy_work_queue(mld->wiphy, &mld->add_txqs_wk);
	}
	spin_unlock_bh(&mld->add_txqs_lock);
}

static
int iwl_mld_add_chanctx(struct ieee80211_hw *hw,
			struct ieee80211_chanctx_conf *ctx)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_phy *phy = iwl_mld_phy_from_mac80211(ctx);
	int fw_id = iwl_mld_allocate_fw_phy_id(mld);
	int ret;

	if (fw_id < 0)
		return fw_id;

	phy->fw_id = fw_id;
	phy->chandef = *iwl_mld_get_chandef_from_chanctx(ctx);

	ret = iwl_mld_phy_fw_action(mld, ctx, FW_CTXT_ACTION_ADD);
	if (ret) {
		mld->used_phy_ids &= ~BIT(phy->fw_id);
		return ret;
	}

	/* TODO: remove on RLC offload */
	return iwl_mld_send_rlc_cmd(mld, fw_id);
}

static
void iwl_mld_remove_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_phy *phy = iwl_mld_phy_from_mac80211(ctx);

	iwl_mld_phy_fw_action(mld, ctx, FW_CTXT_ACTION_REMOVE);
	mld->used_phy_ids &= ~BIT(phy->fw_id);
}

static
void iwl_mld_change_chanctx(struct ieee80211_hw *hw,
			    struct ieee80211_chanctx_conf *ctx, u32 changed)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_phy *phy = iwl_mld_phy_from_mac80211(ctx);
	struct cfg80211_chan_def *chandef =
		iwl_mld_get_chandef_from_chanctx(ctx);

	/* We don't care about these */
	if (!(changed & ~(IEEE80211_CHANCTX_CHANGE_RX_CHAINS |
			  IEEE80211_CHANCTX_CHANGE_RADAR |
			  IEEE80211_CHANCTX_CHANGE_CHANNEL)))
		return;

	/* Check if a FW update is required */

	if (changed & IEEE80211_CHANCTX_CHANGE_AP)
		goto update;

	if (chandef->chan == phy->chandef.chan &&
	    chandef->center_freq1 == phy->chandef.center_freq1 &&
	    chandef->punctured == phy->chandef.punctured) {
		/* Check if we are toggling between HT and non-HT, no-op */
		if (phy->chandef.width == chandef->width ||
		    (phy->chandef.width <= NL80211_CHAN_WIDTH_20 &&
		     chandef->width <= NL80211_CHAN_WIDTH_20))
			return;
	}
update:
	phy->chandef = *chandef;

	iwl_mld_phy_fw_action(mld, ctx, FW_CTXT_ACTION_MODIFY);
}

static
int iwl_mld_assign_vif_chanctx(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ieee80211_bss_conf *link,
			       struct ieee80211_chanctx_conf *ctx)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	/* TODO: for AP, send mac ctxt cmd to update HE cap (or in start_ap?)
	 * (task=AP)
	 */

	rcu_assign_pointer(mld_link->chan_ctx, ctx);

	/* TODO: detect entering EMLSR (task=EMLSR) */

	/* First send the link command with the phy context ID.
	 * Now that we have the phy, we know the band so also the rates
	 */
	ret = iwl_mld_change_link_in_fw(mld, link,
					LINK_CONTEXT_MODIFY_RATES_INFO);
	if (ret)
		goto err;

	/* TODO: Initialize rate control for the AP station, since we might be
	 * doing a link switch here - we cannot initialize it before since
	 * this needs the phy context assigned (and in FW?), and we cannot
	 * do it later because it needs to be initialized as soon as we're
	 * able to TX on the link, i.e. when active. (task=link-switch)
	 */

	/* Now activate the link */
	ret = iwl_mld_activate_link(mld, link);
	if (ret)
		goto err;

	if (vif->type == NL80211_IFTYPE_STATION)
		iwl_mld_send_ap_tx_power_constraint_cmd(mld, vif, link);

	return 0;
err:
	RCU_INIT_POINTER(mld_link->chan_ctx, NULL);
	return ret;
}

static
void iwl_mld_unassign_vif_chanctx(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_bss_conf *link,
				  struct ieee80211_chanctx_conf *ctx)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	int ret;

	if (WARN_ON(!mld_link))
		return;

	ret = iwl_mld_deactivate_link(mld, link);
	if (ret)
		return;

	/* TODO: detect exiting EMLSR (task=EMLSR)*/

	RCU_INIT_POINTER(mld_link->chan_ctx, NULL);

	/* in the non-MLO case, remove/re-add the link to clean up FW state.
	 * In MLO, it'll be done in drv_change_vif_link
	 */
	if (!ieee80211_vif_is_mld(vif) && !mld_vif->ap_sta &&
	    !WARN_ON_ONCE(vif->cfg.assoc)) {
		iwl_mld_remove_link(mld, link);
		iwl_mld_add_link(mld, link);
	}
}

static
int iwl_mld_mac80211_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	return -EOPNOTSUPP;
}

static
u32 iwl_mld_link_changed_mapping(struct ieee80211_vif *vif,
				 struct ieee80211_bss_conf *link_conf,
				 u64 changes)
{
	u32 link_changes = 0;
	bool has_he, has_eht;

	if (changes & BSS_CHANGED_QOS && vif->cfg.assoc && link_conf->qos)
		link_changes |= LINK_CONTEXT_MODIFY_QOS_PARAMS;

	if (changes & (BSS_CHANGED_ERP_PREAMBLE | BSS_CHANGED_BASIC_RATES |
		       BSS_CHANGED_ERP_SLOT))
		link_changes |= LINK_CONTEXT_MODIFY_RATES_INFO;

	if (changes & (BSS_CHANGED_HT | BSS_CHANGED_ERP_CTS_PROT))
		link_changes |= LINK_CONTEXT_MODIFY_PROTECT_FLAGS;

	/* todo: check mac80211's HE flags and if command is needed every time
	 * there's a link change. Currently used flags are
	 * BSS_CHANGED_HE_OBSS_PD and BSS_CHANGED_HE_BSS_COLOR.
	 */
	has_he = link_conf->he_support && !iwlwifi_mod_params.disable_11ax;
	has_eht = link_conf->eht_support && !iwlwifi_mod_params.disable_11be;

	if (vif->cfg.assoc && (has_he || has_eht))
		link_changes |= LINK_CONTEXT_MODIFY_HE_PARAMS;

	return link_changes;
}

static
void iwl_mld_mac80211_link_info_changed(struct ieee80211_hw *hw,
					struct ieee80211_vif *vif,
					struct ieee80211_bss_conf *link_conf,
					u64 changes)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	u32 link_changes;

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return;
	}

	link_changes = iwl_mld_link_changed_mapping(vif, link_conf, changes);
	if (link_changes)
		iwl_mld_change_link_in_fw(mld, link_conf, link_changes);

	if (changes & BSS_CHANGED_TPE)
		iwl_mld_send_ap_tx_power_constraint_cmd(mld, vif, link_conf);

	// todo: BSS_CHANGED_BEACON_INFO (task=beacon_filter, power)
	// todo: BSS_CHANGED_BANDWIDTH (task=EMLSR)
	// todo: BSS_CHANGED_CQM
	// todo: BSS_CHANGED_TXPOWER (task=power)
}

static
void iwl_mld_mac80211_vif_cfg_changed(struct ieee80211_hw *hw,
				      struct ieee80211_vif *vif,
				      u64 changes)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return;
	}

	if (changes & BSS_CHANGED_ASSOC) {
		ret = iwl_mld_mac_fw_action(mld, vif, FW_CTXT_ACTION_MODIFY);
		if (ret)
			IWL_ERR(mld, "failed to update context\n");

		if (vif->cfg.assoc)
			iwl_mld_set_vif_associated(mld, vif);
			/* todo: if assoc request statistics (task=statistics)
			 */
	}

	if (changes & BSS_CHANGED_PS &&
	    !WARN_ON(vif->type != NL80211_IFTYPE_STATION))
		iwl_mld_update_mac_power(mld, vif, false);

	//todo: BSS_CHANGED_MLD_VALID_LINKS/CHANGED_MLD_TTLM - mlo_int_scan_wk
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

static int
iwl_mld_mac80211_hw_scan(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif,
			 struct ieee80211_scan_request *hw_req)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	if (WARN_ON(!hw_req->req.n_channels ||
		    hw_req->req.n_channels >
		    mld->fw->ucode_capa.n_scan_channels))
		return -EINVAL;

	return iwl_mld_regular_scan_start(mld, vif, &hw_req->req, &hw_req->ies);
}

static void
iwl_mld_mac80211_cancel_hw_scan(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* Due to a race condition, it's possible that mac80211 asks
	 * us to stop a hw_scan when it's already stopped. This can
	 * happen, for instance, if we stopped the scan ourselves,
	 * called ieee80211_scan_completed() and the userspace called
	 * cancel scan before ieee80211_scan_work() could run.
	 * To handle that, simply return if the scan is not running.
	 */
	if (mld->scan.status & IWL_MLD_SCAN_REGULAR)
		iwl_mld_scan_stop(mld, IWL_MLD_SCAN_REGULAR, true);
}

static int
iwl_mld_mac80211_sched_scan_start(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct cfg80211_sched_scan_request *req,
				  struct ieee80211_scan_ies *ies)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	return iwl_mld_sched_scan_start(mld, vif, req, ies, IWL_MLD_SCAN_SCHED);
}

static int
iwl_mld_mac80211_sched_scan_stop(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	/* Due to a race condition, it's possible that mac80211 asks
	 * us to stop a sched_scan when it's already stopped. This
	 * can happen, for instance, if we stopped the scan ourselves,
	 * called ieee80211_sched_scan_stopped() and the userspace called
	 * stop sched scan before ieee80211_sched_scan_stopped_work()
	 * could run. To handle this, simply return if the scan is
	 * not running.
	 */
	if (!(mld->scan.status & IWL_MLD_SCAN_SCHED))
		return 0;

	ret = iwl_mld_scan_stop(mld, IWL_MLD_SCAN_SCHED, false);
	wiphy_work_flush(mld->wiphy, &mld->async_handlers_wk);

	return ret;
}

static void
iwl_mld_mac80211_reconfig_complete(struct ieee80211_hw *hw,
				   enum ieee80211_reconfig_type reconfig_type)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	switch (reconfig_type) {
	case IEEE80211_RECONFIG_TYPE_RESTART:
		mld->fw_status.in_hw_restart = false;
		iwl_mld_send_recovery_cmd(mld, ERROR_RECOVERY_END_OF_RECOVERY);
		break;
	case IEEE80211_RECONFIG_TYPE_SUSPEND:
		break;
	}
}

static
void iwl_mld_mac80211_mgd_prepare_tx(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif,
				     struct ieee80211_prep_tx_info *info)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	u32 duration = IWL_MLD_SESSION_PROTECTION_ASSOC_TIME_MS;

	/* After a successful association the connection is etalibeshed
	 * and we can rely on the quota to send the disassociation frame.
	 */
	if (info->was_assoc)
		return;

	if (info->duration > duration)
		duration = info->duration;

	iwl_mld_schedule_session_protection(mld, vif, duration,
					    IWL_MLD_SESSION_PROTECTION_MIN_TIME_MS,
					    info->link_id);
}

static
void iwl_mld_mac_mgd_complete_tx(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 struct ieee80211_prep_tx_info *info)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* Successful authentication is the only case that requires to let the
	 * the session protection go. We'll need it for the upcoming
	 * association. For all the other cases, we need to cancel the session
	 * protection.
	 * After successful association the connection is established and
	 * further mgd tx can rely on the quota.
	 */
	if (info->success && info->subtype == IEEE80211_STYPE_AUTH)
		return;

	/* The firmware will be on medium after we configure the vif as
	 * associated. Removing the session protection allows the firmware
	 * to stop being on medium. In order to ensure the continuity of our
	 * presence on medium, we need first to configure the vif as associated
	 * and only then, remove the session protection.
	 * Currently, mac80211 calls vif_cfg_changed() first and then,
	 * drv_mgd_complete_tx(). Ensure that this assumption stays true by
	 * a warning.
	 */
	WARN_ON(info->success &&
		(info->subtype == IEEE80211_STYPE_ASSOC_REQ ||
		 info->subtype == IEEE80211_STYPE_REASSOC_REQ) &&
		!vif->cfg.assoc);

	iwl_mld_cancel_session_protection(mld, vif, info->link_id);
}

static int
iwl_mld_mac80211_conf_tx(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif,
			 unsigned int link_id, u16 ac,
			 const struct ieee80211_tx_queue_params *params)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link;

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return 0;
	}

	lockdep_assert_wiphy(mld->wiphy);

	link = iwl_mld_link_dereference_check(mld_vif, link_id);
	if (!link)
		return -EINVAL;

	link->queue_params[ac] = *params;

	/* No need to update right away, we'll get BSS_CHANGED_QOS
	 * The exception is P2P_DEVICE interface which needs immediate update.
	 */
	/* TODO: change link for p2p device (task=P2P) */
	return 0;
}

static void iwl_mld_set_uapsd(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	vif->driver_flags &= ~IEEE80211_VIF_SUPPORTS_UAPSD;

	if (vif->type != NL80211_IFTYPE_STATION)
		return;

	if (vif->p2p &&
	    !(iwlwifi_mod_params.uapsd_disable & IWL_DISABLE_UAPSD_P2P_CLIENT))
		vif->driver_flags |= IEEE80211_VIF_SUPPORTS_UAPSD;

	if (!vif->p2p &&
	    !(iwlwifi_mod_params.uapsd_disable & IWL_DISABLE_UAPSD_BSS))
		vif->driver_flags |= IEEE80211_VIF_SUPPORTS_UAPSD;
}

static int iwl_mld_move_sta_state_up(struct iwl_mld *mld,
				     struct ieee80211_vif *vif,
				     struct ieee80211_sta *sta,
				     enum ieee80211_sta_state old_state,
				     enum ieee80211_sta_state new_state)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	if (old_state == IEEE80211_STA_NOTEXIST &&
	    new_state == IEEE80211_STA_NONE) {
		ret = iwl_mld_add_sta(mld, sta, vif, STATION_TYPE_PEER);
		if (ret)
			return ret;

		if (vif->type == NL80211_IFTYPE_STATION && !sta->tdls)
			mld_vif->ap_sta = sta;

		/* Initialize TLC here already - this really tells
		 * the firmware only what the supported legacy rates are
		 * (may be) since it's initialized already from what the
		 * AP advertised in the beacon/probe response. This will
		 * allow the firmware to send auth/assoc frames with one
		 * of the supported rates already, rather than having to
		 * use a mandatory rate.
		 * If we're the AP, we'll just assume mandatory rates at
		 * this point, but we know nothing about the STA anyway.
		 */
		iwl_mld_config_tlc(mld, vif, sta);

		return ret;
	} else if (old_state == IEEE80211_STA_NONE &&
		   new_state == IEEE80211_STA_AUTH) {
		iwl_mld_set_uapsd(mld, vif);
		return 0;
	} else if (old_state == IEEE80211_STA_AUTH &&
		   new_state == IEEE80211_STA_ASSOC) {
		ret = iwl_mld_update_all_link_stations(mld, sta);

		/* Now the link_sta's capabilities are set, update the FW */
		iwl_mld_config_tlc(mld, vif, sta);

		return ret;
	} else if (old_state == IEEE80211_STA_ASSOC &&
		   new_state == IEEE80211_STA_AUTHORIZED) {
		mld_vif->authorized = true;

		/* clear COEX_HIGH_PRIORITY_ENABLE */
		ret = iwl_mld_mac_fw_action(mld, vif, FW_CTXT_ACTION_MODIFY);
		if (ret)
			return ret;

		/* MFP is set by default before the station is authorized.
		 * Clear it here in case it's not used.
		 */
		if (!sta->mfp)
			ret = iwl_mld_update_all_link_stations(mld, sta);

		/* We can use wide bandwidth now, not only 20 MHz */
		iwl_mld_config_tlc(mld, vif, sta);

		return ret;
	} else {
		IWL_ERR(mld, "NOT IMPLEMENTED YET\n");
		return -EINVAL;
	}
}

static int iwl_mld_move_sta_state_down(struct iwl_mld *mld,
				       struct ieee80211_vif *vif,
				       struct ieee80211_sta *sta,
				       enum ieee80211_sta_state old_state,
				       enum ieee80211_sta_state new_state)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	if (old_state == IEEE80211_STA_AUTHORIZED &&
	    new_state == IEEE80211_STA_ASSOC) {
		mld_vif->authorized = false;
		/* once we move into assoc state, need to update the FW to
		 * stop using wide bandwidth
		 */
		iwl_mld_config_tlc(mld, vif, sta);
	} else if (old_state == IEEE80211_STA_ASSOC &&
		   new_state == IEEE80211_STA_AUTH) {
		/* nothing */
	} else if (old_state == IEEE80211_STA_AUTH &&
		   new_state == IEEE80211_STA_NONE) {
		/* nothing */
	} else if (old_state == IEEE80211_STA_NONE &&
		   new_state == IEEE80211_STA_NOTEXIST) {
		mld_vif->ap_sta = NULL;
		iwl_mld_remove_sta(mld, sta);
	} else {
		IWL_ERR(mld, "NOT IMPLEMENTED YET\n");
		return -EINVAL;
	}
	return 0;
}

static int iwl_mld_mac80211_sta_state(struct ieee80211_hw *hw,
				      struct ieee80211_vif *vif,
				      struct ieee80211_sta *sta,
				      enum ieee80211_sta_state old_state,
				      enum ieee80211_sta_state new_state)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	IWL_DEBUG_MAC80211(mld, "station %pM state change %d->%d\n",
			   sta->addr, old_state, new_state);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION ||
	    sta->tdls) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET %s\n", __func__);
		return -EINVAL;
	}

	mld_sta->sta_state = new_state;

	if (old_state < new_state)
		return iwl_mld_move_sta_state_up(mld, vif, sta, old_state,
						 new_state);
	else
		return iwl_mld_move_sta_state_down(mld, vif, sta, old_state,
						   new_state);
}

static void iwl_mld_mac80211_flush(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif,
				   u32 queues, bool drop)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* Make sure we're done with the deferred traffic before flushing */
	wiphy_work_flush(mld->wiphy, &mld->add_txqs_wk);

	for (int i = 0; i < mld->fw->ucode_capa.num_stations; i++) {
		struct ieee80211_link_sta *link_sta =
			wiphy_dereference(mld->wiphy,
					  mld->fw_id_to_link_sta[i]);

		if (!link_sta)
			continue;

		/* Check that the sta belongs to the given vif */
		if (vif && vif != iwl_mld_sta_from_mac80211(link_sta->sta)->vif)
			continue;

		if (drop)
			iwl_mld_flush_sta_txqs(mld, link_sta->sta);
		else
			iwl_mld_wait_sta_txqs_empty(mld, link_sta->sta);
	}
}

static void iwl_mld_mac80211_flush_sta(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       struct ieee80211_sta *sta)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	iwl_mld_flush_sta_txqs(mld, sta);
}

static int
iwl_mld_mac80211_ampdu_action(struct ieee80211_hw *hw,
			      struct ieee80211_vif *vif,
			      struct ieee80211_ampdu_params *params)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct ieee80211_sta *sta = params->sta;
	enum ieee80211_ampdu_mlme_action action = params->action;
	u16 tid = params->tid;
	u16 ssn = params->ssn;
	u16 buf_size = params->buf_size;
	u16 timeout = params->timeout;
	int ret;

	IWL_DEBUG_HT(mld, "A-MPDU action on addr %pM tid: %d action: %d\n",
		     sta->addr, tid, action);

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		/* TODO: BT coex amsdu disallowed (task=coex) */
		ret = iwl_mld_ampdu_rx_start(mld, sta, tid, ssn, buf_size,
					     timeout);
		break;
	case IEEE80211_AMPDU_RX_STOP:
		ret = iwl_mld_ampdu_rx_stop(mld, sta, tid);
		break;
	default:
		/* The mac80211 TX_AMPDU_SETUP_IN_HW flag is set for all
		 * devices, since all support TX A-MPDU offload in hardware.
		 * Therefore, no TX action should be requested here.
		 */
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	return ret;
}

static bool iwl_mld_can_hw_csum(struct sk_buff *skb)
{
	u8 protocol = ip_hdr(skb)->protocol;

	return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

static bool iwl_mld_mac80211_can_aggregate(struct ieee80211_hw *hw,
					   struct sk_buff *head,
					   struct sk_buff *skb)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	if (!IS_ENABLED(CONFIG_INET))
		return false;

	/* For now don't aggregate IPv6 in AMSDU */
	if (skb->protocol != htons(ETH_P_IP))
		return false;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (mld->trans->dbg_cfg.HW_CSUM_DISABLE)
		return false;
#endif

	/* Allow aggregation only if both frames have the same HW csum offload
	 * capability, ensuring consistent HW or SW csum handling in A-MSDU.
	 */
	return iwl_mld_can_hw_csum(skb) == iwl_mld_can_hw_csum(head);
}

static void iwl_mld_mac80211_sync_rx_queues(struct ieee80211_hw *hw)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	iwl_mld_sync_rx_queues(mld, IWL_MLD_RXQ_EMPTY, NULL, 0);
}

static void iwl_mld_sta_rc_update(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_link_sta *link_sta,
				  u32 changed)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	if (changed & (IEEE80211_RC_BW_CHANGED |
		       IEEE80211_RC_SUPP_RATES_CHANGED |
		       IEEE80211_RC_NSS_CHANGED)) {
		struct ieee80211_bss_conf *link =
			link_conf_dereference_check(vif, link_sta->link_id);

		if (WARN_ON(!link))
			return;

		iwl_mld_config_tlc_link(mld, vif, link, link_sta);
	}
}

static void iwl_mld_set_wakeup(struct ieee80211_hw *hw, bool enabled)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	device_set_wakeup_enable(mld->trans->dev, enabled);
}

/* Returns 0 on success. 1 if failed to suspend with wowlan:
 * If the circumstances didn't satisfy the conditions for suspension
 * with wowlan, mac80211 would use the no_wowlan flow.
 * If an error had occurred we update the trans status and state here
 * and the result will be stopping the FW.
 */
static int
iwl_mld_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	iwl_fw_runtime_suspend(&mld->fwrt);

	ret = iwl_mld_wowlan_suspend(mld, wowlan);
	if (ret) {
		if (ret < 0) {
			mld->trans->state = IWL_TRANS_NO_FW;
			set_bit(STATUS_FW_ERROR, &mld->trans->status);
		}
		return 1;
	}

	if (iwl_mld_no_wowlan_suspend(mld))
		return 1;

	return 0;
}

static int iwl_mld_resume(struct ieee80211_hw *hw)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int ret;

	ret = iwl_mld_wowlan_resume(mld);

	if (!ret)
		iwl_fw_runtime_resume(&mld->fwrt);

	return ret;
}

const struct ieee80211_ops iwl_mld_hw_ops = {
	.tx = iwl_mld_mac80211_tx,
	.start = iwl_mld_mac80211_start,
	.stop = iwl_mld_mac80211_stop,
	.config = iwl_mld_mac80211_config,
	.add_interface = iwl_mld_mac80211_add_interface,
	.remove_interface = iwl_mld_mac80211_remove_interface,
	.conf_tx = iwl_mld_mac80211_conf_tx,
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
	.cancel_hw_scan = iwl_mld_mac80211_cancel_hw_scan,
	.sched_scan_start = iwl_mld_mac80211_sched_scan_start,
	.sched_scan_stop = iwl_mld_mac80211_sched_scan_stop,
	.mgd_prepare_tx = iwl_mld_mac80211_mgd_prepare_tx,
	.mgd_complete_tx = iwl_mld_mac_mgd_complete_tx,
	.sta_state = iwl_mld_mac80211_sta_state,
	.flush = iwl_mld_mac80211_flush,
	.flush_sta = iwl_mld_mac80211_flush_sta,
	.ampdu_action = iwl_mld_mac80211_ampdu_action,
	.can_aggregate_in_amsdu = iwl_mld_mac80211_can_aggregate,
	.sync_rx_queues = iwl_mld_mac80211_sync_rx_queues,
	.link_sta_rc_update = iwl_mld_sta_rc_update,
#ifdef CONFIG_PM_SLEEP
	.suspend = iwl_mld_suspend,
	.resume = iwl_mld_resume,
	.set_wakeup = iwl_mld_set_wakeup,
	.set_rekey_data = iwl_mld_set_rekey_data,
#endif /* CONFIG_PM_SLEEP */
#ifdef CPTCFG_IWLWIFI_DEBUGFS
	.vif_add_debugfs = iwl_mld_add_vif_debugfs,
	.link_add_debugfs = iwl_mld_add_link_debugfs,
	.link_sta_add_debugfs = iwl_mld_add_link_sta_debugfs,
#endif
};
