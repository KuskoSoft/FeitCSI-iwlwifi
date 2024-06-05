// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"
#include "mac80211.h"
#include "fw/api/scan.h"
#ifdef CONFIG_PM_SLEEP
#include "fw/api/d3.h"
#endif /* CONFIG_PM_SLEEP */

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

	/* LAR is expected to be enabled for all supported devices */
	WARN_ON(!mld->nvm_data->lar_enabled);

	wiphy->regulatory_flags |= REGULATORY_WIPHY_SELF_MANAGED;
	wiphy->regulatory_flags |= REGULATORY_ENABLE_RELAX_NO_IR;
}

static void iwl_mld_hw_set_pm(struct iwl_mld *mld)
{
#ifdef CONFIG_PM_SLEEP
	struct wiphy *wiphy = mld->wiphy;
	u8 cmd_ver = iwl_fw_lookup_cmd_ver(mld->fw,
					   SCAN_OFFLOAD_UPDATE_PROFILES_CMD,
					   IWL_FW_CMD_VER_UNKNOWN);

	if (!device_can_wakeup(mld->trans->dev))
		return;

	/* All supported devices are currently using version 3 of the cmd.
	 * Since version 3, IWL_SCAN_MAX_PROFILES_V2 shall be used where
	 * necessary, verify that once here.
	 */
	WARN_ONCE(cmd_ver != 3,
		  "Unexpected SCAN_OFFLOAD_UPDATE_PROFILES_CMD version %d\n",
		  cmd_ver);

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

int iwl_mld_register_hw(struct iwl_mld *mld)
{
	struct ieee80211_hw *hw = mld->hw;

	hw->queues = IEEE80211_NUM_ACS;

	iwl_mld_hw_set_addresses(mld);
	iwl_mld_hw_set_channels(mld);
	iwl_mld_hw_set_security(mld);
	iwl_mld_hw_set_regulatory(mld);
	iwl_mld_hw_set_pm(mld);

	return ieee80211_register_hw(mld->hw);
}

static void
iwl_mld_mac80211_tx(struct ieee80211_hw *hw,
		    struct ieee80211_tx_control *control, struct sk_buff *skb)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_mac80211_start(struct ieee80211_hw *hw)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_mac80211_stop(struct ieee80211_hw *hw, bool suspend)
{
	WARN_ON("Not supported yet\n");
}

static
int iwl_mld_mac80211_config(struct ieee80211_hw *hw, u32 changed)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
int iwl_mld_mac80211_add_interface(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif)
{
	WARN_ON("Not supported yet\n");
	return -EOPNOTSUPP;
}

static
void iwl_mld_mac80211_remove_interface(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif)
{
	WARN_ON("Not supported yet\n");
}

static
void iwl_mld_mac80211_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *total_flags,
				       u64 multicast)
{
	WARN_ON("Not supported yet\n");
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

const struct ieee80211_ops iwl_mld_hw_ops = {
	.tx = iwl_mld_mac80211_tx,
	.start = iwl_mld_mac80211_start,
	.stop = iwl_mld_mac80211_stop,
	.config = iwl_mld_mac80211_config,
	.add_interface = iwl_mld_mac80211_add_interface,
	.remove_interface = iwl_mld_mac80211_remove_interface,
	.configure_filter = iwl_mld_mac80211_configure_filter,
	.wake_tx_queue = iwl_mld_mac80211_wake_tx_queue,
	.add_chanctx = iwl_mld_add_chanctx,
	.remove_chanctx = iwl_mld_remove_chanctx,
	.change_chanctx = iwl_mld_change_chanctx,
	.assign_vif_chanctx = iwl_mld_assign_vif_chanctx,
	.unassign_vif_chanctx = iwl_mld_unassign_vif_chanctx,
#ifdef CONFIG_PM_SLEEP
	.suspend = iwl_mld_suspend,
	.resume = iwl_mld_resume,
#endif /* CONFIG_PM_SLEEP */
};
