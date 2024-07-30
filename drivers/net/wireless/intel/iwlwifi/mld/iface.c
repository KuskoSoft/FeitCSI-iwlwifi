// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <net/cfg80211.h>

#include "iface.h"
#include "hcmd.h"

#include "fw/api/context.h"
#include "fw/api/mac.h"

/* Cleanup function for struct iwl_mld_vif, will be called in restart */
void iwl_mld_cleanup_vif(void *data, u8 *mac, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link;

	/* TODO: remove (task=p2p) */
	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION)
		return;

	for_each_mld_vif_valid_link(mld_vif, link)
		iwl_mld_cleanup_link(link);

	CLEANUP_STRUCT(mld_vif);
}

static int iwl_mld_send_mac_cmd(struct iwl_mld *mld,
				struct iwl_mac_config_cmd *cmd)
{
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(MAC_CONF_GROUP, MAC_CONFIG_CMD),
				   cmd);
	if (ret)
		IWL_ERR(mld, "Failed to send MAC_CONFIG_CMD ret = %d\n", ret);

	return ret;
}

int iwl_mld_mac80211_iftype_to_fw(const struct ieee80211_vif *vif)
{
	switch (vif->type) {
	case NL80211_IFTYPE_STATION:
		return vif->p2p ? FW_MAC_TYPE_P2P_STA : FW_MAC_TYPE_BSS_STA;
	case NL80211_IFTYPE_AP:
		return FW_MAC_TYPE_GO;
	case NL80211_IFTYPE_MONITOR:
		return FW_MAC_TYPE_LISTENER;
	case NL80211_IFTYPE_P2P_DEVICE:
		return FW_MAC_TYPE_P2P_DEVICE;
	case NL80211_IFTYPE_ADHOC:
		return FW_MAC_TYPE_IBSS;
	default:
		WARN_ON_ONCE(1);
	}
	return FW_MAC_TYPE_BSS_STA;
}

static bool iwl_mld_is_nic_ack_enabled(struct iwl_mld *mld,
				       struct ieee80211_vif *vif)
{
	const struct ieee80211_supported_band *sband;
	const struct ieee80211_sta_he_cap *own_he_cap;

	lockdep_assert_wiphy(mld->wiphy);

	/* This capability is the same for all bands,
	 * so take it from one of them.
	 */
	sband = mld->hw->wiphy->bands[NL80211_BAND_2GHZ];
	own_he_cap = ieee80211_get_he_iftype_cap_vif(sband, vif);

	return own_he_cap && (own_he_cap->he_cap_elem.mac_cap_info[2] &
			       IEEE80211_HE_MAC_CAP2_ACK_EN);
}

/* fill the common part for all interface types */
static void iwl_mld_mac_cmd_fill_common(struct iwl_mld *mld,
					struct ieee80211_vif *vif,
					struct iwl_mac_config_cmd *cmd,
					u32 action)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct ieee80211_bss_conf *link_conf;
	unsigned int link_id;

	lockdep_assert_wiphy(mld->wiphy);

	cmd->id_and_color = cpu_to_le32(mld_vif->fw_id);
	cmd->action = cpu_to_le32(action);

	cmd->mac_type =
		cpu_to_le32(iwl_mld_mac80211_iftype_to_fw(vif));

	memcpy(cmd->local_mld_addr, vif->addr, ETH_ALEN);

	if (iwlwifi_mod_params.disable_11ax)
		return;

	cmd->nic_not_ack_enabled =
		cpu_to_le32(!iwl_mld_is_nic_ack_enabled(mld, vif));

	/* If we have MLO enabled, then the firmware needs to enable
	 * address translation for the station(s) we add. That depends
	 * on having EHT enabled in firmware, which in turn depends on
	 * mac80211 in the code below.
	 * However, mac80211 doesn't enable HE/EHT until it has parsed
	 * the association response successfully, so just skip all that
	 * and enable both when we have MLO.
	 */
	if (ieee80211_vif_is_mld(vif)) {
		if (vif->type == NL80211_IFTYPE_AP)
			cmd->he_ap_support = cpu_to_le16(1);
		else
			cmd->he_support = cpu_to_le16(1);

		cmd->eht_support = cpu_to_le32(1);
		return;
	}

	for_each_vif_active_link(vif, link_conf, link_id) {
		if (!link_conf->he_support)
			continue;

		if (vif->type == NL80211_IFTYPE_AP)
			cmd->he_ap_support = cpu_to_le16(1);
		else
			cmd->he_support = cpu_to_le16(1);

		/* EHT, if supported, was already set above */
		break;
	}
}

static void iwl_mld_fill_mac_cmd_sta(struct iwl_mld *mld,
				     struct ieee80211_vif *vif, u32 action,
				     struct iwl_mac_config_cmd *cmd)
{
	lockdep_assert_wiphy(mld->wiphy);

	WARN_ON(vif->type != NL80211_IFTYPE_STATION);

	WARN(vif->p2p, "not supported yet\n");

	/* We always want to hear MCAST frames, if we're not authorized yet,
	 * we'll drop them.
	 */
	cmd->filter_flags |= cpu_to_le32(MAC_CFG_FILTER_ACCEPT_GRP);

	/* Adding a MAC ctxt with is_assoc set is not allowed in fw
	 * (and shouldn't happen)
	 */
	if (vif->cfg.assoc && action != FW_CTXT_ACTION_ADD) {
		cmd->client.is_assoc = 1;

		if (!iwl_mld_vif_from_mac80211(vif)->authorized)
			cmd->client.data_policy |=
				cpu_to_le16(COEX_HIGH_PRIORITY_ENABLE);
	} else {
		/* Allow beacons to pass through as long as we are not
		 * associated
		 */
		cmd->filter_flags |= cpu_to_le32(MAC_CFG_FILTER_ACCEPT_BEACON);
	}

	cmd->client.assoc_id = cpu_to_le16(vif->cfg.aid);

	if (ieee80211_vif_is_mld(vif)) {
		u16 esr_transition_timeout =
			u16_get_bits(vif->cfg.eml_cap,
				     IEEE80211_EML_CAP_TRANSITION_TIMEOUT);

		cmd->client.esr_transition_timeout =
			min_t(u16, IEEE80211_EML_CAP_TRANSITION_TIMEOUT_128TU,
			      esr_transition_timeout);
		cmd->client.medium_sync_delay =
			cpu_to_le16(vif->cfg.eml_med_sync_delay);
	}

	/* TODO: set TWT flags. (task=TWT) */
	/* TODO: set ctwin in p2p (task=p2p) */
	/* TODO: set MAC_CFG_FILTER_ACCEPT_PROBE_REQ in p2p (task=p2p) */
}

static int
iwl_mld_rm_mac_from_fw(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mac_config_cmd cmd = {
		.action = cpu_to_le32(FW_CTXT_ACTION_REMOVE),
		.id_and_color = cpu_to_le32(mld_vif->fw_id),
	};

	return iwl_mld_send_mac_cmd(mld, &cmd);
}

int iwl_mld_mac_fw_action(struct iwl_mld *mld, struct ieee80211_vif *vif,
			  u32 action)
{
	struct iwl_mac_config_cmd cmd = {};

	lockdep_assert_wiphy(mld->wiphy);

	if (action == FW_CTXT_ACTION_REMOVE)
		return iwl_mld_rm_mac_from_fw(mld, vif);

	iwl_mld_mac_cmd_fill_common(mld, vif, &cmd, action);

	switch (vif->type) {
	case NL80211_IFTYPE_STATION:
		iwl_mld_fill_mac_cmd_sta(mld, vif, action, &cmd);
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_P2P_DEVICE:
	case NL80211_IFTYPE_ADHOC:
	default:
		WARN(1, "not supported yet\n");
		return -EOPNOTSUPP;
	}

	return iwl_mld_send_mac_cmd(mld, &cmd);
}

IWL_MLD_ALLOC_FN(vif, vif)

/* Constructor function for struct iwl_mld_vif */
static int
iwl_mld_init_vif(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	mld_vif->mld = mld;

	ret = iwl_mld_allocate_vif_fw_id(mld, &mld_vif->fw_id, vif);
	if (ret)
		return ret;

	/* the first link points to the default one when in non-MLO */
	RCU_INIT_POINTER(mld_vif->link[0], &mld_vif->deflink);

	return 0;
}

int iwl_mld_add_vif(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION) {
		IWL_ERR(mld, "NOT IMPLEMENTED YET: %s\n", __func__);
		return 0;
	}

	ret = iwl_mld_init_vif(mld, vif);
	if (ret)
		return ret;

	ret = iwl_mld_mac_fw_action(mld, vif, FW_CTXT_ACTION_ADD);
	if (ret)
		RCU_INIT_POINTER(mld->fw_id_to_vif[mld_vif->fw_id], NULL);

	return ret;
}

int iwl_mld_rm_vif(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	WARN_ON(ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION);

	ret = iwl_mld_mac_fw_action(mld, vif, FW_CTXT_ACTION_REMOVE);

	if (WARN_ON(mld_vif->fw_id >= ARRAY_SIZE(mld->fw_id_to_vif)))
		return -EINVAL;

	RCU_INIT_POINTER(mld->fw_id_to_vif[mld_vif->fw_id], NULL);

	return ret;
}

void iwl_mld_set_vif_associated(struct iwl_mld *mld,
				struct ieee80211_vif *vif)
{
	struct ieee80211_bss_conf *link;
	unsigned int link_id;

	for_each_vif_active_link(vif, link, link_id) {
		if (iwl_mld_link_set_associated(mld, vif, link))
			IWL_ERR(mld, "failed to update link %d\n", link_id);
	}
	/* todo:  update_mu_groups
	 * todo: recalc_multicast
	 * todo: coex: coex_vif_change and reset ave_beacon_signal
	 */
}
