// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <net/cfg80211.h>

#include "iface.h"
#include "hcmd.h"

#include "fw/api/context.h"
#include "fw/api/mac.h"
#include "fw/api/time-event.h"

/* Cleanup function for struct iwl_mld_vif, will be called in restart */
void iwl_mld_cleanup_vif(void *data, u8 *mac, struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link;

	if (vif->type != NL80211_IFTYPE_STATION &&
	    vif->type != NL80211_IFTYPE_AP &&
	    vif->type != NL80211_IFTYPE_P2P_DEVICE)
		return;

	mld_vif->roc_activity = ROC_NUM_ACTIVITIES;

	for_each_mld_vif_valid_link(mld_vif, link)
		iwl_mld_cleanup_link(mld_vif->mld, link);

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

static void iwl_mld_fill_mac_cmd_ap(struct iwl_mld *mld,
				    struct ieee80211_vif *vif,
				    struct iwl_mac_config_cmd *cmd)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	lockdep_assert_wiphy(mld->wiphy);

	WARN_ON(vif->type != NL80211_IFTYPE_AP);

	WARN(vif->p2p, "not supported yet\n");

	cmd->filter_flags |= cpu_to_le32(MAC_CFG_FILTER_ACCEPT_PROBE_REQ);

	/* in AP mode, pass beacons from other APs (needed for ht protection).
	 * When there're no any associated station, which means that we are not
	 * TXing anyway, don't ask FW to pass beacons to prevent unnecessary
	 * wake-ups.
	 */
	if (mld_vif->num_associated_stas)
		cmd->filter_flags |= cpu_to_le32(MAC_CFG_FILTER_ACCEPT_BEACON);
}

static void iwl_mld_go_iterator(void *_data, u8 *mac, struct ieee80211_vif *vif)
{
	bool *go_active = _data;

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_P2P_GO &&
	    iwl_mld_vif_from_mac80211(vif)->ap_ibss_active)
		*go_active = true;
}

static bool iwl_mld_p2p_dev_has_extended_disc(struct iwl_mld *mld)
{
	bool go_active = false;

	/* This flag should be set to true when the P2P Device is
	 * discoverable and there is at least a P2P GO. Setting
	 * this flag will allow the P2P Device to be discoverable on other
	 * channels in addition to its listen channel.
	 * Note that this flag should not be set in other cases as it opens the
	 * Rx filters on all MAC and increases the number of interrupts.
	 */
	ieee80211_iterate_active_interfaces(mld->hw,
					IEEE80211_IFACE_ITER_RESUME_ALL,
					iwl_mld_go_iterator, &go_active);

	return go_active;
}

static void iwl_mld_fill_mac_cmd_p2p_dev(struct iwl_mld *mld,
					 struct ieee80211_vif *vif,
					 struct iwl_mac_config_cmd *cmd)
{
	bool ext_disc = iwl_mld_p2p_dev_has_extended_disc(mld);

	lockdep_assert_wiphy(mld->wiphy);

	/* Override the filter flags to accept all management frames. This is
	 * needed to support both P2P device discovery using probe requests and
	 * P2P service discovery using action frames
	 */
	cmd->filter_flags = cpu_to_le32(MAC_CFG_FILTER_ACCEPT_CONTROL_AND_MGMT);

	if (ext_disc)
		cmd->p2p_dev.is_disc_extended = cpu_to_le32(1);
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
		iwl_mld_fill_mac_cmd_ap(mld, vif, &cmd);
		break;
	case NL80211_IFTYPE_MONITOR:
		cmd.filter_flags =
			cpu_to_le32(MAC_CFG_FILTER_PROMISC |
				    MAC_CFG_FILTER_ACCEPT_CONTROL_AND_MGMT |
				    MAC_CFG_FILTER_ACCEPT_BEACON |
				    MAC_CFG_FILTER_ACCEPT_PROBE_REQ |
				    MAC_CFG_FILTER_ACCEPT_GRP);
		break;
	case NL80211_IFTYPE_P2P_DEVICE:
		iwl_mld_fill_mac_cmd_p2p_dev(mld, vif, &cmd);
		break;
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
	mld_vif->roc_activity = ROC_NUM_ACTIVITIES;

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

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION &&
	    ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_AP &&
	    vif->type != NL80211_IFTYPE_P2P_DEVICE &&
	    vif->type != NL80211_IFTYPE_MONITOR) {
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

	WARN_ON(ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION &&
		ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_AP &&
		vif->type != NL80211_IFTYPE_P2P_DEVICE &&
		vif->type != NL80211_IFTYPE_MONITOR);

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

static void iwl_mld_get_fw_id_bss_bitmap_iter(void *_data, u8 *mac,
					      struct ieee80211_vif *vif)
{
	u8 *fw_id_bitmap = _data;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	if (ieee80211_vif_type_p2p(vif) != NL80211_IFTYPE_STATION)
		return;

	*fw_id_bitmap |= BIT(mld_vif->fw_id);
}

u8 iwl_mld_get_fw_bss_vifs_ids(struct iwl_mld *mld)
{
	u8 fw_id_bitmap = 0;

	ieee80211_iterate_interfaces(mld->hw,
				     IEEE80211_IFACE_SKIP_SDATA_NOT_IN_DRIVER,
				     iwl_mld_get_fw_id_bss_bitmap_iter,
				     &fw_id_bitmap);

	return fw_id_bitmap;
}
