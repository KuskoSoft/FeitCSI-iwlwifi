// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "link.h"
#include "iface.h"
#include "hcmd.h"
#include "phy.h"

#include "fw/api/context.h"

static int iwl_mld_send_link_cmd(struct iwl_mld *mld,
				 struct iwl_link_config_cmd *cmd,
				 enum iwl_ctxt_action action)
{
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	cmd->action = cpu_to_le32(action);
	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(MAC_CONF_GROUP, LINK_CONFIG_CMD),
				   cmd);
	if (ret)
		IWL_ERR(mld, "Failed to send LINK_CONFIG_CMD (action:%d): %d\n",
			action, ret);
	return ret;
}

static int iwl_mld_add_link_to_fw(struct iwl_mld *mld,
				  struct ieee80211_bss_conf *link_conf)
{
	struct ieee80211_vif *vif = link_conf->vif;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(link_conf);
	struct iwl_link_config_cmd cmd = {};

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(link->fw_id);
	cmd.mac_id = cpu_to_le32(mld_vif->fw_id);
	cmd.spec_link_id = link_conf->link_id;
	cmd.phy_id = cpu_to_le32(FW_CTXT_INVALID);

	ether_addr_copy(cmd.local_link_addr, link_conf->addr);

	if (vif->type == NL80211_IFTYPE_ADHOC && link_conf->bssid)
		ether_addr_copy(cmd.ibss_bssid_addr, link_conf->bssid);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_ADD);
}

static void iwl_mld_fill_rates(void) {}

static void iwl_mld_fill_pretection_flags(void) {}

static void iwl_mld_fill_qos_params(void) {}

static void iwl_mld_fill_mu_edca(void) {}

static int
iwl_mld_change_link_in_fw(struct iwl_mld *mld, struct ieee80211_bss_conf *link,
			  u32 changes)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	struct ieee80211_chanctx_conf *chan_ctx;
	struct ieee80211_vif *vif = link->vif;
	struct iwl_link_config_cmd cmd = {};
	u32 flags = 0;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(mld_link->fw_id);
	cmd.spec_link_id = link->link_id;
	cmd.mac_id = cpu_to_le32(iwl_mld_vif_from_mac80211(vif)->fw_id);

	chan_ctx = wiphy_dereference(mld->wiphy, mld_link->chan_ctx);

	cmd.phy_id = cpu_to_le32(chan_ctx ?
		iwl_mld_phy_from_mac80211(chan_ctx)->fw_id :
		FW_CTXT_INVALID);

	ether_addr_copy(cmd.local_link_addr, link->addr);

	cmd.active = cpu_to_le32(mld_link->active);

	if (vif->type == NL80211_IFTYPE_ADHOC && link->bssid)
		ether_addr_copy(cmd.ibss_bssid_addr, link->bssid);

	iwl_mld_fill_rates();

	cmd.cck_short_preamble = cpu_to_le32(link->use_short_preamble);
	cmd.short_slot = cpu_to_le32(link->use_short_slot);

	iwl_mld_fill_pretection_flags();

	iwl_mld_fill_qos_params();

	cmd.bi = cpu_to_le32(link->beacon_int);
	cmd.dtim_interval = cpu_to_le32(link->beacon_int * link->dtim_period);

	/* Configure HE parameters only if HE is supported, and only after
	 * the parameters are set in mac80211 (meaning after assoc)
	 */
	if (!link->he_support || iwlwifi_mod_params.disable_11ax ||
	    (vif->type == NL80211_IFTYPE_STATION && !vif->cfg.assoc)) {
		changes &= ~LINK_CONTEXT_MODIFY_HE_PARAMS;
		goto send_cmd;
	}

	cmd.htc_trig_based_pkt_ext = link->htc_trig_based_pkt_ext;

	if (link->uora_exists) {
		cmd.rand_alloc_ecwmin = link->uora_ocw_range & 0x7;
		cmd.rand_alloc_ecwmax = (link->uora_ocw_range >> 3) & 0x7;
	}

	iwl_mld_fill_mu_edca();

	cmd.bss_color = link->he_bss_color.color;

	if (!link->he_bss_color.enabled)
		flags |= LINK_FLG_BSS_COLOR_DIS;

	cmd.frame_time_rts_th = cpu_to_le16(link->frame_time_rts_th);

	/* Block 26-tone RU OFDMA transmissions */
	/* TODO: calculate he_ru_2mhz_block upon assoc (task=assoc) */
	if (mld_link->he_ru_2mhz_block)
		flags |= LINK_FLG_RU_2MHZ_BLOCK;

	if (link->nontransmitted) {
		ether_addr_copy(cmd.ref_bssid_addr, link->transmitter_bssid);
		cmd.bssid_index = link->bssid_index;
	}

	/* The only EHT parameter is puncturing, and starting from PHY cmd
	 * version 6 - it is sent there. For older versions of the PHY cmd,
	 * puncturing is not needed at all.
	 */
	if (WARN_ON(changes & LINK_CONTEXT_MODIFY_EHT_PARAMS))
		changes &= ~LINK_CONTEXT_MODIFY_EHT_PARAMS;

send_cmd:
	cmd.modify_mask = cpu_to_le32(changes);
	cmd.flags = cpu_to_le32(flags);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_MODIFY);
}

static int
iwl_mld_rm_link_from_fw(struct iwl_mld *mld, struct ieee80211_bss_conf *link)
{
	struct iwl_mld_link *mld_link = iwl_mld_link_from_mac80211(link);
	struct iwl_link_config_cmd cmd = {};

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON(!mld_link))
		return -EINVAL;

	cmd.link_id = cpu_to_le32(mld_link->fw_id);
	cmd.spec_link_id = link->link_id;
	cmd.phy_id = cpu_to_le32(FW_CTXT_INVALID);

	return iwl_mld_send_link_cmd(mld, &cmd, FW_CTXT_ACTION_REMOVE);
}

static int iwl_mld_deactivate_link_in_fw(struct iwl_mld *mld,
					 struct ieee80211_bss_conf *link)
{
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	ret = iwl_mld_cancel_session_protection(mld, link->vif, link->link_id);

	if (ret)
		return ret;

	ret = iwl_mld_change_link_in_fw(mld, link,
					LINK_CONTEXT_MODIFY_ACTIVE);

	return ret;
}

IWL_MLD_ALLOC_FN(link, bss_conf)

/* Constructor function for struct iwl_mld_link */
static int
iwl_mld_init_link(struct iwl_mld *mld, struct ieee80211_bss_conf *link,
		  struct iwl_mld_link *mld_link)
{
	return iwl_mld_allocate_link_fw_id(mld, mld_link, link);
}

/* Initializes the link structure, maps fw id to the ieee80211_bss_conf, and
 * adds a link to the fw
 */
int iwl_mld_add_link(struct iwl_mld *mld,
		     struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(bss_conf);
	int ret;

	ret = iwl_mld_init_link(mld, bss_conf, link);
	if (ret)
		return ret;

	ret = iwl_mld_add_link_to_fw(mld, bss_conf);
	if (ret)
		RCU_INIT_POINTER(mld->fw_id_to_bss_conf[link->fw_id], NULL);

	return ret;
}

/* Remove link from fw, unmap the bss_conf, and destroy the link structure */
int iwl_mld_remove_link(struct iwl_mld *mld,
			struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_link *link = iwl_mld_link_from_mac80211(bss_conf);
	int ret;

	if (link->active) {
		ret = iwl_mld_deactivate_link_in_fw(mld, bss_conf);
		if (ret)
			return ret;
		link->active = false;
	}

	ret = iwl_mld_rm_link_from_fw(mld, bss_conf);
	if (ret)
		return ret;

	if (WARN_ON(link->fw_id >= ARRAY_SIZE(mld->fw_id_to_bss_conf)))
		return -EINVAL;

	RCU_INIT_POINTER(mld->fw_id_to_bss_conf[link->fw_id], NULL);

	return 0;
}
