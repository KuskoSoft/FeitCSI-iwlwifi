// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "link.h"
#include "iface.h"
#include "hcmd.h"

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

static int
iwl_mld_change_link_in_fw(struct iwl_mld *mld, struct ieee80211_bss_conf *link,
			  u32 changes, bool active)
{
	lockdep_assert_wiphy(mld->wiphy);

	WARN_ONCE(1, "Not supported yet\n");

	return -EOPNOTSUPP;
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

	/* TODO: remove session protection for that link, if any */

	ret = iwl_mld_change_link_in_fw(mld, link,
					LINK_CONTEXT_MODIFY_ACTIVE,
					false);

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
