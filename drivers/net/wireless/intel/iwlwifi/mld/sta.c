// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "sta.h"
#include "hcmd.h"
#include "iface.h"

static int
iwl_mld_fw_sta_id_from_link_sta(struct iwl_mld *mld,
				struct ieee80211_link_sta *link_sta)
{
	for (int fw_id = 0; fw_id < ARRAY_SIZE(mld->fw_id_to_link_sta);
	     fw_id++) {
		struct ieee80211_link_sta *l_sta;

		l_sta = rcu_access_pointer(mld->fw_id_to_link_sta[fw_id]);

		if (l_sta == link_sta)
			return fw_id;
	}
	return -ENOENT;
}

static void
iwl_mld_fill_ampdu_size_and_dens(struct ieee80211_link_sta *link_sta,
				 __le32 *tx_ampdu_max_size,
				 __le32 *tx_ampdu_spacing)
{
	/* TODO */
}

static u8 iwl_mld_get_uapsd_acs(struct ieee80211_sta *sta)
{
	/* TODO */
	return 0;
}

static void iwl_mld_fill_pkt_ext(struct ieee80211_link_sta *link_sta,
				 struct iwl_he_pkt_ext_v2 *pkt_ext)
{
	/* TODO (task=EHT connection)*/
}

static u32 iwl_mld_get_htc_flags(struct ieee80211_link_sta *link_sta)
{
	/* TODO */
	return 0;
}

static int iwl_mld_send_sta_cmd(struct iwl_mld *mld,
				const struct iwl_sta_cfg_cmd *cmd)
{
	int ret = iwl_mld_send_cmd_pdu(mld,
				       WIDE_ID(MAC_CONF_GROUP, STA_CONFIG_CMD),
				       cmd);
	if (ret)
		IWL_ERR(mld, "STA_CONFIG_CMD send failed, ret=0x%x\n", ret);
	return ret;
}

static int
iwl_mld_add_modify_sta_cmd(struct iwl_mld *mld,
			   struct ieee80211_link_sta *link_sta)
{
	struct ieee80211_sta *sta = link_sta->sta;
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_bss_conf *link;
	struct iwl_mld_link *mld_link;
	struct iwl_sta_cfg_cmd cmd = {};
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

	lockdep_assert_wiphy(mld->wiphy);

	link = link_conf_dereference_protected(mld_sta->vif,
					       link_sta->link_id);

	mld_link = iwl_mld_link_from_mac80211(link);

	if (WARN_ON(!link || !mld_link || fw_id < 0))
		return -EINVAL;

	cmd.sta_id = cpu_to_le32(fw_id);
	cmd.station_type = cpu_to_le32(mld_sta->sta_type);
	cmd.link_id = cpu_to_le32(mld_link->fw_id);

	memcpy(&cmd.peer_mld_address, sta->addr, ETH_ALEN);
	memcpy(&cmd.peer_link_address, link_sta->addr, ETH_ALEN);

	if (mld_sta->sta_state >= IEEE80211_STA_ASSOC)
		cmd.assoc_id = cpu_to_le32(sta->aid);

	if (sta->mfp || mld_sta->sta_state < IEEE80211_STA_AUTHORIZED)
		cmd.mfp = cpu_to_le32(1);

	switch (link_sta->rx_nss) {
	case 1:
		cmd.mimo = cpu_to_le32(0);
		break;
	case 2 ... 8:
		cmd.mimo = cpu_to_le32(1);
		break;
	}

	switch (link_sta->smps_mode) {
	case IEEE80211_SMPS_AUTOMATIC:
	case IEEE80211_SMPS_NUM_MODES:
		WARN_ON(1);
		break;
	case IEEE80211_SMPS_STATIC:
		/* override NSS */
		cmd.mimo = cpu_to_le32(0);
		break;
	case IEEE80211_SMPS_DYNAMIC:
		cmd.mimo_protection = cpu_to_le32(1);
		break;
	case IEEE80211_SMPS_OFF:
		/* nothing */
		break;
	}

	iwl_mld_fill_ampdu_size_and_dens(link_sta, &cmd.tx_ampdu_max_size,
					 &cmd.tx_ampdu_spacing);

	if (sta->wme) {
		cmd.sp_length =
			cpu_to_le32(sta->max_sp ? sta->max_sp * 2 : 128);
		cmd.uapsd_acs = cpu_to_le32(iwl_mld_get_uapsd_acs(sta));
	}

	if (link_sta->he_cap.has_he) {
		cmd.trig_rnd_alloc =
			cpu_to_le32(link->uora_exists ? 1 : 0);

		/* PPE Thresholds */
		iwl_mld_fill_pkt_ext(link_sta, &cmd.pkt_ext);

		/* HTC flags */
		cmd.htc_flags =
			cpu_to_le32(iwl_mld_get_htc_flags(link_sta));

		if (link_sta->he_cap.he_cap_elem.mac_cap_info[2] &
		    IEEE80211_HE_MAC_CAP2_ACK_EN)
			cmd.ack_enabled = cpu_to_le32(1);
	}

	return iwl_mld_send_sta_cmd(mld, &cmd);
}

IWL_MLD_ALLOC_FN(link_sta, link_sta)

static int
iwl_mld_add_link_sta(struct iwl_mld *mld, struct ieee80211_link_sta *link_sta)
{
	int ret;
	u8 fw_id;

	/* We need to preserve the fw sta ids during a restart, since the fw
	 * will recover SN/PN for them
	 */
	if (!mld->fw_status.in_hw_restart) {
		/* Allocate a fw id and map it to the link_sta */
		ret = iwl_mld_allocate_link_sta_fw_id(mld, &fw_id, link_sta);
		if (ret)
			return ret;
	}

	ret = iwl_mld_add_modify_sta_cmd(mld, link_sta);
	if (ret)
		RCU_INIT_POINTER(mld->fw_id_to_link_sta[fw_id], NULL);

	return ret;
}

static int
iwl_mvm_remove_link_sta(struct iwl_mld *mld,
			struct ieee80211_link_sta *link_sta)
{
	int fw_id = iwl_mld_fw_sta_id_from_link_sta(mld, link_sta);

	if (WARN_ON(fw_id < 0))
		return fw_id;

	/* TODO: send command to remove from FW */

	RCU_INIT_POINTER(mld->fw_id_to_link_sta[fw_id], NULL);

	return 0;
}

static void
iwl_mld_init_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		 struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);

	mld_sta->vif = vif;
	mld_sta->sta_type = type;
}

int iwl_mld_add_sta(struct iwl_mld *mld, struct ieee80211_sta *sta,
		    struct ieee80211_vif *vif, enum iwl_fw_sta_type type)
{
	iwl_mld_init_sta(mld, sta, vif, type);

	/* When the sta is added, i.e. its state is moving from NOTEXIST to
	 * NONE, it can't have more then one active link_sta,
	 * and that one active link_sta is deflink.
	 * In restart when in EMLSR, mac80211 will first configure us to one
	 * link, and then explicitly activate the second link and the link_sta.
	 */
	return iwl_mld_add_link_sta(mld, &sta->deflink);
}

int iwl_mld_remove_sta(struct iwl_mld *mld, struct ieee80211_sta *sta)
{
	struct iwl_mld_sta *mld_sta = iwl_mld_sta_from_mac80211(sta);
	struct ieee80211_link_sta *link_sta;
	u8 link_id;
	int ret;

	/* Remove all link_sta's*/
	for_each_sta_active_link(mld_sta->vif, sta, link_sta, link_id) {
		ret = iwl_mvm_remove_link_sta(mld, link_sta);
		if (ret)
			break;
	}
	return ret;
}
