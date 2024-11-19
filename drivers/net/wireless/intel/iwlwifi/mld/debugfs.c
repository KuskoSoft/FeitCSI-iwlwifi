/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "debugfs.h"
#include "iwl-io.h"
#include "hcmd.h"
#include "iface.h"
#include "sta.h"
#include "tlc.h"
#include "power.h"
#include "notif.h"
#include "ap.h"
#include "iwl-utils.h"

#include "fw/api/rs.h"
#include "fw/api/dhc.h"

#define MLD_DEBUGFS_READ_FILE_OPS(name, bufsz)				\
	_MLD_DEBUGFS_READ_FILE_OPS(name, bufsz, struct iwl_mld)

#define MLD_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, mld,			\
			    &iwl_dbgfs_##name##_ops);			\
	} while (0)
#define MLD_DEBUGFS_ADD_FILE(name, parent, mode)			\
	MLD_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

static bool iwl_mld_dbgfs_fw_cmd_disabled(struct iwl_mld *mld)
{
#ifdef CONFIG_PM_SLEEP
	return !mld->fw_status.running || mld->fw_status.in_d3;
#else
	return !mld->fw_status.running;
#endif /* CONFIG_PM_SLEEP */
}

static ssize_t iwl_dbgfs_fw_dbg_clear_write(struct iwl_mld *mld,
					    char *buf, size_t count)
{
	/* If the firmware is not running, silently succeed since there is
	 * no data to clear.
	 */
	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return 0;

	iwl_fw_dbg_clear_monitor_buf(&mld->fwrt);

	return count;
}

static ssize_t iwl_dbgfs_fw_nmi_write(struct iwl_mld *mld, char *buf,
				      size_t count)
{
	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	IWL_ERR(mld, "Triggering an NMI from debugfs\n");

	if (count == 6 && !strcmp(buf, "nolog\n"))
		mld->fw_status.do_not_dump_once = true;

	iwl_force_nmi(mld->trans);

	return count;
}

static ssize_t iwl_dbgfs_fw_restart_write(struct iwl_mld *mld, char *buf,
					  size_t count)
{
	int __maybe_unused ret;

	if (!iwlwifi_mod_params.fw_restart)
		return -EPERM;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	if (count == 6 && !strcmp(buf, "nolog\n")) {
		mld->fw_status.do_not_dump_once = true;
		set_bit(STATUS_SUPPRESS_CMD_ERROR_ONCE, &mld->trans->status);
	}

	/* take the return value to make compiler happy - it will
	 * fail anyway
	 */
	ret = iwl_mld_send_cmd_empty(mld, WIDE_ID(LONG_GROUP, REPLY_ERROR));

	return count;
}

struct iwl_mld_sniffer_apply {
	struct iwl_mld *mld;
	const u8 *bssid;
	u16 aid;
};

static bool iwl_mld_sniffer_apply(struct iwl_notif_wait_data *notif_data,
				  struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mld_sniffer_apply *apply = data;

	apply->mld->monitor.cur_aid = cpu_to_le16(apply->aid);
	memcpy(apply->mld->monitor.cur_bssid, apply->bssid,
	       sizeof(apply->mld->monitor.cur_bssid));

	return true;
}

static ssize_t
iwl_dbgfs_he_sniffer_params_write(struct iwl_mld *mld, char *buf,
				  size_t count)
{
	struct iwl_notification_wait wait;
	struct iwl_he_monitor_cmd he_mon_cmd = {};
	struct iwl_mld_sniffer_apply apply = {
		.mld = mld,
	};
	u16 wait_cmds[] = {
		WIDE_ID(DATA_PATH_GROUP, HE_AIR_SNIFFER_CONFIG_CMD),
	};
	u32 aid;
	int ret;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	if (!mld->monitor.on)
		return -ENODEV;

	ret = sscanf(buf, "%x %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &aid,
		     &he_mon_cmd.bssid[0], &he_mon_cmd.bssid[1],
		     &he_mon_cmd.bssid[2], &he_mon_cmd.bssid[3],
		     &he_mon_cmd.bssid[4], &he_mon_cmd.bssid[5]);
	if (ret != 7)
		return -EINVAL;

	he_mon_cmd.aid = cpu_to_le16(aid);

	apply.aid = aid;
	apply.bssid = (void *)he_mon_cmd.bssid;

	/* Use the notification waiter to get our function triggered
	 * in sequence with other RX. This ensures that frames we get
	 * on the RX queue _before_ the new configuration is applied
	 * still have mld->cur_aid pointing to the old AID, and that
	 * frames on the RX queue _after_ the firmware processed the
	 * new configuration (and sent the response, synchronously)
	 * get mld->cur_aid correctly set to the new AID.
	 */
	iwl_init_notification_wait(&mld->notif_wait, &wait,
				   wait_cmds, ARRAY_SIZE(wait_cmds),
				   iwl_mld_sniffer_apply, &apply);

	ret = iwl_mld_send_cmd_pdu(mld,
				   WIDE_ID(DATA_PATH_GROUP,
					   HE_AIR_SNIFFER_CONFIG_CMD),
				   &he_mon_cmd);

	/* no need to really wait, we already did anyway */
	iwl_remove_notification(&mld->notif_wait, &wait);

	return ret ?: count;
}

static ssize_t
iwl_dbgfs_he_sniffer_params_read(struct iwl_mld *mld, size_t count,
				 char *buf)
{
	return scnprintf(buf, sizeof(buf),
			 "%d %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
			 le16_to_cpu(mld->monitor.cur_aid),
			 mld->monitor.cur_bssid[0], mld->monitor.cur_bssid[1],
			 mld->monitor.cur_bssid[2], mld->monitor.cur_bssid[3],
			 mld->monitor.cur_bssid[4], mld->monitor.cur_bssid[5]);
}

WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(fw_nmi, 10);
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(fw_restart, 10);
WIPHY_DEBUGFS_READ_WRITE_FILE_OPS_MLD(he_sniffer_params, 32);
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(fw_dbg_clear, 10);

static ssize_t iwl_dbgfs_wifi_6e_enable_read(struct iwl_mld *mld,
					     size_t count, u8 *buf)
{
	int err;
	u32 value;

	err = iwl_bios_get_dsm(&mld->fwrt, DSM_FUNC_ENABLE_6E, &value);
	if (err)
		return err;

	return scnprintf(buf, count, "0x%08x\n", value);
}

MLD_DEBUGFS_READ_FILE_OPS(wifi_6e_enable, 64);

static ssize_t iwl_dbgfs_inject_packet_write(struct iwl_mld *mld,
					     char *buf, size_t count)
{
	struct iwl_op_mode *opmode = container_of((void *)mld,
						  struct iwl_op_mode,
						  op_mode_specific);
	struct iwl_rx_cmd_buffer rxb = {};
	struct iwl_rx_packet *pkt;
	int n_bytes = count / 2;
	int ret = -EINVAL;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	rxb._page = alloc_pages(GFP_KERNEL, 0);
	if (!rxb._page)
		return -ENOMEM;
	pkt = rxb_addr(&rxb);

	ret = hex2bin(page_address(rxb._page), buf, n_bytes);
	if (ret)
		goto out;

	/* avoid invalid memory access and malformed packet */
	if (n_bytes < sizeof(*pkt) ||
	    n_bytes != sizeof(*pkt) + iwl_rx_packet_payload_len(pkt))
		goto out;

	local_bh_disable();
	iwl_mld_rx(opmode, NULL, &rxb);
	local_bh_enable();
	ret = 0;

out:
	iwl_free_rxb(&rxb);

	return ret ?: count;
}

WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(inject_packet, 512);

void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir)
{
	/* Add debugfs files here */

	MLD_DEBUGFS_ADD_FILE(fw_nmi, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(fw_restart, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(wifi_6e_enable, debugfs_dir, 0400);
	MLD_DEBUGFS_ADD_FILE(he_sniffer_params, debugfs_dir, 0600);
	MLD_DEBUGFS_ADD_FILE(fw_dbg_clear, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(inject_packet, debugfs_dir, 0200);

	/* Create a symlink with mac80211. It will be removed when mac80211
	 * exits (before the opmode exits which removes the target.)
	 */
	if (!IS_ERR(debugfs_dir)) {
		char buf[100];

		snprintf(buf, 100, "../../%pd2", debugfs_dir->d_parent);
		debugfs_create_symlink("iwlwifi", mld->wiphy->debugfsdir,
				       buf);
	}
}

#define VIF_DEBUGFS_WRITE_FILE_OPS(name, bufsz)			\
	WIPHY_DEBUGFS_WRITE_FILE_OPS(vif_##name, bufsz, vif)

#define VIF_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, vif,			\
			    &iwl_dbgfs_vif_##name##_ops);		\
	} while (0)
#define VIF_DEBUGFS_ADD_FILE(name, parent, mode)			\
	VIF_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

static ssize_t iwl_dbgfs_vif_bf_params_write(struct iwl_mld *mld, char *buf,
					     size_t count, void *data)
{
	struct ieee80211_vif *vif = data;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int link_id = vif->active_links ? __ffs(vif->active_links) : 0;
	struct ieee80211_bss_conf *link_conf;
	int val;

	if (!strncmp("bf_enable_beacon_filter=", buf, 24)) {
		if (sscanf(buf + 24, "%d", &val) != 1)
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	if (val != 0 && val != 1)
		return -EINVAL;

	link_conf = link_conf_dereference_protected(vif, link_id);
	if (WARN_ON(!link_conf))
		return -ENODEV;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	mld_vif->disable_bf = !val;

	if (val)
		return iwl_mld_enable_beacon_filter(mld, link_conf,
						    false) ?: count;
	else
		return iwl_mld_disable_beacon_filter(mld, vif) ?: count;
}

static ssize_t iwl_dbgfs_vif_pm_params_write(struct iwl_mld *mld,
					  char *buf,
					  size_t count, void *data)
{
	struct ieee80211_vif *vif = data;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int val;

	if (!strncmp("use_ps_poll=", buf, 12)) {
		if (sscanf(buf + 12, "%d", &val) != 1)
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	mld_vif->use_ps_poll = val;

	return iwl_mld_update_mac_power(mld, vif, false) ?: count;
}

VIF_DEBUGFS_WRITE_FILE_OPS(pm_params, 32);
VIF_DEBUGFS_WRITE_FILE_OPS(bf_params, 32);

static int
_iwl_dbgfs_inject_beacon_ie(struct iwl_mld *mld, struct ieee80211_vif *vif,
			    char *bin, ssize_t len,
			    bool restore)
{
	struct iwl_mld_vif *mld_vif;
	struct iwl_mld_link *mld_link;
	struct iwl_mac_beacon_cmd beacon_cmd = {};
	int n_bytes = len / 2;

	/* Element len should be represented by u8 */
	if (n_bytes >= U8_MAX)
		return -EINVAL;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	if (!vif)
		return -EINVAL;

	mld_vif = iwl_mld_vif_from_mac80211(vif);
	mld_vif->beacon_inject_active = true;
	mld->hw->extra_beacon_tailroom = n_bytes;

	for_each_mld_vif_valid_link(mld_vif, mld_link) {
		u32 offset;
		struct ieee80211_tx_info *info;
		struct ieee80211_bss_conf *link_conf =
			link_conf_dereference_protected(vif, link_id);
		struct ieee80211_chanctx_conf *ctx =
			wiphy_dereference(mld->wiphy, link_conf->chanctx_conf);
		struct sk_buff *beacon =
			ieee80211_beacon_get_template(mld->hw, vif,
						      NULL, link_id);

		if (!beacon)
			return -EINVAL;

		if (!restore && (WARN_ON(!n_bytes || !bin) ||
				 hex2bin(skb_put_zero(beacon, n_bytes),
					 bin, n_bytes))) {
			dev_kfree_skb(beacon);
			return -EINVAL;
		}

		info = IEEE80211_SKB_CB(beacon);

		beacon_cmd.flags =
			cpu_to_le16(iwl_mld_get_rate_flags(mld, info, vif,
							   link_conf,
							   ctx->def.chan->band));
		beacon_cmd.byte_cnt = cpu_to_le16((u16)beacon->len);
		beacon_cmd.link_id =
			cpu_to_le32(mld_link->fw_id);

		iwl_mld_set_tim_idx(mld, &beacon_cmd.tim_idx,
				    beacon->data, beacon->len);

		offset = iwl_find_ie_offset(beacon->data,
					    WLAN_EID_S1G_TWT,
					    beacon->len);

		beacon_cmd.btwt_offset = cpu_to_le32(offset);

		iwl_mld_send_beacon_template_cmd(mld, beacon, &beacon_cmd);
		dev_kfree_skb(beacon);
	}

	if (restore)
		mld_vif->beacon_inject_active = false;

	return 0;
}

static ssize_t
iwl_dbgfs_vif_inject_beacon_ie_write(struct iwl_mld *mld,
				     char *buf, size_t count,
				     void *data)
{
	struct ieee80211_vif *vif = data;
	int ret = _iwl_dbgfs_inject_beacon_ie(mld, vif, buf,
					      count, false);

	mld->hw->extra_beacon_tailroom = 0;
	return ret ?: count;
}

VIF_DEBUGFS_WRITE_FILE_OPS(inject_beacon_ie, 512);

static ssize_t
iwl_dbgfs_vif_inject_beacon_ie_restore_write(struct iwl_mld *mld,
					     char *buf,
					     size_t count,
					     void *data)
{
	struct ieee80211_vif *vif = data;
	int ret = _iwl_dbgfs_inject_beacon_ie(mld, vif, NULL,
					      0, true);

	mld->hw->extra_beacon_tailroom = 0;
	return ret ?: count;
}

VIF_DEBUGFS_WRITE_FILE_OPS(inject_beacon_ie_restore, 512);

void iwl_mld_add_vif_debugfs(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif)
{
	struct dentry *mld_vif_dbgfs =
		debugfs_create_dir("iwlmld", vif->debugfs_dir);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	char target[3 * 3 + 11 + (NL80211_WIPHY_NAME_MAXLEN + 1) +
		    (7 + IFNAMSIZ + 1) + 6 + 1];
	char name[7 + IFNAMSIZ + 1];

	/* Create symlink for convenience pointing to interface specific
	 * debugfs entries for the driver. For example, under
	 * /sys/kernel/debug/iwlwifi/0000\:02\:00.0/iwlmld/
	 * find
	 * netdev:wlan0 -> ../../../ieee80211/phy0/netdev:wlan0/iwlmld/
	 */
	snprintf(name, sizeof(name), "%pd", vif->debugfs_dir);
	snprintf(target, sizeof(target), "../../../%pd3/iwlmld",
		 vif->debugfs_dir);
	debugfs_create_symlink(name, mld->debugfs_dir, target);

#ifdef HACK_IWLWIFI_DEBUGFS_IWLMVM_SYMLINK
	debugfs_create_symlink("iwlmvm", vif->debugfs_dir, "iwlmld");
#endif

	if (iwlmld_mod_params.power_scheme != IWL_POWER_SCHEME_CAM &&
	    vif->type == NL80211_IFTYPE_STATION) {
		VIF_DEBUGFS_ADD_FILE(pm_params, mld_vif_dbgfs, 0200);
		VIF_DEBUGFS_ADD_FILE(bf_params, mld_vif_dbgfs, 0200);
	}

	if (vif->type == NL80211_IFTYPE_AP) {
		VIF_DEBUGFS_ADD_FILE(inject_beacon_ie, mld_vif_dbgfs, 0200);
		VIF_DEBUGFS_ADD_FILE(inject_beacon_ie_restore,
				     mld_vif_dbgfs, 0200);
	}

}

#define LINK_DEBUGFS_WRITE_FILE_OPS(name, bufsz)			\
	WIPHY_DEBUGFS_WRITE_FILE_OPS(link_##name, bufsz, bss_conf)

#define LINK_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, link_conf,		\
			    &iwl_dbgfs_link_##name##_ops);		\
	} while (0)
#define LINK_DEBUGFS_ADD_FILE(name, parent, mode)			\
	LINK_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

void iwl_mld_add_link_debugfs(struct ieee80211_hw *hw,
			      struct ieee80211_vif *vif,
			      struct ieee80211_bss_conf *link_conf,
			      struct dentry *dir)
{
	struct dentry *mld_link_dir;

	mld_link_dir = debugfs_lookup("iwlmld", dir);

	/* For non-MLO vifs, the dir of deflink is the same as the vif's one.
	 * so if iwlmld dir already exists, this means that this is deflink.
	 * If not, this is a per-link dir of a MLO vif, add in it the iwlmld
	 * dir.
	 */
	if (!mld_link_dir)
		mld_link_dir = debugfs_create_dir("iwlmld", dir);

#ifdef HACK_IWLWIFI_DEBUGFS_IWLMVM_SYMLINK
	{
		struct dentry *mvm_link_dir = debugfs_lookup("iwlmvm", dir);

		if (!mvm_link_dir)
			debugfs_create_symlink("iwlmvm", dir, "iwlmld");
	}
#endif

}

static ssize_t iwl_dbgfs_fixed_rate_write(struct iwl_mld *mld, char *buf,
					  size_t count, void *data)
{
	struct ieee80211_link_sta *link_sta = data;
	struct iwl_mld_link_sta *mld_link_sta;
	u32 rate;
	u32 partial = false;
	char pretty_rate[100];
	int ret;
	u8 fw_sta_id;

	mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
	if (WARN_ON(!mld_link_sta))
		return -EINVAL;

	fw_sta_id = mld_link_sta->fw_id;

	if (sscanf(buf, "%i %i", &rate, &partial) == 0)
		return -EINVAL;

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	ret = iwl_mld_send_tlc_dhc(mld, fw_sta_id,
				   partial ? IWL_TLC_DEBUG_PARTIAL_FIXED_RATE :
					     IWL_TLC_DEBUG_FIXED_RATE,
				   rate);

	rs_pretty_print_rate(pretty_rate, sizeof(pretty_rate), rate);

	IWL_DEBUG_RATE(mld, "sta_id %d rate %s partial: %d, ret:%d\n",
		       fw_sta_id, pretty_rate, partial, ret);

	return ret ? : count;
}

static ssize_t iwl_dbgfs_tlc_dhc_write(struct iwl_mld *mld, char *buf,
				       size_t count, void *data)
{
	struct ieee80211_link_sta *link_sta = data;
	struct iwl_mld_link_sta *mld_link_sta;
	u32 type, value;
	int ret;
	u8 fw_sta_id;

	mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
	if (WARN_ON(!mld_link_sta))
		return -EINVAL;

	fw_sta_id = mld_link_sta->fw_id;

	if (sscanf(buf, "%i %i", &type, &value) != 2) {
		IWL_DEBUG_RATE(mld, "usage <type> <value>\n");
		return -EINVAL;
	}

	if (iwl_mld_dbgfs_fw_cmd_disabled(mld))
		return -EIO;

	ret = iwl_mld_send_tlc_dhc(mld, fw_sta_id, type, value);

	return ret ? : count;
}

#define LINK_STA_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, link_sta,		\
			    &iwl_dbgfs_##name##_ops);			\
	} while (0)
#define LINK_STA_DEBUGFS_ADD_FILE(name, parent, mode)			\
	LINK_STA_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

#define LINK_STA_WIPHY_DEBUGFS_WRITE_OPS(name, bufsz)			\
	WIPHY_DEBUGFS_WRITE_FILE_OPS(name, bufsz, link_sta)

LINK_STA_WIPHY_DEBUGFS_WRITE_OPS(tlc_dhc, 64);
LINK_STA_WIPHY_DEBUGFS_WRITE_OPS(fixed_rate, 64);

void iwl_mld_add_link_sta_debugfs(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_link_sta *link_sta,
				  struct dentry *dir)
{
	LINK_STA_DEBUGFS_ADD_FILE(fixed_rate, dir, 0200);
	LINK_STA_DEBUGFS_ADD_FILE(tlc_dhc, dir, 0200);
}
