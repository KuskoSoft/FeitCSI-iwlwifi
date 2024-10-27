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

#include "fw/api/rs.h"

#define MLD_DEBUGFS_READ_FILE_OPS(name, bufsz)				\
	_MLD_DEBUGFS_READ_FILE_OPS(name, bufsz, struct iwl_mld)

#define MLD_DEBUGFS_WRITE_FILE_OPS(name, bufsz)				\
	_MLD_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct iwl_mld)

#define MLD_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz)			\
	_MLD_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz, struct iwl_mld)

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

	wiphy_lock(mld->wiphy);

	if (count == 6 && !strcmp(buf, "nolog\n")) {
		mld->fw_status.do_not_dump_once = true;
		set_bit(STATUS_SUPPRESS_CMD_ERROR_ONCE, &mld->trans->status);
	}

	/* take the return value to make compiler happy - it will
	 * fail anyway
	 */
	ret = iwl_mld_send_cmd_empty(mld, WIDE_ID(LONG_GROUP, REPLY_ERROR));

	wiphy_unlock(mld->wiphy);

	return count;
}

MLD_DEBUGFS_WRITE_FILE_OPS(fw_nmi, 10);
MLD_DEBUGFS_WRITE_FILE_OPS(fw_restart, 10);

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

void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir)
{
	/* Add debugfs files here */

	MLD_DEBUGFS_ADD_FILE(fw_nmi, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(fw_restart, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(wifi_6e_enable, debugfs_dir, 0400);

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

void iwl_mld_add_vif_debugfs(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif)
{
	__maybe_unused struct dentry *mld_vif_dbgfs =
		debugfs_create_dir("iwlmld", vif->debugfs_dir);

	/* ADD per-interface files here */
}

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

	/* Add here per-links files to mld_link_dir */
}

static ssize_t iwl_dbgfs_fixed_rate_write(struct ieee80211_link_sta *link_sta,
					  char *buf, size_t count)
{
	struct iwl_mld *mld = iwl_mld_sta_from_mac80211(link_sta->sta)->mld;
	struct iwl_mld_link_sta *mld_link_sta;
	u32 rate;
	u32 partial = false;
	char pretty_rate[100];
	int ret;
	u8 fw_sta_id;

	rcu_read_lock();

	mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
	if (WARN_ON(!mld_link_sta)) {
		rcu_read_unlock();
		return -EINVAL;
	}

	fw_sta_id = mld_link_sta->fw_id;

	rcu_read_unlock();

	if (sscanf(buf, "%i %i", &rate, &partial) == 0)
		return -EINVAL;

	ret = iwl_mld_send_tlc_dhc(mld, fw_sta_id,
				   partial ? IWL_TLC_DEBUG_PARTIAL_FIXED_RATE :
					     IWL_TLC_DEBUG_FIXED_RATE,
				   rate);

	rs_pretty_print_rate(pretty_rate, sizeof(pretty_rate), rate);

	IWL_DEBUG_RATE(mld, "sta_id %d rate %s partial: %d, ret:%d\n",
		       fw_sta_id, pretty_rate, partial, ret);

	return ret ? : count;
}

static ssize_t iwl_dbgfs_tlc_dhc_write(struct ieee80211_link_sta *link_sta,
				       char *buf, size_t count)
{
	struct iwl_mld *mld = iwl_mld_sta_from_mac80211(link_sta->sta)->mld;
	struct iwl_mld_link_sta *mld_link_sta;
	u32 type, value;
	int ret;
	u8 fw_sta_id;

	rcu_read_lock();

	mld_link_sta = iwl_mld_link_sta_from_mac80211(link_sta);
	if (WARN_ON(!mld_link_sta)) {
		rcu_read_unlock();
		return -EINVAL;
	}

	fw_sta_id = mld_link_sta->fw_id;

	rcu_read_unlock();

	if (sscanf(buf, "%i %i", &type, &value) != 2) {
		IWL_DEBUG_RATE(mld, "usage <type> <value>\n");
		return -EINVAL;
	}

	ret = iwl_mld_send_tlc_dhc(mld, fw_sta_id, type, value);

	return ret ? : count;
}

#define LINK_STA_DEBUGFS_WRITE_FILE_OPS(name, bufsz)			\
	_MLD_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct ieee80211_link_sta)

#define LINK_STA_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, link_sta,		\
			    &iwl_dbgfs_##name##_ops);			\
	} while (0)
#define LINK_STA_DEBUGFS_ADD_FILE(name, parent, mode)			\
	LINK_STA_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

LINK_STA_DEBUGFS_WRITE_FILE_OPS(fixed_rate, 64);
LINK_STA_DEBUGFS_WRITE_FILE_OPS(tlc_dhc, 64);

void iwl_mld_add_link_sta_debugfs(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_link_sta *link_sta,
				  struct dentry *dir)
{
	LINK_STA_DEBUGFS_ADD_FILE(fixed_rate, dir, 0200);
	LINK_STA_DEBUGFS_ADD_FILE(tlc_dhc, dir, 0200);
}
