/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "debugfs.h"
#include "iwl-io.h"
#include "hcmd.h"
#include "iface.h"

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

static ssize_t iwl_dbgfs_fw_nmi_write(struct iwl_mld *mld, char *buf,
				      size_t count)
{
	if (!mld->fw_status.running)
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

	if (!mld->fw_status.running)
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

void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir)
{
	/* Add debugfs files here */

	MLD_DEBUGFS_ADD_FILE(fw_nmi, debugfs_dir, 0200);
	MLD_DEBUGFS_ADD_FILE(fw_restart, debugfs_dir, 0200);

	/*
	 * TODO: Once registered to mac80211, add a symlink in mac80211
	 * debugfs
	 */
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
