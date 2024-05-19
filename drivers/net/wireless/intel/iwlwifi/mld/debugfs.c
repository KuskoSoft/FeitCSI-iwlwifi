/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "debugfs.h"

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

void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir)
{
	/* Add debugfs files here */

	/*
	 * TODO: Once registered to mac80211, add a symlink in mac80211
	 * debugfs
	 */
}
