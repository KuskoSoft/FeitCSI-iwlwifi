/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_h__
#define __iwl_mld_h__

#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/runtime.h"

/**
 * struct iwl_mld - MLD op mode
 *
 * @dev: pointer to device struct. For printing purposes
 * @trans: pointer to the transport layer
 * @cfg: pointer to the device configuration
 * @fw: a pointer to the fw object
 * @fwrt: fw runtime data
 * @debugfs_dir: debugfs directory
 */
struct iwl_mld {
	struct device *dev;
	struct iwl_trans *trans;
	const struct iwl_cfg *cfg;
	const struct iwl_fw *fw;
	struct iwl_fw_runtime fwrt;
	struct dentry *debugfs_dir;
};

/* Extract MLD priv from op_mode */
#define IWL_OP_MODE_GET_MLD(_iwl_op_mode)		\
	((struct iwl_mld *)(_iwl_op_mode)->op_mode_specific)

#endif /* __iwl_mld_h__ */
