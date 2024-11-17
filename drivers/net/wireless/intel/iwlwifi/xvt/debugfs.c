// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2017 Intel Deutschland GmbH
 * Copyright (C) 2018-2024 Intel Corporation
 */
#include "xvt.h"
#include "fw/dbg.h"
#include "fw/acpi.h"

#define XVT_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)		\
static ssize_t _iwl_dbgfs_##name##_write(struct file *file,		\
					 const char __user *user_buf,	\
					 size_t count, loff_t *ppos)	\
{									\
	argtype *arg = file->private_data;				\
	char buf[buflen] = {};						\
	size_t buf_size = min(count, sizeof(buf) -  1);			\
									\
	if (copy_from_user(buf, user_buf, buf_size))			\
		return -EFAULT;						\
									\
	return iwl_dbgfs_##name##_write(arg, buf, buf_size, ppos);	\
}

#define _XVT_DEBUGFS_WRITE_FILE_OPS(name, buflen, argtype)		\
XVT_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)			\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write = _iwl_dbgfs_##name##_write,				\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

#define XVT_DEBUGFS_WRITE_FILE_OPS(name, bufsz) \
	_XVT_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct iwl_xvt)

#define XVT_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	if (!debugfs_create_file(alias, mode, parent, xvt,	\
				 &iwl_dbgfs_##name##_ops))	\
		goto err;					\
	} while (0)

#define XVT_DEBUGFS_ADD_FILE(name, parent, mode) \
	XVT_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

static ssize_t iwl_dbgfs_fw_restart_write(struct iwl_xvt *xvt, char *buf,
					  size_t count, loff_t *ppos)
{
	int __maybe_unused ret;

	if (!xvt->fw_running)
		return -EIO;

	mutex_lock(&xvt->mutex);

	/* Take the return value, though failure is expected, for compilation */
	ret = iwl_xvt_send_cmd_pdu(xvt,
				   WIDE_ID(LONG_GROUP, REPLY_ERROR),
				   0, 0, NULL);

	mutex_unlock(&xvt->mutex);

	return count;
}

static ssize_t iwl_dbgfs_fw_nmi_write(struct iwl_xvt *xvt, char *buf,
				      size_t count, loff_t *ppos)
{
	iwl_force_nmi(xvt->trans);

	return count;
}

static ssize_t iwl_dbgfs_set_profile_write(struct iwl_xvt *xvt, char *buf,
					   size_t count, loff_t *ppos)
{
	int chain_a, chain_b;

	if (sscanf(buf, "%d %d", &chain_a, &chain_b) != 2)
		return -EINVAL;

	if (!(chain_a > 0 && chain_a < BIOS_SAR_MAX_PROFILE_NUM) ||
	    !(chain_b > 0 && chain_b < BIOS_SAR_MAX_PROFILE_NUM))
		return -EINVAL;

	mutex_lock(&xvt->mutex);
	iwl_xvt_sar_select_profile(xvt, chain_a, chain_b);
	mutex_unlock(&xvt->mutex);

	return count;
}

/* Device wide debugfs entries */
XVT_DEBUGFS_WRITE_FILE_OPS(fw_restart, 10);
XVT_DEBUGFS_WRITE_FILE_OPS(fw_nmi, 10);
XVT_DEBUGFS_WRITE_FILE_OPS(set_profile, 10);

#ifdef CPTCFG_IWLWIFI_DEBUGFS
int iwl_xvt_dbgfs_register(struct iwl_xvt *xvt, struct dentry *dbgfs_dir)
{
	xvt->debugfs_dir = dbgfs_dir;

	XVT_DEBUGFS_ADD_FILE(fw_restart, xvt->debugfs_dir, S_IWUSR);
	XVT_DEBUGFS_ADD_FILE(fw_nmi, xvt->debugfs_dir, S_IWUSR);
	XVT_DEBUGFS_ADD_FILE(set_profile, xvt->debugfs_dir, S_IWUSR);

	return 0;
err:
	IWL_ERR(xvt, "Can't create the xvt debugfs directory\n");
	return -ENOMEM;
}
#endif /* CPTCFG_IWLWIFI_DEBUGFS */
