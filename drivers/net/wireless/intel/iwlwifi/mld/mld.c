// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"

#define DRV_DESCRIPTION "Intel(R) MLD wireless driver for Linux"
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(IWLWIFI);

static const struct iwl_op_mode_ops iwl_mld_ops;

static int __init iwl_mld_init(void)
{
	int ret = iwl_opmode_register("iwlmld", &iwl_mld_ops);

	if (ret)
		pr_err("Unable to register MLD op_mode: %d\n", ret);

	return ret;
}
module_init(iwl_mld_init);

static void __exit iwl_mld_exit(void)
{
	iwl_opmode_deregister("iwlmld");
}
module_exit(iwl_mld_exit);

static bool
iwl_is_mld_op_mode_supported(struct iwl_trans *trans)
{
	/* TODO: Verify also by FW version */
	return trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_BZ;
}

static struct iwl_op_mode *
iwl_mld_allocate_op_mode(void)
{
	struct iwl_op_mode *op_mode;
	size_t alloc_size =
		sizeof(struct iwl_op_mode) + sizeof(struct iwl_mld);

	/*
	 * TODO: when the mac80211 ops is added, use ieee80211_alloc_hw instead
	 */
	op_mode = kzalloc(alloc_size, GFP_KERNEL);
	if (!op_mode)
		return NULL;

	op_mode->ops = &iwl_mld_ops;

	return op_mode;
}

static void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir)
{
	/*TODO: add debugfs files */
}

static void
iwl_construct_mld(struct iwl_mld *mld, struct iwl_trans *trans,
		  const struct iwl_cfg *cfg, const struct iwl_fw *fw,
		  struct dentry *debugfs_dir)
{
	mld->dev = trans->dev;
	mld->trans = trans;
	mld->cfg = cfg;
	mld->fw = fw;

	iwl_mld_add_debugfs_files(mld, debugfs_dir);
}

static void
iwl_mld_construct_fw_runtime(struct iwl_mld *mld, struct iwl_trans *trans,
			     const struct iwl_fw *fw,
			     struct dentry *debugfs_dir)
{
	iwl_fw_runtime_init(&mld->fwrt, trans, fw, NULL, mld,
			    NULL, NULL, debugfs_dir);

	iwl_fw_set_current_image(&mld->fwrt, IWL_UCODE_REGULAR);
}

static void
iwl_mld_configure_trans(struct iwl_op_mode *op_mode)
{
	struct iwl_trans_config trans_cfg = {
		.op_mode = op_mode,
		/* Rx is not supported yet, but add it to avoid warnings */
		.rx_buf_size = iwl_amsdu_size_to_rxb_size(),
	};
	struct iwl_mld *mld = IWL_OP_MODE_GET_MLD(op_mode);

	/*TODO: add more configurations here */

	iwl_trans_configure(mld->trans, &trans_cfg);
}

/*
 *****************************************************
 * op mode ops functions
 *****************************************************
 */
static struct iwl_op_mode *
iwl_op_mode_mld_start(struct iwl_trans *trans, const struct iwl_cfg *cfg,
		      const struct iwl_fw *fw, struct dentry *dbgfs_dir)
{
	struct iwl_op_mode *op_mode;
	struct iwl_mld *mld;

	if (WARN_ON(!iwl_is_mld_op_mode_supported(trans)))
		return NULL;

	op_mode = iwl_mld_allocate_op_mode();
	if (!op_mode)
		return NULL;

	mld = IWL_OP_MODE_GET_MLD(op_mode);

	iwl_construct_mld(mld, trans, cfg, fw, dbgfs_dir);

	iwl_mld_construct_fw_runtime(mld, trans, fw, dbgfs_dir);

	/* Configure transport layer with the opmode specific params */
	iwl_mld_configure_trans(op_mode);

	return op_mode;
}

static void
iwl_op_mode_mld_stop(struct iwl_op_mode *op_mode)
{
	struct iwl_mld *mld = IWL_OP_MODE_GET_MLD(op_mode);

	iwl_fw_runtime_free(&mld->fwrt);

	iwl_trans_op_mode_leave(mld->trans);

	kfree(op_mode);
}

static void
iwl_mld_rx(struct iwl_op_mode *op_mode, struct napi_struct *napi,
	   struct iwl_rx_cmd_buffer *rxb)
{
	/* TODO: add RX path :-) */
	WARN_ONCE(1, "RX is not supported yet\n");
}

static void
iwl_mld_rx_rss(struct iwl_op_mode *op_mode, struct napi_struct *napi,
	       struct iwl_rx_cmd_buffer *rxb, unsigned int queue)
{
	/* TODO: add RX path :-) */
	WARN_ONCE(1, "RX is not supported yet\n");
}

static void
iwl_mld_queue_full(struct iwl_op_mode *op_mode, int hw_queue)
{
	/* TODO */
	WARN_ONCE(1, "Not supported yet\n");
}

static void
iwl_mld_queue_not_full(struct iwl_op_mode *op_mode, int hw_queue)
{
	/* TODO */
	WARN_ONCE(1, "Not supported yet\n");
}

static bool
iwl_mld_set_hw_rfkill_state(struct iwl_op_mode *op_mode, bool state)
{
	/* TODO */
	WARN_ONCE(1, "Not supported yet\n");
	return false;
}

static void
iwl_mld_free_skb(struct iwl_op_mode *op_mode, struct sk_buff *skb)
{
	/* TODO */
	WARN_ONCE(1, "Not supported yet\n");
}

static void
iwl_mld_nic_error(struct iwl_op_mode *op_mode, bool sync)
{
	/* TODO */
	WARN_ONCE(1, "Not supported yet\n");
}

static void
iwl_mld_time_point(struct iwl_op_mode *op_mode,
		   enum iwl_fw_ini_time_point tp_id,
		   union iwl_dbg_tlv_tp_data *tp_data)
{
	/* TODO: debug support */
	WARN_ONCE(1, "Not supported yet\n");
}

static const struct iwl_op_mode_ops iwl_mld_ops = {
	.start = iwl_op_mode_mld_start,
	.stop = iwl_op_mode_mld_stop,
	.rx = iwl_mld_rx,
	.rx_rss = iwl_mld_rx_rss,
	.queue_full = iwl_mld_queue_full,
	.queue_not_full = iwl_mld_queue_not_full,
	.hw_rf_kill = iwl_mld_set_hw_rfkill_state,
	.free_skb = iwl_mld_free_skb,
	.nic_error = iwl_mld_nic_error,
	.time_point = iwl_mld_time_point,
};
