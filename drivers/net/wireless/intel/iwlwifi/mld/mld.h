/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_h__
#define __iwl_mld_h__

#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/runtime.h"
#include "fw/notif-wait.h"

#define IWL_MLD_MAX_ADDRESSES		5

/**
 * struct iwl_mld - MLD op mode
 *
 * @dev: pointer to device struct. For printing purposes
 * @trans: pointer to the transport layer
 * @cfg: pointer to the device configuration
 * @fw: a pointer to the fw object
 * @hw: pointer to the hw object.
 * @wiphy: a pointer to the wiphy struct, for easier access to it.
 * @nvm_data: pointer to the nvm_data that includes all our capabilities
 * @fwrt: fw runtime data
 * @debugfs_dir: debugfs directory
 * @notif_wait: notification wait related data.
 * @async_handlers_list: a list of all async RX handlers. When a notifciation
 *	with an async handler is received, it is added to this list.
 *	When &async_handlers_wk runs - it runs these handlers one by one.
 * @async_handlers_lock: a lock for &async_handlers_list. Sync
 *	&async_handlers_wk and RX notifcation path.
 * @async_handlers_wk: A work to run all async RX handlers from
 *	&async_handlers_list.
 * @fw_status: bitmap of fw status bits
 * @addresses: device MAC addresses.
 * @wowlan: WoWLAN support data.
 */
struct iwl_mld {
	struct device *dev;
	struct iwl_trans *trans;
	const struct iwl_cfg *cfg;
	const struct iwl_fw *fw;
	struct ieee80211_hw *hw;
	struct wiphy *wiphy;
	struct iwl_nvm_data *nvm_data;
	struct iwl_fw_runtime fwrt;
	struct dentry *debugfs_dir;
	struct iwl_notif_wait_data notif_wait;
	struct list_head async_handlers_list;
	spinlock_t async_handlers_lock;
	struct wiphy_work async_handlers_wk;

	struct {
		u32 running:1,
		    do_not_dump_once:1;
	} fw_status;
	struct mac_address addresses[IWL_MLD_MAX_ADDRESSES];
#ifdef CONFIG_PM
	struct wiphy_wowlan_support wowlan;
#endif /* CONFIG_PM */
};

/* Extract MLD priv from op_mode */
#define IWL_OP_MODE_GET_MLD(_iwl_op_mode)		\
	((struct iwl_mld *)(_iwl_op_mode)->op_mode_specific)

void
iwl_mld_add_debugfs_files(struct iwl_mld *mld, struct dentry *debugfs_dir);
int iwl_mld_run_fw_init_sequence(struct iwl_mld *mld);

static inline u8 iwl_mld_get_valid_tx_ant(const struct iwl_mld *mld)
{
	u8 tx_ant = mld->fw->valid_tx_ant;

	if (mld->nvm_data && mld->nvm_data->valid_tx_ant)
		tx_ant &= mld->nvm_data->valid_tx_ant;

	return tx_ant;
}

static inline u8 iwl_mld_get_valid_rx_ant(const struct iwl_mld *mld)
{
	u8 rx_ant = mld->fw->valid_rx_ant;

	if (mld->nvm_data && mld->nvm_data->valid_rx_ant)
		rx_ant &= mld->nvm_data->valid_rx_ant;

	return rx_ant;
}

extern const struct ieee80211_ops iwl_mld_hw_ops;

#if IS_ENABLED(CPTCFG_IWLWIFI_KUNIT_TESTS)
extern const struct iwl_hcmd_arr iwl_mld_groups[];
extern const unsigned int global_iwl_mld_goups_size;
#endif

#endif /* __iwl_mld_h__ */
