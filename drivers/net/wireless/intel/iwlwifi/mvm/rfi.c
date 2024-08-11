// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2020 - 2024 Intel Corporation
 */

#include "mvm.h"
#include "fw/api/commands.h"
#include "fw/api/phy-ctxt.h"

/* DDR needs frequency in units of 16.666MHz, so provide FW with the
 * frequency values in the adjusted format.
 */
static const
struct iwl_rfi_ddr_lut_entry iwl_rfi_ddr_table[IWL_RFI_DDR_LUT_SIZE] = {
	/* frequency 2600MHz */
	{cpu_to_le16(156), {34, 36, 38, 40, 42, 50},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
	       PHY_BAND_5,}},

	/* frequency 2667MHz */
	{cpu_to_le16(160), {50, 58, 60, 62, 64, 68},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
	       PHY_BAND_5,}},

	/* frequency 2800MHz */
	{cpu_to_le16(168), {114, 116, 118, 120, 122},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,}},

	/* frequency 2933MHz */
	{cpu_to_le16(176), {163, 167, 169, 171, 173, 175},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
	       PHY_BAND_5,}},

	/* frequency 3000MHz */
	{cpu_to_le16(180), {3, 5, 7, 9, 11, 15, 31},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 3067MHz */
	{cpu_to_le16(184), {15, 23, 27, 29, 31, 33, 35, 37, 39, 47, 63},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6,}},

	/* frequency 3200MHz */
	{cpu_to_le16(192), {63, 79, 83, 85, 87, 89, 91, 95},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 3300MHz */
	{cpu_to_le16(198), {95, 111, 119, 123, 125, 129, 127, 131, 135, 143,
				159},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6,}},

	/* frequency 3400MHz */
	{cpu_to_le16(204), {159, 163, 165, 167, 169, 171, 175, 191},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 3733MHz */
	{cpu_to_le16(224), {114, 116, 118, 120, 122},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,}},

	/* frequency 4000MHz */
	{cpu_to_le16(240), {3, 5, 7, 9, 11, 15, 31},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 4200MHz */
	{cpu_to_le16(252), {63, 65, 67, 69, 71, 79, 95},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 4267MHz */
	{cpu_to_le16(256), {63, 79, 83, 85, 87, 89, 91, 95},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 4400MHz */
	{cpu_to_le16(264), {95, 111, 119, 123, 125, 127, 129, 131, 135, 143,
				159},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6,}},

	/* frequency 4600MHz */
	{cpu_to_le16(276), {159, 175, 183, 185, 187, 189, 191},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 4800MHz */
	{cpu_to_le16(288), {1, 3, 5, 7, 9, 11, 13, 15},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 5200MHz */
	{cpu_to_le16(312), {34, 36, 38, 40, 42, 50},
	       {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
		PHY_BAND_5,}},

	/* frequency 5333MHz */
	{cpu_to_le16(320), {50, 58, 60, 62, 64, 68},
	       {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
		PHY_BAND_5,}},

	/* frequency 5600MHz */
	{cpu_to_le16(336), {114, 116, 118, 120, 122},
	       {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,}},

	/* frequency 5868MHz */
	{cpu_to_le16(352), {163, 167, 169, 171, 173, 175},
	       {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
		PHY_BAND_5,}},

	/* frequency 6000MHz */
	{cpu_to_le16(360), {3, 5, 7, 9, 11, 15, 31},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 6133MHz */
	{cpu_to_le16(368), {15, 23, 27, 29, 31, 33, 35, 37, 39, 47, 63},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6,}},

	/* frequency 6400MHz */
	{cpu_to_le16(384), {63, 79, 83, 85, 87, 89, 91, 95,},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 6600MHz */
	{cpu_to_le16(396), {95, 111, 119, 123, 125, 127, 129, 131, 135, 143,
				159},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6,}},

	/* frequency 6800MHz */
	{cpu_to_le16(408), {159, 163, 165, 167, 169, 171, 175, 191},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

	/* frequency 6933MHz */
	{cpu_to_le16(416), {159, 175, 183, 187, 189, 191, 193, 195, 197, 199,
				207},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6,}},
};

static inline bool iwl_rfi_enabled_by_mac_type(struct iwl_mvm *mvm,
					       bool so_rfi_mode)
{
	u32 mac_type = CSR_HW_REV_TYPE(mvm->trans->hw_rev);
	bool enable_rfi = false;

	if ((mac_type != IWL_CFG_ANY && mac_type >= IWL_CFG_MAC_TYPE_MA) ||
	    (mac_type == IWL_CFG_MAC_TYPE_SO && so_rfi_mode))
		enable_rfi = true;

	return enable_rfi;
}

bool iwl_rfi_supported(struct iwl_mvm *mvm, bool so_rfi_mode, bool is_ddr)
{
	bool rfi_enable_mac_type = iwl_rfi_enabled_by_mac_type(mvm,
							       so_rfi_mode);
	bool ddr_capa = fw_has_capa(&mvm->fw->ucode_capa,
				    IWL_UCODE_TLV_CAPA_RFI_DDR_SUPPORT);
	bool dlvr_capa = fw_has_capa(&mvm->fw->ucode_capa,
				     IWL_UCODE_TLV_CAPA_RFI_DLVR_SUPPORT);

	IWL_DEBUG_FW(mvm, "FW has RFI DDR capability:%s DLVR capability:%s\n",
		     ddr_capa ? "yes" : "no", dlvr_capa ? "yes" : "no");

	IWL_DEBUG_FW(mvm,
		     "HW is integrated:%s rfi_enabled:%s fw_rfi_state:%d\n",
		     mvm->trans->trans_cfg->integrated ? "yes" : "no",
		     rfi_enable_mac_type ? "yes" : "no", mvm->fw_rfi_state);

	return (is_ddr ? ddr_capa : dlvr_capa) && mvm->bios_enable_rfi &&
		rfi_enable_mac_type && mvm->trans->trans_cfg->integrated &&
		iwl_mvm_fw_rfi_state_supported(mvm);
}

static bool
iwl_mvm_ddr_changed(struct iwl_mvm *mvm,
		    struct iwl_rfi_config_info *rfi_config_info)
{
	if (memcmp(rfi_config_info->ddr_table,
		   mvm->iwl_prev_rfi_config_cmd->ddr_table,
		   sizeof(rfi_config_info->ddr_table)))
		return true;

	if (iwl_mvm_rfi_desense_supported(mvm)) {
		if (memcmp(rfi_config_info->desense_table,
			   mvm->iwl_prev_rfi_config_cmd->desense_table,
			   sizeof(rfi_config_info->desense_table)))
			return true;

		if (rfi_config_info->snr_threshold !=
		    mvm->iwl_prev_rfi_config_cmd->snr_threshold)
			return true;
	}

	return false;
}

int iwl_rfi_send_config_cmd(struct iwl_mvm *mvm,
			    struct iwl_rfi_config_info *rfi_config_info,
			    bool is_set_master_cmd, bool force_send_table)
{
	struct iwl_rfi_config_cmd *cmd = NULL;
	bool rfi_ddr_support;
	bool rfi_dlvr_support;
	bool old_force_rfi = mvm->force_enable_rfi;
	bool so_rfi_mode;
	int ret = 0;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(SYSTEM_GROUP, RFI_CONFIG_CMD),
		.dataflags[0] = IWL_HCMD_DFL_DUP,
	};
	u8 cmd_ver = iwl_fw_lookup_cmd_ver(mvm->fw,
					   WIDE_ID(SYSTEM_GROUP,
						   RFI_CONFIG_CMD), 0);

	if (cmd_ver == 3)
		hcmd.len[0] = sizeof(struct iwl_rfi_config_cmd_v3);
	else if (cmd_ver == 4)
		hcmd.len[0] = sizeof(struct iwl_rfi_config_cmd);
	else
		return -EOPNOTSUPP;

	/* for SO, rfi support is enabled only when vendor
	 * command explicitly asked us to manage RFI.
	 * vendor command can change SO enablement mode
	 */
	if (is_set_master_cmd) {
		mvm->force_enable_rfi = mvm->rfi_wlan_master;
		so_rfi_mode = old_force_rfi ? true : mvm->force_enable_rfi;
	} else {
		so_rfi_mode = mvm->force_enable_rfi;
	}

	rfi_ddr_support = iwl_rfi_supported(mvm, so_rfi_mode, true);
	rfi_dlvr_support = iwl_rfi_supported(mvm, so_rfi_mode, false);

	if (!rfi_ddr_support && !rfi_dlvr_support)
		return -EOPNOTSUPP;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;
	hcmd.data[0] = cmd;

	lockdep_assert_held(&mvm->mutex);

	IWL_DEBUG_FW(mvm, "wlan is %s rfi master\n",
		     mvm->rfi_wlan_master ? "" : "Not");

	/* Drop stored rfi_config_cmd buffer when there is change in master */
	if (is_set_master_cmd) {
		kfree(mvm->iwl_prev_rfi_config_cmd);
		mvm->iwl_prev_rfi_config_cmd = NULL;
	}

	/* Zero iwl_rfi_config_cmd is legal for FW API and since it has
	 * rfi_memory_support equal to 0, it will disable all RFIm operation
	 * in the FW.
	 * Not having rfi_config_info when wlan driver is not the master
	 * means user-space requested to stop RFIm.
	 */
	if (!rfi_config_info && !mvm->rfi_wlan_master) {
		if (force_send_table || !mvm->iwl_prev_rfi_config_cmd ||
		    memcmp(mvm->iwl_prev_rfi_config_cmd, cmd, sizeof(*cmd))) {
			IWL_DEBUG_FW(mvm, "Sending zero DDR superset table\n");
			goto send_empty_cmd;
		} else {
			IWL_DEBUG_FW(mvm, "Skip RFI_CONFIG_CMD sending\n");
			goto out;
		}
	}

	BUILD_BUG_ON(sizeof(*cmd) != sizeof(*mvm->iwl_prev_rfi_config_cmd));
	BUILD_BUG_ON(sizeof(cmd->ddr_table) !=
		sizeof(rfi_config_info->ddr_table));
	BUILD_BUG_ON(sizeof(cmd->desense_table) !=
		sizeof(rfi_config_info->desense_table));

	if (rfi_ddr_support) {
		/* Fill in the defaults, it'll be overridden if needed */
		memcpy(cmd->ddr_table, iwl_rfi_ddr_table,
		       sizeof(cmd->ddr_table));
		memset(&cmd->desense_table, IWL_RFI_DDR_DESENSE_VALUE,
		       sizeof(cmd->desense_table));
		cmd->snr_threshold = cpu_to_le32(IWL_RFI_DDR_SNR_THRESHOLD);

		/* don't send RFI_CONFIG_CMD to FW when DDR table passed by
		 * caller and previously sent table is same.
		 */
		if (!force_send_table && rfi_config_info &&
		    mvm->iwl_prev_rfi_config_cmd &&
		    !iwl_mvm_ddr_changed(mvm, rfi_config_info)) {
			IWL_DEBUG_FW(mvm, "Skip RFI_CONFIG_CMD sending\n");
			goto out;
		/* send RFI_CONFIG_CMD to FW with OEM ddr table */
		} else if (rfi_config_info) {
			IWL_DEBUG_FW(mvm, "Sending oem DDR superset table\n");
			memcpy(cmd->ddr_table, rfi_config_info->ddr_table,
			       sizeof(cmd->ddr_table));
			/* notify FW the table is not the default one */
			cmd->oem = 1;
			memcpy(cmd->desense_table,
			       rfi_config_info->desense_table,
			       sizeof(cmd->desense_table));
			cmd->snr_threshold =
					rfi_config_info->snr_threshold;
		/* send previous RFI_CONFIG_CMD once again as FW lost RFI DDR
		 * table in reset
		 */
		} else if (mvm->iwl_prev_rfi_config_cmd && force_send_table) {
			memcpy(cmd, mvm->iwl_prev_rfi_config_cmd, sizeof(*cmd));
			IWL_DEBUG_FW(mvm,
				     "Sending buffered %s DDR superset table\n",
				     cmd->oem ? "oem" : "default");
		/* don't send previous RFI_CONFIG_CMD as FW has same table */
		} else if (mvm->iwl_prev_rfi_config_cmd) {
			IWL_DEBUG_FW(mvm, "Skip RFI_CONFIG_CMD sending\n");
			goto out;
		/* send default ddr table for the first time */
		} else {
			IWL_DEBUG_FW(mvm,
				     "Sending default DDR superset table\n");
		}

		cmd->rfi_memory_support = cpu_to_le32(RFI_DDR_SUPPORTED_MSK);
	}

	if (rfi_dlvr_support)
		cmd->rfi_memory_support |= cpu_to_le32(RFI_DLVR_SUPPORTED_MSK);

	if (rfi_ddr_support && iwl_mvm_rfi_desense_supported(mvm))
		cmd->rfi_memory_support |=
			cpu_to_le32(RFI_DESENSE_SUPPORTED_MSK);

send_empty_cmd:
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	kfree(mvm->iwl_prev_rfi_config_cmd);
	if (ret) {
		mvm->iwl_prev_rfi_config_cmd = NULL;
		IWL_ERR(mvm, "Failed to send RFI config cmd %d\n", ret);
	} else {
		mvm->iwl_prev_rfi_config_cmd = cmd;
		cmd = NULL;
	}

out:
	kfree(cmd);
	return ret;
}

void *iwl_rfi_get_freq_table(struct iwl_mvm *mvm)
{
	void *resp;
	int resp_size;
	int ret;
	struct iwl_host_cmd cmd = {
		.id = WIDE_ID(SYSTEM_GROUP, RFI_GET_FREQ_TABLE_CMD),
		.flags = CMD_WANT_SKB,
	};
	u8 notif_ver = iwl_fw_lookup_notif_ver(mvm->fw, SYSTEM_GROUP,
					       RFI_GET_FREQ_TABLE_CMD,
					       IWL_FW_CMD_VER_UNKNOWN);

	if (notif_ver == 1)
		resp_size = sizeof(struct iwl_rfi_freq_table_resp_cmd_v1);
	else if (notif_ver == 2)
		resp_size = sizeof(struct iwl_rfi_freq_table_resp_cmd);
	else
		return ERR_PTR(-EOPNOTSUPP);

	if (!iwl_rfi_supported(mvm, mvm->force_enable_rfi, true))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &cmd);
	mutex_unlock(&mvm->mutex);
	if (ret)
		return ERR_PTR(ret);

	if (WARN_ON_ONCE(iwl_rx_packet_payload_len(cmd.resp_pkt) !=
			 resp_size)) {
		iwl_free_resp(&cmd);
		return ERR_PTR(-EIO);
	}

	resp = kmemdup(cmd.resp_pkt->data, resp_size, GFP_KERNEL);
	iwl_free_resp(&cmd);

	if (!resp)
		return ERR_PTR(-ENOMEM);

	return resp;
}

VISIBLE_IF_IWLWIFI_KUNIT
bool iwl_mvm_rfi_ddr_esr_accept_link_pair(struct iwl_mvm *mvm, u8 channel_a,
					  u8 band_a, u8 channel_b, u8 band_b)
{
	bool rfi_ddr_support = iwl_rfi_supported(mvm, mvm->force_enable_rfi,
						 true);
	struct iwl_rfi_freq_table_resp_cmd_v1 *iwl_rfi_subset_table;
	bool channel_a_has_interference = false;
	bool channel_b_has_interference = false;
	u8 ddr_interference_freq_count = 0;
	int i, j;

	if (!rfi_ddr_support)
		return true;

	iwl_rfi_subset_table = mvm->iwl_rfi_subset_table;

	for (i = 0; i < ARRAY_SIZE(iwl_rfi_subset_table->ddr_table); i++) {
		struct iwl_rfi_ddr_lut_entry *ddr_table_entry =
			&iwl_rfi_subset_table->ddr_table[i];
		bool channel_a_interference_entry = false;
		bool channel_b_interference_entry = false;

		/* freq 0 means empty row */
		if (!ddr_table_entry->freq)
			continue;

		for (j = 0; j < ARRAY_SIZE(ddr_table_entry->channels); j++) {
			/* channel 0 means empty entry */
			if (!ddr_table_entry->channels[j])
				continue;

			if (ddr_table_entry->channels[j] == channel_a &&
			    ddr_table_entry->bands[j] == band_a) {
				channel_a_interference_entry = true;
				channel_a_has_interference = true;
			}
			if (ddr_table_entry->channels[j] == channel_b &&
			    ddr_table_entry->bands[j] == band_b) {
				channel_b_interference_entry = true;
				channel_b_has_interference = true;
			}

			if (channel_a_interference_entry &&
			    channel_b_interference_entry)
				break;
		}

		if (channel_a_interference_entry ||
		    channel_b_interference_entry)
			ddr_interference_freq_count++;
	}

	/* Wifi firmware request PMC firmware not to operate on given DDR freq.
	 * so if there is only one interfering freq at most, we can ask PMC not
	 * to operate on it, hence EMLSR is allowed
	 */
	if (ddr_interference_freq_count < 2)
		return true;

	return !(channel_a_has_interference && channel_b_has_interference);
}
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_mvm_rfi_ddr_esr_accept_link_pair);

VISIBLE_IF_IWLWIFI_KUNIT
bool iwl_mvm_rfi_dlvr_esr_accept_link_pair(struct iwl_mvm *mvm, u8 channel_a,
					   u8 band_a, u8 channel_b, u8 band_b)
{
	bool rfi_dlvr_support = iwl_rfi_supported(mvm, mvm->force_enable_rfi,
						  false);
	u8 notif_ver = iwl_fw_lookup_notif_ver(mvm->fw, SYSTEM_GROUP,
					       RFI_GET_FREQ_TABLE_CMD, 0);
	struct iwl_rfi_freq_table_resp_cmd *iwl_rfi_subset_table;
	bool channel_a_has_interference = false;
	bool channel_b_has_interference = false;
	int i, j;

	if (notif_ver < 2 || !rfi_dlvr_support)
		return true;

	iwl_rfi_subset_table = mvm->iwl_rfi_subset_table;
	for (i = 0; i < ARRAY_SIZE(iwl_rfi_subset_table->dlvr_table); i++) {
		struct iwl_rfi_dlvr_lut_entry *dlvr_table_entry =
			&iwl_rfi_subset_table->dlvr_table[i];
		bool channel_a_interference_entry = false;
		bool channel_b_interference_entry = false;

		/* freq 0 means empty row */
		if (!dlvr_table_entry->freq)
			continue;

		for (j = 0; j < ARRAY_SIZE(dlvr_table_entry->channels); j++) {
			/* channel 0 means empty entry */
			if (!dlvr_table_entry->channels[j])
				continue;

			if (dlvr_table_entry->channels[j] == channel_a &&
			    dlvr_table_entry->bands[j] == band_a) {
				channel_a_interference_entry = true;
				channel_a_has_interference = true;
			}
			if (dlvr_table_entry->channels[j] == channel_b &&
			    dlvr_table_entry->bands[j] == band_b) {
				channel_b_interference_entry = true;
				channel_b_has_interference = true;
			}

			if (channel_a_interference_entry &&
			    channel_b_interference_entry)
				break;
		}

		/* Wifi firmware request PMC firmware to operate on given
		 * DLVR freq. Found free DLVR entry, hence allow EMLSR
		 */
		if (!(channel_a_interference_entry ||
		      channel_b_interference_entry))
			return true;
	}

	return !(channel_a_has_interference && channel_b_has_interference);
}
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_mvm_rfi_dlvr_esr_accept_link_pair);

u32
iwl_mvm_rfi_esr_state_link_pair(struct ieee80211_vif *vif,
				const struct iwl_mvm_link_sel_data *a,
				const struct iwl_mvm_link_sel_data *b)
{
	u8 channel_a = ieee80211_frequency_to_channel(a->chandef->center_freq1);
	u8 channel_b = ieee80211_frequency_to_channel(b->chandef->center_freq1);
	u8 band_a = iwl_mvm_phy_band_from_nl80211(a->chandef->chan->band);
	u8 band_b = iwl_mvm_phy_band_from_nl80211(b->chandef->chan->band);
	struct iwl_mvm *mvm = iwl_mvm_vif_from_mac80211(vif)->mvm;

	lockdep_assert_held(&mvm->mutex);
	if (mvm->fw_rfi_state != IWL_RFI_DDR_SUBSET_TABLE_READY ||
	    !mvm->iwl_rfi_subset_table)
		return 0;

	if (iwl_mvm_rfi_ddr_esr_accept_link_pair(mvm, channel_a, band_a,
						 channel_b, band_b) &&
	    iwl_mvm_rfi_dlvr_esr_accept_link_pair(mvm, channel_a, band_a,
						  channel_b, band_b))
		return 0;

	return IWL_MVM_ESR_EXIT_RFI;
}

static void iwl_rfi_update_mvm_rfi_tables(struct iwl_mvm *mvm)
{
	void *iwl_rfi_subset_table;

	iwl_rfi_subset_table = iwl_rfi_get_freq_table(mvm);
	mutex_lock(&mvm->mutex);
	kfree(mvm->iwl_rfi_subset_table);
	if (IS_ERR(iwl_rfi_subset_table)) {
		mvm->iwl_rfi_subset_table = NULL;
		IWL_DEBUG_FW(mvm, "RFIm, tables read fail\n");
	} else {
		mvm->iwl_rfi_subset_table = iwl_rfi_subset_table;
	}
	mutex_unlock(&mvm->mutex);
}

void iwl_rfi_support_notif_handler(struct iwl_mvm *mvm,
				   struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_rfi_support_notif *notif = (void *)pkt->data;

	mvm->fw_rfi_state = le32_to_cpu(notif->reason);
	switch (mvm->fw_rfi_state) {
	case IWL_RFI_DDR_SUBSET_TABLE_READY:
		IWL_DEBUG_FW(mvm, "RFIm, DDR subset table ready\n");
		iwl_rfi_update_mvm_rfi_tables(mvm);
		break;
	case IWL_RFI_PMC_SUPPORTED:
		IWL_DEBUG_FW(mvm, "RFIm, PMC supported\n");
		break;
	case IWL_RFI_PMC_NOT_SUPPORTED:
		IWL_DEBUG_FW(mvm, "RFIm, PMC not supported\n");
		break;
	case IWL_RFI_RESET_FAILURE_SEND_TO_PEER:
		fallthrough;
	case IWL_RFI_RESET_FAILURE_PLAT_PSS:
		fallthrough;
	case IWL_RFI_RESET_FAILURE_TIMER:
		fallthrough;
	case IWL_RFI_MAX_RESETS_DONE:
		fallthrough;
	default:
		IWL_DEBUG_FW(mvm, "RFIm is deactivated, reason = %d\n",
			     mvm->fw_rfi_state);
	}
}
