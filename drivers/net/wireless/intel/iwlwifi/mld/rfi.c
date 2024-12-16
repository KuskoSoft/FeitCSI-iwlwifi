// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */

#include "mld.h"
#include "hcmd.h"
#include "rfi.h"
#include "fw/api/rfi.h"

static const
struct iwl_rfi_ddr_lut_entry iwl_mld_rfi_ddr_table[IWL_RFI_DDR_LUT_SIZE] = {
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

	/* frequency 3133MHz */
	{cpu_to_le16(188), {31, 47, 55, 57, 59, 61, 63, 65, 67, 71, 79, 95},
	      {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
	       PHY_BAND_6, PHY_BAND_6,}},

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

	/* frequency 6267MHz */
	{cpu_to_le16(376), {31, 47, 55, 57, 59, 61, 63, 65, 67, 71, 79, 95},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6,}},

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

	/* frequency 6667MHz */
	{cpu_to_le16(400), {127, 135, 137, 139, 141, 143, 145, 147, 151, 159},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},

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

	/* frequency 10400MHz */
	{cpu_to_le16(624), {34, 36, 38, 40, 42, 50},
	       {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,
		PHY_BAND_5,}},

	/* frequency 11200MHz */
	{cpu_to_le16(672), {114, 116, 118, 120, 122},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,}},

	/* frequency 11800MHz */
	{cpu_to_le16(708), {163, 171, 173, 175, 177},
	      {PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5, PHY_BAND_5,}},

	/* frequency 12800MHz */
	{cpu_to_le16(768), {63, 79, 83, 85, 87, 89, 91, 95,},
	       {PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,
		PHY_BAND_6, PHY_BAND_6, PHY_BAND_6,}},
};

static bool iwl_mld_rfi_fw_state_supported(struct iwl_mld *mld)
{
	return mld->rfi.fw_state == IWL_RFI_PMC_SUPPORTED ||
	       mld->rfi.fw_state == IWL_RFI_DDR_SUBSET_TABLE_READY;
}

bool iwl_mld_rfi_supported(struct iwl_mld *mld,
			   enum iwl_mld_rfi_feature rfi_feature)
{
	u32 mac_type = CSR_HW_REV_TYPE(mld->trans->hw_rev);

	if (!(mld->trans->trans_cfg->integrated && mld->rfi.bios_enabled &&
	      iwl_mld_rfi_fw_state_supported(mld)))
		return false;

	if (rfi_feature == IWL_MLD_RFI_DDR_FEATURE)
		return fw_has_capa(&mld->fw->ucode_capa,
				   IWL_UCODE_TLV_CAPA_RFI_DDR_SUPPORT);

	if (rfi_feature == IWL_MLD_RFI_DLVR_FEATURE)
		return fw_has_capa(&mld->fw->ucode_capa,
				   IWL_UCODE_TLV_CAPA_RFI_DLVR_SUPPORT);

	return (mac_type == IWL_CFG_MAC_TYPE_SC ||
		mac_type == IWL_CFG_MAC_TYPE_SC2 ||
		mac_type == IWL_CFG_MAC_TYPE_SC2F) &&
	       fw_has_capa(&mld->fw->ucode_capa,
			   IWL_UCODE_TLV_CAPA_RFI_DDR_SUPPORT);
}

static void iwl_mld_set_default_rfi_config_cmd(struct iwl_rfi_config_cmd *cmd)
{
	BUILD_BUG_ON(sizeof(iwl_mld_rfi_ddr_table) != sizeof(cmd->ddr_table));

	cmd->rfi_memory_support = 0;
	memcpy(cmd->ddr_table, iwl_mld_rfi_ddr_table, sizeof(cmd->ddr_table));
	memset(cmd->desense_table, IWL_RFI_DDR_DESENSE_VALUE,
	       sizeof(cmd->desense_table));
	cmd->snr_threshold = cpu_to_le32(IWL_RFI_DDR_SNR_THRESHOLD);
}

int iwl_mld_rfi_send_config_cmd(struct iwl_mld *mld)
{
	struct iwl_rfi_config_cmd *cmd __free(kfree) = NULL;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(SYSTEM_GROUP, RFI_CONFIG_CMD),
		.dataflags[0] = IWL_HCMD_DFL_DUP,
		.len[0] = sizeof(*cmd),
	};
	bool rfi_dlvr_support;
	bool rfi_ddr_support;
	int ret;

	rfi_ddr_support = iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DDR_FEATURE);
	rfi_dlvr_support = iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DLVR_FEATURE);

	if (!rfi_ddr_support && !rfi_dlvr_support)
		return -EOPNOTSUPP;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	iwl_mld_set_default_rfi_config_cmd(cmd);
	hcmd.data[0] = cmd;

	if (rfi_ddr_support)
		cmd->rfi_memory_support = cpu_to_le32(RFI_DDR_SUPPORTED_MSK);

	if (rfi_dlvr_support)
		cmd->rfi_memory_support |= cpu_to_le32(RFI_DLVR_SUPPORTED_MSK);

	if (iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DESENSE_FEATURE))
		cmd->rfi_memory_support |=
			cpu_to_le32(RFI_DESENSE_SUPPORTED_MSK);

#ifdef CPTCFG_IWL_VENDOR_CMDS
	BUILD_BUG_ON(sizeof(cmd->ddr_table) !=
		sizeof(mld->rfi.external_config_info->ddr_table));
	BUILD_BUG_ON(sizeof(cmd->desense_table) !=
		sizeof(mld->rfi.external_config_info->desense_table));

	if (mld->rfi.external_config_info) {
		IWL_DEBUG_INFO(mld, "Sending oem RFI table\n");
		memcpy(cmd->ddr_table, mld->rfi.external_config_info->ddr_table,
		       sizeof(cmd->ddr_table));
		memcpy(cmd->desense_table,
		       mld->rfi.external_config_info->desense_table,
		       sizeof(cmd->desense_table));
		cmd->snr_threshold =
			mld->rfi.external_config_info->snr_threshold;
		cmd->oem = 1;
	} else {
		IWL_DEBUG_INFO(mld, "Sending default RFI table\n");
	}
#endif

	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (ret)
		IWL_ERR(mld, "Failed to send RFI config cmd %d\n", ret);

	return ret;
}

struct iwl_rfi_freq_table_resp_cmd *
iwl_mld_rfi_get_freq_table(struct iwl_mld *mld)
{
	struct iwl_host_cmd cmd = {
		.id = WIDE_ID(SYSTEM_GROUP, RFI_GET_FREQ_TABLE_CMD),
		.flags = CMD_WANT_SKB,
	};
	struct iwl_rfi_freq_table_resp_cmd *resp = NULL;
	int ret;

	if (!iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DDR_FEATURE) &&
	    !iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DLVR_FEATURE) &&
	    !iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DESENSE_FEATURE))
		return ERR_PTR(-EOPNOTSUPP);

	ret = iwl_mld_send_cmd(mld, &cmd);
	if (ret)
		return ERR_PTR(ret);

	if (IWL_FW_CHECK(mld,
			 iwl_rx_packet_payload_len(cmd.resp_pkt) !=
				sizeof(*resp),
			 "Unexpected RFI_GET_FREQ_TABLE_CMD response size %d (expected %ld)\n",
			 iwl_rx_packet_payload_len(cmd.resp_pkt),
			 sizeof(*resp))) {
		iwl_free_resp(&cmd);
		return ERR_PTR(-EIO);
	}

	resp = kmemdup(cmd.resp_pkt->data, sizeof(*resp), GFP_KERNEL);
	iwl_free_resp(&cmd);

	if (!resp)
		return ERR_PTR(-ENOMEM);

	return resp;
}

void iwl_mld_handle_rfi_support_notif(struct iwl_mld *mld,
				      struct iwl_rx_packet *pkt)
{
	const struct iwl_rfi_support_notif *notif = (void *)pkt->data;

	mld->rfi.fw_state = le32_to_cpu(notif->reason);
	switch (mld->rfi.fw_state) {
	case IWL_RFI_DDR_SUBSET_TABLE_READY:
		IWL_DEBUG_FW(mld, "RFIm, DDR subset table ready\n");
		break;
	case IWL_RFI_PMC_SUPPORTED:
		IWL_DEBUG_FW(mld, "RFIm, PMC supported\n");
		break;
	case IWL_RFI_PMC_NOT_SUPPORTED:
		IWL_DEBUG_FW(mld, "RFIm, PMC not supported\n");
		break;
	default:
		IWL_DEBUG_FW(mld, "RFIm is deactivated, reason = %d\n",
			     mld->rfi.fw_state);
	}
}
