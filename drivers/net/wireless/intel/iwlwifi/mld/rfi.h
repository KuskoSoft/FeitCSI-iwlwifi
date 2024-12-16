// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#ifndef __iwl_mld_rfi_h__
#define __iwl_mld_rfi_h__

#include "fw/api/rfi.h"

enum iwl_mld_rfi_feature {
	IWL_MLD_RFI_DDR_FEATURE,
	IWL_MLD_RFI_DLVR_FEATURE,
	IWL_MLD_RFI_DESENSE_FEATURE,
};

#if CPTCFG_IWL_VENDOR_CMDS
/**
 * struct iwl_mld_rfi_config_info - RFI configuration information
 *
 * @ddr_table: a table of channels that are used by DDR
 * @desense_table: desense values per chain. see &iwl_rfi_desense_lut_entry
 * @snr_threshold: SNR threshold to be used for RSSI based RFIM.
 */
struct iwl_mld_rfi_config_info {
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_SIZE];
	struct iwl_rfi_desense_lut_entry desense_table[IWL_RFI_DDR_LUT_SIZE];
	__le32 snr_threshold;
};

#endif /* CPTCFG_IWL_VENDOR_CMDS */

/**
 * struct iwl_mld_rfi - RFI data
 * @fw_state: Firmware RFI state &enum iwl_rfi_support_reason.
 * @bios_enabled: indicates RFI is enabled in BIOS.
 * @external_config_info: RFI configuration information.
 */
struct iwl_mld_rfi {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u32 fw_state;
	);
	/* And here fields that survive a fw restart */
	bool bios_enabled;
#ifdef CPTCFG_IWL_VENDOR_CMDS
	struct iwl_mld_rfi_config_info *external_config_info;
#endif
};

int iwl_mld_rfi_send_config_cmd(struct iwl_mld *mld);
struct iwl_rfi_freq_table_resp_cmd *
iwl_mld_rfi_get_freq_table(struct iwl_mld *mld);

void iwl_mld_handle_rfi_support_notif(struct iwl_mld *mld,
				      struct iwl_rx_packet *pkt);
bool iwl_mld_rfi_supported(struct iwl_mld *mld,
			   enum iwl_mld_rfi_feature rfi_feature);

#endif /* __iwl_mld_rfi_h__ */
