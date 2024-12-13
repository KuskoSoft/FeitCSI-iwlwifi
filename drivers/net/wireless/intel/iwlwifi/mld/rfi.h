// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_rfi_h__
#define __iwl_mld_rfi_h__

enum iwl_mld_rfi_feature {
	IWL_MLD_RFI_DDR_FEATURE,
	IWL_MLD_RFI_DLVR_FEATURE,
	IWL_MLD_RFI_DESENSE_FEATURE,
};

/**
 * struct iwl_mld_rfi - RFI data
 * @fw_state: Firmware RFI state &enum iwl_rfi_support_reason.
 * @bios_enabled: indicates RFI is enabled in BIOS.
 */
struct iwl_mld_rfi {
	/* Add here fields that need clean up on restart */
	struct_group(zeroed_on_hw_restart,
		u32 fw_state;
	);
	/* And here fields that survive a fw restart */
	bool bios_enabled;
};

int iwl_mld_rfi_send_config_cmd(struct iwl_mld *mld);
struct iwl_rfi_freq_table_resp_cmd *
iwl_mld_rfi_get_freq_table(struct iwl_mld *mld);

void iwl_mld_handle_rfi_support_notif(struct iwl_mld *mld,
				      struct iwl_rx_packet *pkt);

#endif /* __iwl_mld_rfi_h__ */
