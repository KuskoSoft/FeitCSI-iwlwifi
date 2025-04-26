// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>
#include <net/mac80211.h>
#include "mvm/mvm.h"
#include "fw/api/rfi.h"

#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
#else
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
#endif

static struct wiphy wiphy = {
	.mtx = __MUTEX_INITIALIZER(wiphy.mtx),
};

static struct ieee80211_hw hw = {
	.wiphy = &wiphy,
};

static const struct iwl_fw_cmd_version entry = {
	.group = SYSTEM_GROUP,
	.cmd = RFI_GET_FREQ_TABLE_CMD,
	.notif_ver = 2
};

static struct iwl_fw fw = {
	.ucode_capa = {
		.n_cmd_versions = 1,
		.cmd_versions = &entry,
	}
};

static struct iwl_cfg_trans_params trans_cfg = {
	.integrated = true
};

static struct iwl_trans trans = {
	.trans_cfg = &trans_cfg,
	/* RFI feature is enabled only for MA family */
	.hw_rev = IWL_CFG_MAC_TYPE_MA << 4,
};

static struct iwl_mvm mvm = {
	.trans = &trans,
	.fw = &fw,
	.hw = &hw,
	.mutex = __MUTEX_INITIALIZER(mvm.mutex),
	.fw_rfi_state = IWL_RFI_DDR_SUBSET_TABLE_READY,
	.bios_enable_rfi = true,
};

static const struct valid_rfi_link_pair_case {
	const char *desc;
	u8 channel_a;
	u8 channel_b;
	u8 band_a;
	u8 band_b;
	struct iwl_rfi_freq_table_resp_cmd rfi_subset_table;
	bool rfi_ddr_valid;
	bool rfi_dlvr_valid;
} valid_rfi_link_pair_cases[] = {
	{
		.desc = "Empty tables",
		.channel_a = 1,
		.channel_b = 2,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.rfi_subset_table = {
			.ddr_table = {
				{
					.freq = 0,
					.channels = {},
					.bands = {},
				},
			},
			.dlvr_table = {
				{
					.freq = 0,
					.channels = {},
					.bands = {},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "One link has interference with one of DDR and DLVR frequency",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.rfi_subset_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {11, 15, 31},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {11, 15, 31},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "Two links has interference with two different DDR and DLVR frequencies",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.rfi_subset_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = false,
		.rfi_dlvr_valid = false,
	},
	{
		.desc = "One frequency that doesn't interfere the link",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.rfi_subset_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(192),
					.channels = {31, 33, 35},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1348),
					.channels = {31, 33, 35},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = false,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "One link has interference with DDR and DLVR frequency",
		.channel_a = 3,
		.channel_b = 7,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.rfi_subset_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {5, 7, 9},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {7, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {5, 7, 9},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {7, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
};

KUNIT_ARRAY_PARAM_DESC(valid_rfi_link_pair, valid_rfi_link_pair_cases, desc)

static void test_rfi_valid_link_pair(struct kunit *test)
{
	const struct valid_rfi_link_pair_case *params = test->param_value;
	bool dlvr_result;
	bool ddr_result;

	mvm.iwl_rfi_subset_table =
		kunit_kzalloc(test, sizeof(struct iwl_rfi_freq_table_resp_cmd),
			      GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, mvm.iwl_rfi_subset_table);

	memcpy(mvm.iwl_rfi_subset_table, &params->rfi_subset_table,
	       sizeof(struct iwl_rfi_freq_table_resp_cmd));

	wiphy_lock(&wiphy);
	mutex_lock(&mvm.mutex);
	__set_bit((__force long)IWL_UCODE_TLV_CAPA_RFI_DDR_SUPPORT,
		  fw.ucode_capa._capa);
	__set_bit((__force long)IWL_UCODE_TLV_CAPA_RFI_DLVR_SUPPORT,
		  fw.ucode_capa._capa);

	ddr_result = iwl_mvm_rfi_ddr_esr_accept_link_pair(&mvm,
							  params->channel_a,
							  params->band_a,
							  params->channel_b,
							  params->band_b);
	dlvr_result = iwl_mvm_rfi_dlvr_esr_accept_link_pair(&mvm,
							    params->channel_a,
							    params->band_a,
							    params->channel_b,
							    params->band_b);
	mutex_unlock(&mvm.mutex);
	wiphy_unlock(&wiphy);

	KUNIT_EXPECT_EQ(test, ddr_result, params->rfi_ddr_valid);
	KUNIT_EXPECT_EQ(test, dlvr_result, params->rfi_dlvr_valid);

	kunit_kfree(test, mvm.iwl_rfi_subset_table);
}

static struct kunit_case valid_rfi_link_pair_test_cases[] = {
	KUNIT_CASE_PARAM(test_rfi_valid_link_pair,
			 valid_rfi_link_pair_gen_params),
	{},
};

static struct kunit_suite valid_rfi_link_pair = {
	.name = "iwlmvm-valid-rfi-link-pair",
	.test_cases = valid_rfi_link_pair_test_cases,
};

kunit_test_suite(valid_rfi_link_pair);
