// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include <linux/etherdevice.h>
#include <net/netlink.h>
#include <net/mac80211.h>
#include "mld.h"
#include "mcc.h"
#include "regulatory.h"
#include "vendor-cmd.h"
#include "iwl-vendor-cmd.h"
#include "fw/api/rfi.h"
#include "rfi.h"

static int validate_rfi_channel(const struct nlattr *attr,
				struct netlink_ext_ack *extack)
{
	u8 *channel_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_ddr_lut_entry *)0)->channels))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (channel_list[i] > IWL_RFI_MAX_ALLOWED_CHAN)
			return -EINVAL;

	return 0;
}

static int validate_rfi_bands(const struct nlattr *attr,
			      struct netlink_ext_ack *extack)
{
	u8 *band_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_ddr_lut_entry *)0)->bands))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (band_list[i] != PHY_BAND_24 &&
		    band_list[i] != PHY_BAND_5 &&
		    band_list[i] != PHY_BAND_6)
			return -EINVAL;

	return 0;
}

static int validate_rfi_desense(const struct nlattr *attr,
				struct netlink_ext_ack *extack)
{
	u8 *desense_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_desense_lut_entry *)0)->chain_a))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (desense_list[i] > IWL_RFI_MAX_DESENSE)
			return -EINVAL;

	return 0;
}

static const struct nla_policy
iwl_mld_vendor_attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_COUNTRY] = { .type = NLA_STRING, .len = 2 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_RFIM_INFO] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_RFIM_FREQ] = NLA_POLICY_MAX(NLA_U16,
							 IWL_RFI_MAX_FREQ_VAL),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_channel,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_BANDS] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_bands,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_desense,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_desense,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD] =
		NLA_POLICY_MAX(NLA_U32, IWL_RFI_MAX_SNR_THRESHOLD),
};

static struct nlattr **iwl_mld_parse_vendor_data(const void *data, int data_len)
{
	struct nlattr **tb;
	int err;

	if (!data)
		return ERR_PTR(-EINVAL);

	tb = kcalloc(MAX_IWL_MVM_VENDOR_ATTR + 1, sizeof(*tb), GFP_KERNEL);
	if (!tb)
		return ERR_PTR(-ENOMEM);

	err = nla_parse(tb, MAX_IWL_MVM_VENDOR_ATTR, data, data_len,
			iwl_mld_vendor_attr_policy, NULL);
	if (err) {
		kfree(tb);
		return ERR_PTR(err);
	}

	return tb;
}

static int iwl_mld_set_country(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct ieee80211_regdomain *regd;
	struct nlattr **tb;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int retval;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_COUNTRY]) {
		retval = -EINVAL;
		goto free;
	}

	/* set regdomain information to FW */
	regd = iwl_mld_get_regdomain(mld,
				     nla_data(tb[IWL_MVM_VENDOR_ATTR_COUNTRY]),
				     MCC_SOURCE_MCC_API, NULL);
	if (IS_ERR_OR_NULL(regd)) {
		retval = -EIO;
		goto free;
	}

	retval = regulatory_set_wiphy_regd(wiphy, regd);
	kfree(regd);
free:
	kfree(tb);
	return retval;
}

static int iwl_mld_vendor_set_dynamic_txp_profile(struct wiphy *wiphy,
						  struct wireless_dev *wdev,
						  const void *data,
						  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct nlattr **tb;
	u8 chain_a, chain_b;
	int err;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] ||
	    !tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]) {
		kfree(tb);
		return -EINVAL;
	}

	chain_a = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE]);
	chain_b = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]);

	kfree(tb);

	if (mld->fwrt.sar_chain_a_profile == chain_a &&
	    mld->fwrt.sar_chain_b_profile == chain_b)
		return 0;

	mld->fwrt.sar_chain_a_profile = chain_a;
	mld->fwrt.sar_chain_b_profile = chain_b;

	/* If the fw is not running, settings will be applied upon fw load */
	if (!mld->fw_status.running)
		return 0;

	err = iwl_mld_config_sar_profile(mld, chain_a, chain_b);

	if (err > 0)
		/* For SAR validation purpose we need to track the exact return
		 * value of iwl_mld_sar_select_profile, mostly to differentiate
		 * between general SAR failure and the case of WRDS disable
		 * (it is illegal if WRDS doesn't exist but WGDS does).
		 * Since nl80211 forbids a positive number as a return value,
		 * in case SAR is disabled overwrite it with -ENOENT.
		 */
		err = -ENOENT;
	return err;
}

static int iwl_mld_vendor_ppag_get_table(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb = NULL;
	struct nlattr *nl_table;
	int ret, per_chain_size, chain;

	/* if ppag is disabled */
	if (!mld->fwrt.ppag_flags)
		return -ENOENT;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 180);
	if (!skb)
		return -ENOMEM;

	nl_table = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_PPAG_TABLE |
				   NLA_F_NESTED);
	if (!nl_table) {
		ret = -ENOBUFS;
		goto err;
	}

	per_chain_size = (mld->fwrt.ppag_ver == 0) ?
		IWL_NUM_SUB_BANDS_V1 : IWL_NUM_SUB_BANDS_V2;

	for (chain = 0; chain < IWL_NUM_CHAIN_LIMITS; chain++) {
		if (nla_put(skb, chain + 1, per_chain_size,
			    &mld->fwrt.ppag_chains[chain].subbands[0])) {
			ret = -ENOBUFS;
			goto err;
		}
	}

	nla_nest_end(skb, nl_table);

	/* put the ppag version */
	if (nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS,
			per_chain_size)) {
		ret = -ENOBUFS;
		goto err;
	}

	return cfg80211_vendor_cmd_reply(skb);
err:
	kfree_skb(skb);
	return ret;
}

static bool
iwl_mld_vendor_valid_rfim_info_attr(struct iwl_mld *mld,
				    struct nlattr *rfim_info_attr)
{
	struct iwl_mld_rfi_config_info *rfi_config_info = NULL;
	bool snr_threshold_present = false;
	bool channel_list_present = true;
	bool chain_a_list_present = true;
	bool chain_b_list_present = true;
	bool band_list_present = true;
	bool has_rfi_desense_support;
	struct nlattr *attr;
	int row_idx = -1; /* the row is updated only at frequency attr */
	int rem;

	if (!rfim_info_attr)
		return false;

	has_rfi_desense_support =
		iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DESENSE_FEATURE);

	BUILD_BUG_ON(ARRAY_SIZE(rfi_config_info->ddr_table) !=
		     ARRAY_SIZE(rfi_config_info->desense_table));
	nla_for_each_nested(attr, rfim_info_attr, rem) {
		switch (nla_type(attr)) {
		case IWL_MVM_VENDOR_ATTR_RFIM_FREQ:
			if (!channel_list_present || !band_list_present ||
			    chain_a_list_present != chain_b_list_present)
				return false;

			band_list_present = false;
			channel_list_present = false;
			chain_a_list_present = false;
			chain_b_list_present = false;

			row_idx++;
			if (row_idx >= ARRAY_SIZE(rfi_config_info->ddr_table))
				return false;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS:
			if (row_idx < 0 || channel_list_present)
				return false;

			channel_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_BANDS:
			if (row_idx < 0 || band_list_present)
				return false;

			band_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE:
			if (row_idx < 0 || chain_a_list_present ||
			    !has_rfi_desense_support)
				return false;

			chain_a_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE:
			if (row_idx < 0 || chain_b_list_present ||
			    !has_rfi_desense_support)
				return false;

			chain_b_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD:
			if (snr_threshold_present)
				return false;

			snr_threshold_present = true;
			break;
		default:
			IWL_ERR(mld, "Invalid attribute %d\n", nla_type(attr));
			return false;
		}
	}

	return row_idx >= 0 && channel_list_present && band_list_present &&
	       chain_a_list_present == chain_b_list_present;
}

static int iwl_mld_vendor_rfi_set_table(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct iwl_mld_rfi_config_info *rfi_config_info __free(kfree) = NULL;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct nlattr **tb __free(kfree) = NULL;
	struct nlattr *attr;
	int rem, err = 0;
	int row_idx = -1; /* the row is updated only at frequency attr */

	if (!iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DDR_FEATURE))
		return -EINVAL;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!iwl_mld_vendor_valid_rfim_info_attr(mld,
						 tb[IWL_MVM_VENDOR_ATTR_RFIM_INFO]))
		return -EINVAL;

	rfi_config_info = kzalloc(sizeof(*rfi_config_info), GFP_KERNEL);
	if (!rfi_config_info)
		return -ENOMEM;

	/* Fill rfi_config_info with default data to have compatibility
	 * with old RFI user application.
	 */
	memset(rfi_config_info->desense_table, IWL_RFI_DDR_DESENSE_VALUE,
	       sizeof(rfi_config_info->desense_table));
	rfi_config_info->snr_threshold = cpu_to_le32(IWL_RFI_DDR_SNR_THRESHOLD);

	nla_for_each_nested(attr, tb[IWL_MVM_VENDOR_ATTR_RFIM_INFO], rem) {
		switch (nla_type(attr)) {
		case IWL_MVM_VENDOR_ATTR_RFIM_FREQ:
			row_idx++;
			rfi_config_info->ddr_table[row_idx].freq =
				cpu_to_le16(nla_get_u16(attr));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS:
			memcpy(rfi_config_info->ddr_table[row_idx].channels,
			       nla_data(attr),
			       sizeof(rfi_config_info->ddr_table[0].channels));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_BANDS:
			memcpy(rfi_config_info->ddr_table[row_idx].bands,
			       nla_data(attr),
			       sizeof(rfi_config_info->ddr_table[0].bands));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE:
			memcpy(rfi_config_info->desense_table[row_idx].chain_a,
			       nla_data(attr),
			       sizeof(rfi_config_info->desense_table[0].chain_a));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE:
			memcpy(rfi_config_info->desense_table[row_idx].chain_b,
			       nla_data(attr),
			       sizeof(rfi_config_info->desense_table[0].chain_b));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD:
			rfi_config_info->snr_threshold =
				cpu_to_le32(nla_get_u32(attr));
			break;
		}
	}

	/* Skip sending RFI_CONFIG_CMD to FW when RFI table is same as
	 * previous
	 */
	if (mld->rfi.external_config_info &&
	    !memcmp(rfi_config_info, mld->rfi.external_config_info,
		    sizeof(*rfi_config_info))) {
		IWL_DEBUG_INFO(mld, "Skip sending RFI_CONFIG_CMD\n");
		return 0;
	}

	swap(mld->rfi.external_config_info, rfi_config_info);
	err = iwl_mld_rfi_send_config_cmd(mld);
	if (err) {
		IWL_ERR(mld, "Failed to send rfi table to FW, error %d\n", err);
		kfree(mld->rfi.external_config_info);
		mld->rfi.external_config_info = NULL;
	}

	return err;
}

/* RFIM_INFO requires 4 bytes for nlattr.
 * DDR table will have 4 entries and each entry contains, frequency which
 * requires 2 bytes for it and 4 bytes for nlattr. channel, bands, chain_a and
 * chain_b requires 15 bytes each of it and 4 bytes each nlattr, extra 18 bytes
 * for future. So, response size is 4 + 4 * (2 + 4 + 4 * (15 + 4)) + 18 = 350
 */

#define RFI_GET_TABLE_RESP_SIZE		350
static int iwl_mld_vendor_rfi_get_table(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	const struct iwl_rfi_freq_table_resp_cmd *fw_table;
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb = NULL;
	struct nlattr *rfim_info;
	int ret;

	fw_table = mld->rfi.fw_table;
	if (!fw_table)
		return -EOPNOTSUPP;

	if (fw_table->status != RFI_FREQ_TABLE_OK)
		return -EINVAL;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  RFI_GET_TABLE_RESP_SIZE);
	if (!skb)
		return -ENOMEM;

	rfim_info = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_RFIM_INFO |
					NLA_F_NESTED);
	if (!rfim_info) {
		ret = -ENOBUFS;
		goto err;
	}

	BUILD_BUG_ON(ARRAY_SIZE(fw_table->ddr_table) !=
		     ARRAY_SIZE(fw_table->desense_table));

	for (int i = 0; i < ARRAY_SIZE(fw_table->ddr_table); i++) {
		if (nla_put_u16(skb, IWL_MVM_VENDOR_ATTR_RFIM_FREQ,
				le16_to_cpu(fw_table->ddr_table[i].freq)) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS,
			    sizeof(fw_table->ddr_table[i].channels),
			    fw_table->ddr_table[i].channels) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_BANDS,
			    sizeof(fw_table->ddr_table[i].bands),
			    fw_table->ddr_table[i].bands) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE,
			    sizeof(fw_table->desense_table[i].chain_a),
			    fw_table->desense_table[i].chain_a) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE,
			    sizeof(fw_table->desense_table[i].chain_b),
			    fw_table->desense_table[i].chain_b)) {
			ret = -ENOBUFS;
			goto err;
		}
	}

	nla_nest_end(skb, rfim_info);

	return cfg80211_vendor_cmd_reply(skb);

err:
	kfree_skb(skb);
	return ret;
}

static const struct wiphy_vendor_command iwl_mld_vendor_commands[] = {
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_COUNTRY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_set_country,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_set_dynamic_txp_profile,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_PPAG_GET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_ppag_get_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_SET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_rfi_set_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_GET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_rfi_get_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
};

void iwl_mld_vendor_cmds_register(struct iwl_mld *mld)
{
	mld->hw->wiphy->vendor_commands = iwl_mld_vendor_commands;
	mld->hw->wiphy->n_vendor_commands = ARRAY_SIZE(iwl_mld_vendor_commands);
}
