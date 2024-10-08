// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include <linux/etherdevice.h>
#include <net/netlink.h>
#include <net/mac80211.h>
#include "mld.h"
#include "mcc.h"
#include "regulatory.h"
#include "vendor-cmd.h"
#include "iwl-vendor-cmd.h"

static const struct nla_policy
iwl_mld_vendor_attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_COUNTRY] = { .type = NLA_STRING, .len = 2 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE] = { .type = NLA_U8 },
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
};

void iwl_mld_vendor_cmds_register(struct iwl_mld *mld)
{
	mld->hw->wiphy->vendor_commands = iwl_mld_vendor_commands;
	mld->hw->wiphy->n_vendor_commands = ARRAY_SIZE(iwl_mld_vendor_commands);
}
