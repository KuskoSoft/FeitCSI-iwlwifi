// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>
#include <kunit/test-bug.h>

#include "utils.h"

#include <linux/device.h>
#include <net/mac80211.h>
#include "fw/api/scan.h"
#include "iwl-trans.h"
#include "mld.h"

#define KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, size)			\
do {									\
	(ptr) = kunit_kzalloc((test), (size), GFP_KERNEL);		\
	KUNIT_ASSERT_NOT_NULL((test), (ptr));				\
} while (0)

#define KUNIT_ALLOC_AND_ASSERT(test, ptr)				\
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, sizeof(*(ptr)))

struct iwl_mld *kunit_setup_mld(void)
{
	struct kunit *test = kunit_get_current_test();
	struct iwl_mld *mld;
	struct iwl_trans *trans;
	const struct iwl_cfg *cfg;
	struct iwl_fw *fw;
	struct ieee80211_hw *hw;

	KUNIT_ALLOC_AND_ASSERT(test, trans);
	KUNIT_ALLOC_AND_ASSERT(test, trans->dev);
	KUNIT_ALLOC_AND_ASSERT(test, cfg);
	KUNIT_ALLOC_AND_ASSERT(test, fw);
	KUNIT_ALLOC_AND_ASSERT(test, hw);
	KUNIT_ALLOC_AND_ASSERT(test, hw->wiphy);

	mutex_init(&hw->wiphy->mtx);

	/* Allocate and initialize the mld structure */
	KUNIT_ALLOC_AND_ASSERT(test, mld);
	iwl_construct_mld(mld, trans, cfg, fw, hw);

	mld->fwrt.trans = trans;
	mld->fwrt.fw = fw;
	mld->fwrt.dev = trans->dev;

	/* TODO: add priv_size to hw allocation and setup hw->priv to enable
	 * testing mac80211 callbacks
	 */

	KUNIT_ALLOC_AND_ASSERT(test, mld->nvm_data);
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, mld->scan.cmd,
				    sizeof(struct iwl_scan_req_umac_v17));
	mld->scan.cmd_size = sizeof(struct iwl_scan_req_umac_v17);

	return mld;
}
