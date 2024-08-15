// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>

#include "utils.h"
#include "mld.h"

MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);

static void iwl_mld_kunit_test_example(struct kunit *test)
{
	struct iwl_mld *mld = test->priv;

	/* Perform tests on the mld instance */
	KUNIT_EXPECT_PTR_EQ(test, mld->dev, mld->trans->dev);
}

static struct kunit_case iwl_mld_kunit_test_cases[] = {
	KUNIT_CASE(iwl_mld_kunit_test_example),
	{},
};

static struct kunit_suite iwl_mld_kunit_test_suite = {
	.name = "iwl_mld_kunit_test_suite",
	.test_cases = iwl_mld_kunit_test_cases,
	.init = kunit_test_init,
};

kunit_test_suite(iwl_mld_kunit_test_suite);
