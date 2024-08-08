// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for channel helper functions
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <kunit/test.h>

#include <iwl-trans.h>
#include "mld.h"

MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);

static void test_hcmd_name_sorted(struct kunit *test)
{
	int i;

	for (i = 0; i < global_iwl_mld_goups_size; i++) {
		const struct iwl_hcmd_arr *arr = &iwl_mld_groups[i];
		int j;

		if (!arr->arr)
			continue;
		for (j = 0; j < arr->size - 1; j++)
			KUNIT_EXPECT_LE(test, arr->arr[j].cmd_id,
					arr->arr[j + 1].cmd_id);
	}
}

static struct kunit_case hcmd_name_sorted_cases[] = {
	KUNIT_CASE(test_hcmd_name_sorted),
	{},
};

static struct kunit_suite hcmd_name_sorted = {
	.name = "iwlmld-sorted-hcmd-names",
	.test_cases = hcmd_name_sorted_cases,
};

kunit_test_suite(hcmd_name_sorted);
