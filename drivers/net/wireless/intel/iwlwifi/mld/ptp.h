/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_ptp_h__
#define __iwl_mld_ptp_h__

#include <linux/ptp_clock_kernel.h>

/**
 * struct ptp_data - PTP hardware clock data
 *
 * @ptp_clock: struct ptp_clock pointer returned by the ptp_clock_register()
 *	function.
 * @ptp_clock_info: struct ptp_clock_info that describes a PTP hardware clock
 * @lock: protects the time adjustments data
 * @delta: delta between hardware clock and ptp clock in nanoseconds
 */
struct ptp_data {
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_info;

	spinlock_t lock;
	s64 delta;
};

void iwl_mld_ptp_init(struct iwl_mld *mld);
void iwl_mld_ptp_remove(struct iwl_mld *mld);

#endif /* __iwl_mld_ptp_h__ */
