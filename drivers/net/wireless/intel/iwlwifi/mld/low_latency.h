/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_low_latency_h__
#define __iwl_mld_low_latency_h__

/**
 * struct iwl_mld_low_latency_packets_counters - Packets counters
 * @lock: synchronize the counting in data path against the worker
 * @vo_vi: per-mac, counts the number of TX and RX voice and video packets
 */
struct iwl_mld_low_latency_packets_counters {
	spinlock_t lock;
	u32 vo_vi[NUM_MAC_INDEX_DRIVER];
} ____cacheline_aligned_in_smp;

/**
 * struct iwl_mld_low_latency - Manage low-latency detection and activation
 * @work: Monitors the number of voice and video packets transmitted and
 *	received over a period to detect low-latency. If the threshold is met,
 *	low-latency is activated. If the threshold is not met within a
 *	10-second period while active, it will be deactivated
 * @timestamp: timestamp of the last execution of &work
 * @window_start: per-mac, timestamp of the start of the current window. when
 *	the window is over, the counters are reset.
 * @pkts_counters: per-queue array voice/video packet counters
 * @result: per-mac latest low-latency result
 */
struct iwl_mld_low_latency {
	struct wiphy_delayed_work work;
	unsigned long timestamp;
	unsigned long window_start[NUM_MAC_INDEX_DRIVER];
	struct iwl_mld_low_latency_packets_counters *pkts_counters;
	bool result[NUM_MAC_INDEX_DRIVER];
};

int iwl_mld_low_latency_init(struct iwl_mld *mld);
void iwl_mld_low_latency_exit(struct iwl_mld *mld);
void iwl_mld_low_latency_free(struct iwl_mld *mld);
void iwl_mld_low_latency_restart_cleanup(struct iwl_mld *mld);

#endif /* __iwl_mld_low_latency_h__ */
