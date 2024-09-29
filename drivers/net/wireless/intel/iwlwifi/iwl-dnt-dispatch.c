// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2014, 2018, 2021, 2022, 2024 Intel Corporation
 * Copyright (C) 2014 Intel Mobile Communications GmbH
 * Copyright (C) 2015-2016 Intel Deutschland GmbH
 */
#include <linux/types.h>
#include <linux/export.h>
#include <linux/vmalloc.h>

#include "iwl-debug.h"
#include "iwl-dnt-cfg.h"
#include "iwl-dnt-dispatch.h"
#include "iwl-dnt-dev-if.h"
#include "iwl-tm-infc.h"
#include "iwl-tm-gnl.h"
#include "iwl-io.h"
#include "fw/error-dump.h"


struct dnt_collect_db *iwl_dnt_dispatch_allocate_collect_db(struct iwl_dnt *dnt)
{
	struct dnt_collect_db *db;

	db = kzalloc(sizeof(struct dnt_collect_db), GFP_KERNEL);
	if (!db) {
		dnt->iwl_dnt_status |= IWL_DNT_STATUS_FAILED_TO_ALLOCATE_DB;
		return NULL;
	}

	spin_lock_init(&db->db_lock);
	init_waitqueue_head(&db->waitq);

	return db;
}

static void iwl_dnt_dispatch_free_collect_db(struct dnt_collect_db *db)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(db->collect_array); i++)
		kfree(db->collect_array[i].data);

	kfree(db);
}

static int iwl_dnt_dispatch_get_list_data(struct dnt_collect_db *db,
					   u8 *buffer, u32 buffer_size)
{
	struct dnt_collect_entry *cur_entry;
	int data_offset = 0;

	spin_lock_bh(&db->db_lock);
	while (db->read_ptr != db->wr_ptr) {
		cur_entry = &db->collect_array[db->read_ptr];
		if (data_offset + cur_entry->size > buffer_size)
			break;
		memcpy(buffer + data_offset, cur_entry->data, cur_entry->size);
		data_offset += cur_entry->size;
		cur_entry->size = 0;
		kfree(cur_entry->data);
		cur_entry->data = NULL;

		/* increment read_ptr */
		db->read_ptr = (db->read_ptr + 1) % IWL_DNT_ARRAY_SIZE;
	}
	spin_unlock_bh(&db->db_lock);
	return data_offset;
}

/*
 * iwl_dnt_dispatch_push_ftrace_handler - handles data ad push it to ftrace.
 */
static void iwl_dnt_dispatch_push_ftrace_handler(struct iwl_dnt *dnt,
						 u8 *buffer, u32 buffer_size)
{
	trace_iwlwifi_dev_dnt_data(dnt->dev, buffer, buffer_size);
}

/*
 * iwl_dnt_dispatch_push_netlink_handler - handles data ad push it to netlink.
 */
static int iwl_dnt_dispatch_push_netlink_handler(struct iwl_dnt *dnt,
						 struct iwl_trans *trans,
						 unsigned int cmd_id,
						 u8 *buffer, u32 buffer_size)
{
	return iwl_tm_gnl_send_msg(trans, cmd_id, false, buffer, buffer_size,
				   GFP_ATOMIC);
}

static int iwl_dnt_dispatch_pull_monitor(struct iwl_dnt *dnt,
					 struct iwl_trans *trans, u8 *buffer,
					 u32 buffer_size)
{
	int ret = 0;

	if (dnt->cur_mon_type == INTERFACE)
		ret = iwl_dnt_dispatch_get_list_data(dnt->dispatch.dbgm_db,
						     buffer, buffer_size);
	else
		ret = iwl_dnt_dev_if_retrieve_monitor_data(dnt, trans, buffer,
							   buffer_size);
	return ret;
}

int iwl_dnt_dispatch_pull(struct iwl_trans *trans, u8 *buffer, u32 buffer_size,
			  u32 input)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;
	int ret = 0;

	if (!trans->op_mode)
		return -EINVAL;

	switch (input) {
	case MONITOR:
		ret = iwl_dnt_dispatch_pull_monitor(dnt, trans, buffer,
						    buffer_size);
		break;
	case UCODE_MESSAGES:
		ret = iwl_dnt_dispatch_get_list_data(dnt->dispatch.um_db,
						     buffer, buffer_size);
		break;
	default:
		WARN_ONCE(1, "Invalid input mode %d\n", input);
		return -EINVAL;
	}

	return ret;
}

static int iwl_dnt_dispatch_collect_data(struct iwl_dnt *dnt,
					 struct dnt_collect_db *db,
					 struct iwl_rx_packet *pkt)
{
	struct dnt_collect_entry *wr_entry;
	u32 data_size;

	data_size = GET_RX_PACKET_SIZE(pkt);
	spin_lock(&db->db_lock);
	wr_entry = &db->collect_array[db->wr_ptr];

	/*
	 * cheking if wr_ptr is already in use
	 * if so it means that we complete a cycle in the array
	 * hence replacing data in wr_ptr
	 */
	if (WARN_ON_ONCE(wr_entry->data)) {
		spin_unlock(&db->db_lock);
		return -ENOMEM;
	}

	wr_entry->size = data_size;
	wr_entry->data = kzalloc(data_size, GFP_ATOMIC);
	if (!wr_entry->data) {
		spin_unlock(&db->db_lock);
		return -ENOMEM;
	}

	memcpy(wr_entry->data, pkt->data, wr_entry->size);
	db->wr_ptr = (db->wr_ptr + 1) % IWL_DNT_ARRAY_SIZE;

	if (db->wr_ptr == db->read_ptr) {
		/*
		 * since we overrun oldest data we should update read
		 * ptr to the next oldest data
		 */
		struct dnt_collect_entry *rd_entry =
			&db->collect_array[db->read_ptr];

		kfree(rd_entry->data);
		rd_entry->data = NULL;
		db->read_ptr = (db->read_ptr + 1) % IWL_DNT_ARRAY_SIZE;
	}
	wake_up_interruptible(&db->waitq);
	spin_unlock(&db->db_lock);

	return 0;
}

int iwl_dnt_dispatch_collect_ucode_message(struct iwl_trans *trans,
					   struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_dnt_dispatch *dispatch;
	struct dnt_collect_db *db;
	int data_size;

	dispatch = &dnt->dispatch;
	db = dispatch->um_db;

	if (dispatch->ucode_msgs_in_mode != COLLECT)
		return 0;

	if (dispatch->ucode_msgs_out_mode != PUSH)
		return iwl_dnt_dispatch_collect_data(dnt, db, pkt);

	data_size = GET_RX_PACKET_SIZE(pkt);
	if (dispatch->ucode_msgs_output == FTRACE)
		iwl_dnt_dispatch_push_ftrace_handler(dnt, pkt->data, data_size);
	else if (dispatch->ucode_msgs_output == NETLINK)
		iwl_dnt_dispatch_push_netlink_handler(dnt, trans,
				IWL_TM_USER_CMD_NOTIF_UCODE_MSGS_DATA,
				pkt->data, data_size);

	return 0;
}
IWL_EXPORT_SYMBOL(iwl_dnt_dispatch_collect_ucode_message);

void iwl_dnt_dispatch_free(struct iwl_dnt *dnt, struct iwl_trans *trans)
{
	struct iwl_dnt_dispatch *dispatch = &dnt->dispatch;
	struct dnt_crash_data *crash = &dispatch->crash;

	if (dispatch->dbgm_db)
		iwl_dnt_dispatch_free_collect_db(dispatch->dbgm_db);
	if (dispatch->um_db)
		iwl_dnt_dispatch_free_collect_db(dispatch->um_db);

	if (dnt->mon_buf_cpu_addr)
		dma_free_coherent(trans->dev, dnt->mon_buf_size,
				  dnt->mon_buf_cpu_addr, dnt->mon_dma_addr);

	if (crash->sram)
		vfree(crash->sram);
	if (crash->rx)
		vfree(crash->rx);
	if (crash->dbgm)
		vfree(crash->dbgm);

	memset(dispatch, 0, sizeof(*dispatch));
}
