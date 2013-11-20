/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2014 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2014 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/export.h>

#include "iwl-drv.h"
#include "iwl-config.h"
#include "iwl-debug.h"
#include "iwl-tm-gnl.h"
#include "iwl-dnt-cfg.h"
#include "iwl-dnt-dispatch.h"
#include "iwl-dnt-dev-if.h"

static bool iwl_dnt_configure_prepare_dma(struct iwl_dnt *dnt,
					  struct iwl_trans *trans)
{
	struct iwl_usr_cfg *usr_cfg = &trans->tmdev->usr_cfg;

	if (usr_cfg->dbm_destination_path != DMA || !usr_cfg->dbgm_mem_power)
		return true;

	dnt->mon_buf_size = 0x800 << usr_cfg->dbgm_mem_power;
	dnt->mon_buf_cpu_addr =
		dma_alloc_coherent(trans->dev, dnt->mon_buf_size,
				   &dnt->mon_dma_addr, GFP_KERNEL);
	if (!dnt->mon_buf_cpu_addr)
		return false;

	dnt->mon_base_addr = (u64) dnt->mon_dma_addr;
	dnt->mon_end_addr = dnt->mon_base_addr + dnt->mon_buf_size;
	return true;
}

static int iwl_dnt_conf_monitor(struct iwl_trans *trans, u32 output,
				u32 monitor_type, u32 target_mon_mode)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;

	if (dnt->cur_input_mask & MONITOR_INPUT_MODE_MASK) {
		IWL_INFO(trans, "DNT: Resetting deivce configuration\n");
		return iwl_dnt_dev_if_configure_monitor(dnt, trans);
	}

	dnt->cur_input_mask |= MONITOR;
	dnt->dispatch.mon_output = output;
	dnt->cur_mon_type = monitor_type;
	dnt->cur_mon_mode = target_mon_mode;
	if (monitor_type == INTERFACE) {
		if (output == NETLINK || output == FTRACE) {
			/* setting PUSH out mode */
			dnt->dispatch.mon_out_mode = PUSH;
			dnt->dispatch.mon_in_mode = COLLECT;
		} else {
			dnt->dispatch.dbgm_db =
				iwl_dnt_dispatch_allocate_collect_db(dnt);
			if (!dnt->dispatch.dbgm_db)
				return -ENOMEM;
			dnt->dispatch.mon_in_mode = RETRIEVE;
		}
	} else {
		dnt->dispatch.mon_out_mode = PULL;
		dnt->dispatch.mon_in_mode = RETRIEVE;
	}
	return iwl_dnt_dev_if_configure_monitor(dnt, trans);
}

void iwl_dnt_start(struct iwl_trans *trans)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;
	struct iwl_usr_cfg *usr_cfg = &trans->tmdev->usr_cfg;

	if (!dnt)
		return;

	if (dnt->mon_configured && usr_cfg->dbg_conf_monitor_cmd_id)
		iwl_dnt_dev_if_start_monitor(dnt, trans);

	if ((dnt->cur_input_mask & UCODE_MESSAGES) && usr_cfg->log_level_cmd_id)
		iwl_dnt_dev_if_set_log_level(dnt, trans);
}
IWL_EXPORT_SYMBOL(iwl_dnt_start);

int iwl_dnt_conf_ucode_msgs_via_rx(struct iwl_trans *trans, u32 output)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;

	if (!dnt)
		return -EINVAL;

	dnt->cur_input_mask |= UCODE_MESSAGES;
	dnt->dispatch.ucode_msgs_output = output;

	if (output == NETLINK || output == FTRACE) {
		/* setting PUSH out mode */
		dnt->dispatch.ucode_msgs_out_mode = PUSH;
	} else {
		dnt->dispatch.um_db =
				iwl_dnt_dispatch_allocate_collect_db(dnt);
		if (!dnt->dispatch.um_db)
			return -ENOMEM;
		dnt->dispatch.ucode_msgs_out_mode = RETRIEVE;
	}
	/* setting COLLECT in mode */
	dnt->dispatch.ucode_msgs_in_mode = COLLECT;

	return 0;
}

void iwl_dnt_init(struct iwl_trans *trans)
{
	struct iwl_dnt *dnt;
	bool ret;

	dnt = kzalloc(sizeof(struct iwl_dnt), GFP_KERNEL);
	if (!dnt)
		return;

	trans->tmdev->dnt = dnt;

	dnt->cfg = &trans->tmdev->usr_cfg;
	dnt->dev = trans->dev;

	/* allocate DMA if needed */
	ret = iwl_dnt_configure_prepare_dma(dnt, trans);
	if (!ret)
		IWL_ERR(trans, "Failed to prepare DMA\n");
}
IWL_EXPORT_SYMBOL(iwl_dnt_init);

void iwl_dnt_free(struct iwl_trans *trans)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;

	if (!dnt)
		return;

	iwl_dnt_dispatch_free(dnt, trans);
	kfree(dnt);
}
IWL_EXPORT_SYMBOL(iwl_dnt_free);

void iwl_dnt_configure(struct iwl_trans *trans)
{
	struct iwl_dnt *dnt = trans->tmdev->dnt;
	struct iwl_usr_cfg *usr_cfg = &trans->tmdev->usr_cfg;

	if (!dnt)
		return;

	switch (usr_cfg->dbm_destination_path) {
	case DMA:
		if (!dnt->mon_buf_cpu_addr) {
			IWL_ERR(trans, "DMA buffer wasn't allocated\n");
			return;
		}
	case NO_MONITOR:
	case MIPI:
	case INTERFACE:
	case ICCM:
	case MARBH:
		iwl_dnt_conf_monitor(trans, usr_cfg->dnt_out_mode,
				     usr_cfg->dbm_destination_path,
				     usr_cfg->dbgm_enable_mode);
		break;
	default:
		IWL_INFO(trans, "Invalid monitor type\n");
		return;
	}
}
IWL_EXPORT_SYMBOL(iwl_dnt_configure);
