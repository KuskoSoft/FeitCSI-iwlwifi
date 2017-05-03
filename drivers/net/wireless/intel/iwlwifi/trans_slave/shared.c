/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2013 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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

#include <linux/module.h>
#include <linux/pm_runtime.h>
#include "iwl-devtrace.h"
#include "shared.h"
#include "iwl-op-mode.h"
#include "iwl-constants.h"
/* FIXME: need to abstract out TX command (once we know what it looks like) */
#include "mvm/fw-api.h"

/* FIXME: change values to be unique for each bus? */
#define IWL_SLV_TX_Q_HIGH_THLD 320
#define IWL_SLV_TX_Q_LOW_THLD 256

/* AL memory pool manager, must be called from a locked context. */

/**
 * iwl_slv_al_mem_pool_init - initialize pool manager
 * @pm - corresponding pool manager
 * @num_elems - number of the elements
 * Returns 0 upon success, negative error otherwise
 */
int iwl_slv_al_mem_pool_init(struct iwl_slv_al_mem_pool *pm, u16 num_elems)
{

	if (WARN_ON(pm == NULL))
		return -EINVAL;

	pm->used = kzalloc(BITS_TO_LONGS(num_elems) * sizeof(unsigned long),
			   GFP_KERNEL);
	if (WARN_ON(pm->used == NULL))
		return -EINVAL;

	pm->pool_size = num_elems;
	pm->free_count = num_elems;

	return 0;
}

void iwl_slv_al_mem_pool_deinit(struct iwl_slv_al_mem_pool *pm)
{
	if (pm) {
		kfree(pm->used);
		pm->used = NULL;
	}
}

#define BUFSZ 256
#define ADD_TEXT(...) pos += scnprintf(buf + pos, BUFSZ - pos, __VA_ARGS__)

/*
 * pick q with min occupied tfds
 */
int iwl_slv_get_next_queue(struct iwl_trans_slv *trans_slv)
{
	struct iwl_trans *trans = IWL_TRANS_SLV_GET_IWL_TRANS(trans_slv);
	int i, minq = -1;
	int cmd_queue = trans_slv->cmd_queue;
	int used, minused = INT_MAX;
	int waiting;
	char buf[BUFSZ];
	int pos = 0;

	memset(buf, 0, BUFSZ);

	ADD_TEXT("QUEUES: ");
	spin_lock_bh(&trans_slv->txq_lock);

	/* hcmd first */
	if (!list_empty(&trans_slv->txqs[cmd_queue].waiting)) {
		spin_unlock_bh(&trans_slv->txq_lock);
		return cmd_queue;
	}

	for (i = 0; i < trans_slv->config.max_queues_num; i++) {
		struct iwl_slv_tx_queue *txq = &trans_slv->txqs[i];

		used = atomic_read(&txq->sent_count);
		waiting = atomic_read(&txq->waiting_count);
		if ((used != 0) || (waiting != 0))
			ADD_TEXT("%d:[%d|%d] ", i, waiting, used);

		if (list_empty(&txq->waiting))
			continue;
		if (minq < 0 || used < minused) {
			minq = i;
			minused = used;
		}
	}

	spin_unlock_bh(&trans_slv->txq_lock);

	IWL_DEBUG_TX(trans, "%s\n", buf);
	IWL_DEBUG_TX(trans, "minq %d\n", minq);
	return minq;
}

/**
 * iwl_slv_pool_mgr_alloc - allocate item from the pool and return its index.
 * @trans_slv - the transport
 * @pm - corresponding pool manager
 * Returns index upon success, negative error otherwise
 */
int iwl_slv_al_mem_pool_alloc(struct iwl_trans_slv_tx *slv_tx,
			      struct iwl_slv_al_mem_pool *pm)
{
	u16 i;

	lockdep_assert_held(&slv_tx->mem_rsrc_lock);

	i = find_first_zero_bit(pm->used, pm->pool_size);

	if (WARN_ON(i >= pm->pool_size))
		return -EINVAL;

	pm->free_count--;
	set_bit(i, pm->used);

	return i;
}

/**
 * iwl_slv_al_mem_pool_alloc_range -
 * Allocate a range from the pool and return its index.
 * @order - region size (log base 2 of number of bits) to find
 * Returns index upon success, negative error otherwise
 */
int iwl_slv_al_mem_pool_alloc_range(struct iwl_trans_slv_tx *slv_tx,
			      struct iwl_slv_al_mem_pool *pm, u8 order)
{
	int i;

	lockdep_assert_held(&slv_tx->mem_rsrc_lock);

	i = bitmap_find_free_region(pm->used, pm->pool_size, order);

	if (i >= 0)
		pm->free_count -= 1 << order;

	return i;
}

/**
 * iwl_slv_al_pool_mgr_free - free item according to index
 * @trans_slv - the transport
 * @pm - corresponding pool manager
 * @idx - the index of the item to free
 * Returns 0 upon success, negative error otherwise
 */
int iwl_slv_al_mem_pool_free(struct iwl_trans_slv_tx *slv_tx,
			     struct iwl_slv_al_mem_pool *pm, u16 idx)
{
	lockdep_assert_held(&slv_tx->mem_rsrc_lock);

	/* Check that the index is legal and was allocated */
	if (WARN_ON(idx >= pm->pool_size || !test_bit(idx, pm->used)))
		return -EINVAL;

	__clear_bit(idx, pm->used);
	pm->free_count++;

	return 0;
}

/**
 * iwl_slv_al_mem_pool_free_region - free region starting index
 * @trans_slv - the transport
 * @pm - corresponding pool manager
 * @idx - the starting index of the region to free
 * @order - region size (log base 2 of number of bits) to free
 * Returns 0 upon success, negative error otherwise
 */
int iwl_slv_al_mem_pool_free_region(struct iwl_trans_slv_tx *slv_tx,
			     struct iwl_slv_al_mem_pool *pm, u16 idx, u8 order)
{
	lockdep_assert_held(&slv_tx->mem_rsrc_lock);

	/* Check that the index is in range */
	if (WARN_ON((idx + (1 << order)) >= pm->pool_size))
		return -EINVAL;

	bitmap_release_region(pm->used, idx, order);
	pm->free_count += 1 << order;

	return 0;
}


static bool iwl_slv_skip_txq_entry(struct iwl_trans_slv *trans_slv,
				   struct iwl_slv_txq_entry *txq_entry,
				   u8 txq_id)
{
	struct iwl_trans *trans = IWL_TRANS_SLV_GET_IWL_TRANS(trans_slv);
	struct iwl_slv_tx_cmd_entry *cmd_entry;
	bool is_cmd = txq_id == trans_slv->cmd_queue;

	if (test_bit(STATUS_TRANS_GOING_IDLE, &trans->status)) {
		if (!is_cmd)
			return true;

		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		if (!(cmd_entry->hcmd_meta.flags & CMD_SEND_IN_IDLE))
			return true;
	}

	if (test_bit(STATUS_TRANS_IDLE, &trans->status)) {
		if (!is_cmd)
			return true;

		/* When the trans is idle, only wake up commands are allowed */
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		if (!(cmd_entry->hcmd_meta.flags & CMD_WAKE_UP_TRANS))
			return true;
	}

	return false;
}

struct iwl_slv_txq_entry *iwl_slv_txq_pop_entry(
					struct iwl_trans_slv *trans_slv,
					u8 txq_id)
{
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[txq_id];
	struct iwl_slv_txq_entry *txq_entry = NULL;

	spin_lock_bh(&trans_slv->txq_lock);

	if (list_empty(&txq->waiting))
		goto exit;

	txq_entry = list_first_entry(&txq->waiting, struct iwl_slv_txq_entry,
				     list);
	if (iwl_slv_skip_txq_entry(trans_slv, txq_entry, txq_id)) {
		IWL_DEBUG_RPM(IWL_TRANS_SLV_GET_IWL_TRANS(trans_slv),
			      "skip cmd. wait for d0i3 exit\n");
		txq_entry = NULL;
		goto exit;
	}

	list_del(&txq_entry->list);
	atomic_dec(&txq->waiting_count);

exit:
	spin_unlock_bh(&trans_slv->txq_lock);
	return txq_entry;
}

void iwl_slv_txq_pushback_entry(struct iwl_trans_slv *trans_slv, u8 txq_id,
		      struct iwl_slv_txq_entry *txq_entry)
{
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[txq_id];

	spin_lock_bh(&trans_slv->txq_lock);

	list_add(&txq_entry->list, &txq->waiting);
	atomic_inc(&txq->waiting_count);

	spin_unlock_bh(&trans_slv->txq_lock);
}

void iwl_slv_txq_add_to_sent(struct iwl_trans_slv *trans_slv, u8 txq_id,
			      struct iwl_slv_txq_entry *txq_entry)
{
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[txq_id];

	spin_lock_bh(&trans_slv->txq_lock);

	list_add_tail(&txq_entry->list, &txq->sent);
	atomic_inc(&txq->sent_count);

	spin_unlock_bh(&trans_slv->txq_lock);

	if (trans_slv->cmd_queue != txq_id) {
		struct iwl_trans *trans = IWL_TRANS_SLV_GET_IWL_TRANS(trans_slv);
		struct iwl_slv_tx_data_entry *data_entry;
		struct iwl_slv_tx_dtu_meta *dtu;
		struct ieee80211_hdr *hdr;
		u8 hdr_len;

		IWL_SLV_TXQ_GET_ENTRY(txq_entry, data_entry);
		dtu = &data_entry->txq_entry.dtu_meta;

		hdr = (struct ieee80211_hdr *)data_entry->skb->data;
		hdr_len = ieee80211_hdrlen(hdr->frame_control);

		trace_iwlwifi_dev_tx(trans->dev,
				     data_entry->skb, NULL, 0,
				     dtu->chunk_info[0].addr,
				     dtu->chunk_info[0].len,
				     hdr_len);

		trace_iwlwifi_dev_tx_data(trans->dev, data_entry->skb, hdr_len);
	}
}

/**
 * iwl_slv_tx_stop - stop tx, don't free resources yet.
 */
void iwl_slv_tx_stop(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	if (WARN(!trans_slv->policy_wq,
		 "trans_slv->policy_wq is NULL. stop before init is done?")) {
		return;
	}
	cancel_work_sync(&trans_slv->policy_trigger);
	flush_workqueue(trans_slv->policy_wq);
}

static inline void iwl_slv_tx_destroy_caches(struct iwl_trans_slv *trans_slv)
{
	if (trans_slv->cmd_entry_pool) {
		kmem_cache_destroy(trans_slv->cmd_entry_pool);
		trans_slv->cmd_entry_pool = NULL;
	}

	if (trans_slv->data_entry_pool) {
		kmem_cache_destroy(trans_slv->data_entry_pool);
		trans_slv->data_entry_pool = NULL;
	}
}

static int iwl_slv_tx_alloc_caches(struct iwl_trans_slv *trans_slv)
{
	int hcmd_entry_size;

	/* cmd_entry has a bus specific field which contains the dev_cmd  */
	hcmd_entry_size = sizeof(struct iwl_slv_tx_cmd_entry) +
			  sizeof(struct iwl_device_cmd);

	trans_slv->cmd_entry_pool =
		kmem_cache_create("iwl_slv_cmd_entry",
				  hcmd_entry_size, sizeof(void *), 0, NULL);

	if (unlikely(!trans_slv->cmd_entry_pool))
		goto error;

	trans_slv->data_entry_pool =
		kmem_cache_create("iwl_slv_data_entry",
				  sizeof(struct iwl_slv_tx_data_entry),
				  sizeof(void *), 0, NULL);

	if (unlikely(!trans_slv->data_entry_pool))
		goto error;

	return 0;

error:
	iwl_slv_tx_destroy_caches(trans_slv);
	return -ENOMEM;
}

static inline int iwl_slv_tx_alloc_queues(struct iwl_trans_slv *trans_slv)
{
	int size, i, ret;

	size = trans_slv->config.max_queues_num *
		sizeof(struct iwl_slv_tx_queue);
	trans_slv->txqs = kzalloc(size, GFP_KERNEL);
	if (!trans_slv->txqs)
		return -ENOMEM;

	ret = iwl_slv_tx_alloc_caches(trans_slv);
	if (ret)
		goto error_free;

	for (i = 0; i < trans_slv->config.max_queues_num; i++) {
		INIT_LIST_HEAD(&trans_slv->txqs[i].waiting);
		INIT_LIST_HEAD(&trans_slv->txqs[i].sent);
		atomic_set(&trans_slv->txqs[i].waiting_count, 0);
		atomic_set(&trans_slv->txqs[i].sent_count, 0);
		trans_slv->txqs[i].last_dtu_wrptr_inc = 0;
	}

	return 0;

error_free:
	kfree(trans_slv->txqs);
	trans_slv->txqs = NULL;

	return ret;
}

static bool iwl_slv_queues_are_empty(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int i, max_queues = trans_slv->config.max_queues_num;

	for (i = 0; i < max_queues; i++) {
		struct iwl_slv_tx_queue *txq = &trans_slv->txqs[i];

		if (atomic_read(&txq->waiting_count) ||
		    atomic_read(&txq->sent_count))
			return false;
	}

	return true;
}

static bool iwl_slv_recalc_rpm_ref(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	if (!iwl_slv_queues_are_empty(trans))
		return false;

	/* only unref if the shared layer took a ref in the first place */
	if (!__test_and_clear_bit(IWL_SLV_RPM_FLAG_REF_TAKEN,
				  &trans_slv->rpm_flags))
		return false;

	iwl_trans_unref(trans);
	return true;
}

static int iwl_slv_fw_enter_d0i3(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int ret;

	if (test_bit(STATUS_FW_ERROR, &trans->status))
		return 0;

	if (trans->state != IWL_TRANS_FW_ALIVE) {
		IWL_DEBUG_RPM(trans, "no fw - don't send d0i3 commands\n");
		return 0;
	}

	if (!trans->op_mode->ops->enter_d0i3)
		return 0;

	set_bit(STATUS_TRANS_GOING_IDLE, &trans->status);

	/* config the fw */
	ret = iwl_op_mode_enter_d0i3(trans->op_mode);
	if (ret == 1) {
		IWL_DEBUG_RPM(trans, "aborting d0i3 entrance\n");
		clear_bit(STATUS_TRANS_GOING_IDLE, &trans->status);
		/* trigger policy to handle commands that could be skipped while
		 * waiting d0i3 exit in case policy exists (meaning we got here
		 * not from flush of rpm_suspend_work) */
		if (trans_slv->policy_wq)
			queue_work(trans_slv->policy_wq,
				   &trans_slv->policy_trigger);
		return -EBUSY;
	}
	if (ret)
		goto err;

	ret = wait_event_timeout(trans_slv->d0i3_waitq,
				 test_bit(STATUS_TRANS_IDLE, &trans->status),
				 msecs_to_jiffies(IWL_TRANS_IDLE_TIMEOUT));
	if (!ret && !test_bit(STATUS_TRANS_IDLE, &trans->status)) {
		IWL_ERR(trans, "Timeout entering D0i3\n");
		ret = -ETIMEDOUT;
		goto err;
	}

	clear_bit(STATUS_TRANS_GOING_IDLE, &trans->status);
	if (!(IWL_D0I3_DEBUG & IWL_D0I3_DBG_KEEP_BUS) &&
	    trans_slv->config.release_bus) {
		ret = trans_slv->config.release_bus(trans);
		if (ret)
			goto err;
	}

	return 0;
err:
	clear_bit(STATUS_TRANS_GOING_IDLE, &trans->status);
	iwl_trans_fw_error(trans);
	return ret;
}

static int iwl_slv_fw_exit_d0i3(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int ret;

	/* sometimes a D0i3 entry is not followed through */
	if (!test_bit(STATUS_TRANS_IDLE, &trans->status))
		return 0;

	if (trans->state != IWL_TRANS_FW_ALIVE) {
		IWL_DEBUG_RPM(trans, "no fw - don't send d0i3 commands\n");
		return 0;
	}

	if (!trans->op_mode->ops->enter_d0i3)
		return 0;

	if (!(IWL_D0I3_DEBUG & IWL_D0I3_DBG_KEEP_BUS) &&
	    trans_slv->config.grab_bus) {
		ret = trans_slv->config.grab_bus(trans);
		if (ret)
			goto err;
	}

	/* config the fw */
	ret = iwl_op_mode_exit_d0i3(trans->op_mode);
	if (ret)
		goto err;

	/* we clear STATUS_TRANS_IDLE only when D0I3_END command is completed */

	ret = wait_event_timeout(trans_slv->d0i3_waitq,
				 !test_bit(STATUS_TRANS_IDLE, &trans->status),
				 msecs_to_jiffies(IWL_TRANS_IDLE_TIMEOUT));
	if (!ret && test_bit(STATUS_TRANS_IDLE, &trans->status)) {
		IWL_ERR(trans, "Timeout exiting D0i3\n");
		ret = -ETIMEDOUT;
		goto err;
	}

	queue_work(trans_slv->policy_wq, &trans_slv->policy_trigger);
	return 0;
err:
	clear_bit(STATUS_TRANS_IDLE, &trans->status);
	iwl_trans_fw_error(trans);
	return ret;
}

#ifdef CONFIG_PM_RUNTIME
static int iwl_slv_runtime_suspend(struct iwl_trans *trans)
{
	int ret;

	if (iwlwifi_mod_params.d0i3_disable)
		return 0;

	if (trans->runtime_pm_mode == IWL_PLAT_PM_MODE_D0I3) {
		ret = iwl_slv_fw_enter_d0i3(trans);
		if (ret)
			return ret;
	}

#ifdef CPTCFG_IWLMVM_WAKELOCK
	if (trans->dbg_cfg.wakelock_mode == IWL_WAKELOCK_MODE_IDLE &&
	    trans->state == IWL_TRANS_FW_ALIVE)
		wake_unlock(&IWL_TRANS_GET_SLV_TRANS(trans)->slv_wake_lock);
#endif

	return 0;
}

static int iwl_slv_runtime_resume(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv __maybe_unused =
				IWL_TRANS_GET_SLV_TRANS(trans);
	int ret = 0;

	if (iwlwifi_mod_params.d0i3_disable)
		return 0;

	if (trans->runtime_pm_mode == IWL_PLAT_PM_MODE_D0I3)
		ret = iwl_slv_fw_exit_d0i3(trans);

#ifdef CPTCFG_IWLMVM_WAKELOCK
	if (trans->dbg_cfg.wakelock_mode == IWL_WAKELOCK_MODE_IDLE &&
	    trans->state == IWL_TRANS_FW_ALIVE &&
	    !trans_slv->suspending)
		wake_lock(&trans_slv->slv_wake_lock);
#endif

	return ret;
}

struct iwl_slv_rpm_device {
	struct iwl_trans *trans;
	struct device dev;
};

static void iwl_slv_rpm_dev_release(struct device *dev)
{
	struct iwl_slv_rpm_device *rpm_dev =
			container_of(dev, struct iwl_slv_rpm_device, dev);

	kfree(rpm_dev);
}

static int iwl_slv_rpm_runtime_suspend(struct device *dev)
{
	struct iwl_slv_rpm_device *rpm_dev =
			container_of(dev, struct iwl_slv_rpm_device, dev);
	struct iwl_trans *trans = rpm_dev->trans;
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int ret;

	IWL_DEBUG_RPM(trans, "entering d0i3\n");
	ret = iwl_slv_runtime_suspend(trans);
	if (ret) {
		IWL_DEBUG_RPM(trans, "error entering d0i3: %d\n", ret);
		return ret;
	}
	pm_runtime_allow(trans_slv->host_dev);
	return 0;
}

static int iwl_slv_rpm_runtime_resume(struct device *dev)
{
	struct iwl_slv_rpm_device *rpm_dev =
			container_of(dev, struct iwl_slv_rpm_device, dev);
	struct iwl_trans *trans = rpm_dev->trans;
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	IWL_DEBUG_RPM(trans, "exiting d0i3\n");
	pm_runtime_forbid(trans_slv->host_dev);
	iwl_slv_runtime_resume(trans);
	return 0;
}

static int iwl_slv_rpm_runtime_idle(struct device *dev)
{
	struct iwl_slv_rpm_device *rpm_dev =
			container_of(dev, struct iwl_slv_rpm_device, dev);
	struct iwl_trans *trans = rpm_dev->trans;

	IWL_DEBUG_RPM(trans, "request d0i3\n");
	pm_request_autosuspend(dev);
	return -EBUSY;
}

#ifdef CONFIG_PM
static int iwl_slv_rpm_prepare(struct device *dev)
{
	struct iwl_slv_rpm_device *rpm_dev =
			container_of(dev, struct iwl_slv_rpm_device, dev);
	struct iwl_trans *trans = rpm_dev->trans;
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	/*
	 * mac80211 might ask us to perform various actions (e.g.
	 * remove all interfaces). however, the device might be in d0i3,
	 * and the runtime_suspend/resume callbacks won't get called
	 * as the pm workqueue is frozen.
	 *
	 * since the prepare() handler gets called before mac80211's suspend(),
	 * get out of d0i3 here (by calling pm_runtime_resume).
	 * we'll get back into d0i3 in iwl_trans_slv_suspend() (called
	 * after mac80211's suspend handler.
	 *
	 * set trans_slv->suspending to avoid taking wakelock during
	 * this process (which will abort the suspend)
	 *
	 * we have to use the .prepare() handler (rather than suspend),
	 * since our device is registered before the wiphy, but we
	 * want the handler to run before mac80211's suspend callback.
	 */
	IWL_DEBUG_RPM(trans, "call pm_runtime_resume - rpm counter: %d\n",
		      atomic_read(&trans->dev->power.usage_count));

	trans_slv->suspending = true;
	pm_runtime_resume(dev);
	trans_slv->suspending = false;

	return 0;
}
#endif

static const struct dev_pm_ops iwl_slv_rpm_pm_ops = {
	SET_RUNTIME_PM_OPS(iwl_slv_rpm_runtime_suspend,
			   iwl_slv_rpm_runtime_resume,
			   iwl_slv_rpm_runtime_idle)
#ifdef CONFIG_PM
	.prepare = iwl_slv_rpm_prepare,
#endif
};

static struct class iwl_slv_rpm_class = {
	.name = "iwl_slv_rpm_class",
	.owner = THIS_MODULE,
	.dev_release = iwl_slv_rpm_dev_release,
	.pm = &iwl_slv_rpm_pm_ops,
};

static struct device *iwl_slv_rpm_add_device(struct iwl_trans *trans)
{
	struct iwl_slv_rpm_device *rpm_dev;
	int ret;

	rpm_dev = kzalloc(sizeof(*rpm_dev), GFP_KERNEL);
	if (!rpm_dev)
		return ERR_PTR(-ENOMEM);

	rpm_dev->trans = trans;
	rpm_dev->dev.class = &iwl_slv_rpm_class;
	rpm_dev->dev.parent = trans->dev;
	dev_set_name(&rpm_dev->dev, "iwl_slv_rpm-%s", dev_name(trans->dev));

	ret = device_register(&rpm_dev->dev);
	if (ret) {
		put_device(&rpm_dev->dev);
		kfree(rpm_dev);
		return ERR_PTR(ret);
	}

	pm_runtime_set_active(&rpm_dev->dev);
	pm_runtime_set_autosuspend_delay(&rpm_dev->dev,
					 iwlwifi_mod_params.d0i3_entry_delay);
	pm_runtime_use_autosuspend(&rpm_dev->dev);
	pm_runtime_enable(&rpm_dev->dev);

	/* take initial reference */
	pm_runtime_get_sync(&rpm_dev->dev);

	return &rpm_dev->dev;
}

static void iwl_slv_rpm_del_device(struct device *dev)
{
	pm_runtime_put_noidle(dev);
	pm_runtime_disable(dev);
	device_unregister(dev);
}
#endif

#ifdef CPTCFG_MAC80211_LATENCY_MEASUREMENTS
void iwl_slv_tx_lat_add_ts_write(struct iwl_trans_slv *trans_slv,
				 u8 txq_id,
				 struct iwl_slv_txq_entry *txq_entry)
{
	s64 temp = ktime_to_ms(ktime_get());
	s64 ts_1;
	s64 diff;
	struct iwl_slv_tx_data_entry *data_entry;

	if (txq_id == trans_slv->cmd_queue)
		return;

	IWL_SLV_TXQ_GET_ENTRY(txq_entry, data_entry);

	ts_1 = ktime_to_ns(data_entry->skb->tstamp) >> 32;
	diff = temp - ts_1;
	ktime_to_ns(data_entry->skb->tstamp) += diff << 16;
}
#endif

void iwl_slv_free_data_queue(struct iwl_trans *trans, int txq_id)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq;
	struct iwl_slv_tx_data_entry *data_entry;
	struct iwl_slv_txq_entry *txq_entry, *tmp;

	if (WARN_ON(trans_slv == NULL || trans_slv->txqs == NULL))
		return;

	txq = &trans_slv->txqs[txq_id];

	spin_lock_bh(&trans_slv->txq_lock);

	/* waiting queue - no need to handle DTU memory */
	list_for_each_entry_safe(txq_entry, tmp, &txq->waiting, list) {
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, data_entry);
		iwl_op_mode_free_skb(trans->op_mode, data_entry->skb);
		kmem_cache_free(trans_slv->data_entry_pool, data_entry);
	}
	atomic_set(&txq->waiting_count, 0);
	INIT_LIST_HEAD(&txq->waiting);

	/* sent queue - need to free DTU memory */
	list_for_each_entry_safe(txq_entry, tmp, &txq->sent, list) {
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, data_entry);
		trans_slv->config.free_dtu_mem(trans, &txq_entry->reclaim_info);
		iwl_op_mode_free_skb(trans->op_mode, data_entry->skb);
		kmem_cache_free(trans_slv->data_entry_pool, data_entry);
	}
	atomic_set(&txq->sent_count, 0);
	INIT_LIST_HEAD(&txq->sent);

	/* just in case the queue was stopped */
	if (test_and_clear_bit(txq_id, trans_slv->queue_stopped_map)) {
		iwl_op_mode_queue_not_full(trans->op_mode, txq_id);
		IWL_DEBUG_TX(trans, "wake %d\n", txq_id);
	}

	iwl_slv_recalc_rpm_ref(trans);
	spin_unlock_bh(&trans_slv->txq_lock);
}

static inline
void iwl_slv_free_cmd_entry(struct iwl_trans *trans,
			    struct iwl_slv_tx_cmd_entry *cmd_entry)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	trans_slv->config.clean_dtu(trans, cmd_entry->txq_entry.reclaim_info);

	kfree(cmd_entry->hcmd_meta.dup_buf);
	cmd_entry->hcmd_meta.dup_buf = NULL;
	kmem_cache_free(trans_slv->cmd_entry_pool, cmd_entry);
}

/**
* iwl_slv_free_queues - free data in all queues.
*
* Locking - this function should be called after AL is stopped, so no DMA
* interrupts can occur at this stage; op_mode also will not send new
* data/command at this stage. All workers should be stopped before this call.
* Thus, no locking is required here.
*/
static void iwl_slv_free_queues(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq;
	struct iwl_slv_tx_cmd_entry *cmd_entry;
	struct iwl_slv_txq_entry *txq_entry, *tmp;
	int i;

	if (WARN_ON(trans_slv == NULL || trans_slv->txqs == NULL))
		return;

	txq = &trans_slv->txqs[trans_slv->cmd_queue];

	/* waiting command queue, not mapped addresses */
	list_for_each_entry_safe(txq_entry, tmp, &txq->waiting, list) {
		list_del(&txq_entry->list);
		atomic_dec(&txq->waiting_count);
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		iwl_slv_free_cmd_entry(trans, cmd_entry);
	}

	/* sent command queue, need to check if mapped and then unmap */
	list_for_each_entry_safe(txq_entry, tmp, &txq->sent, list) {
		list_del(&txq_entry->list);
		atomic_dec(&txq->sent_count);
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		iwl_slv_free_cmd_entry(trans, cmd_entry);
	}

	/* data queues */
	for (i = 0; i < trans_slv->config.max_queues_num; i++)
		if (i != trans_slv->cmd_queue)
			iwl_slv_free_data_queue(trans, i);

	iwl_slv_recalc_rpm_ref(trans);
	iwl_slv_tx_destroy_caches(trans_slv);

	kfree(trans_slv->txqs);
	trans_slv->txqs = NULL;
}

/**
 * iwl_slv_stop - stop slv
 *
 * (free resources allocated during slv start), assumes tx is stopped.
 */
void iwl_slv_stop(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	if (WARN_ON_ONCE(!trans_slv))
		return;

#ifdef CPTCFG_IWLMVM_WAKELOCK
	wake_lock_destroy(&trans_slv->slv_wake_lock);
	wake_lock_destroy(&trans->ref_wake_lock);
	wake_lock_destroy(&trans->timed_wake_lock);
#endif

	iwl_slv_free_queues(trans);

	if (trans_slv->policy_wq) {
		destroy_workqueue(trans_slv->policy_wq);
		trans_slv->policy_wq = NULL;
	}
}

int iwl_slv_init(struct iwl_trans *trans)
{
#ifdef CONFIG_PM_RUNTIME
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int ret;

	trans_slv->d0i3_dev = iwl_slv_rpm_add_device(trans);
	if (IS_ERR(trans_slv->d0i3_dev)) {
		ret = PTR_ERR(trans_slv->d0i3_dev);
		trans_slv->d0i3_dev = NULL;
		return ret;
	}
#ifdef CPTCFG_IWLMVM_WAKELOCK
	/* We always unref before ref'ing at the beginning, to free
	 * the RTPM initial reference.  So set the wakelock reference
	 * count to 1 here, to acoount for that.
	 */
	trans->wakelock_count = 1;
#endif
#endif /* CONFIG_PM_RUNTIME */
	return 0;
}

void iwl_slv_destroy(struct iwl_trans *trans)
{
#ifdef CONFIG_PM_RUNTIME
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	if (trans_slv->d0i3_dev) {
		iwl_slv_rpm_del_device(trans_slv->d0i3_dev);
		trans_slv->d0i3_dev = NULL;
	}
#endif
}

int iwl_slv_start(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv;
	int ret;

	BUG_ON(!trans);
	trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	BUG_ON(!trans_slv);

	/* verify that the configure ops was called before init */
	if (WARN_ON_ONCE(!trans_slv->config.policy_trigger)) {
		ret = EINVAL;
		goto error;
	}

	spin_lock_init(&trans_slv->txq_lock);

	ret = iwl_slv_tx_alloc_queues(trans_slv);
	if (ret)
		goto error;

	/* Initialize the wait queue for commands */
	init_waitqueue_head(&trans_slv->wait_command_queue);

	init_waitqueue_head(&trans_slv->d0i3_waitq);

	/* initialize policy data */
	trans_slv->policy_wq = alloc_workqueue("slv_policy_wq",
					       WQ_HIGHPRI | WQ_UNBOUND, 1);
	INIT_WORK(&trans_slv->policy_trigger, trans_slv->config.policy_trigger);

#ifdef CPTCFG_IWLMVM_WAKELOCK
	/* The transport wakelock is locked on init. We only
	 * allow unlock when in d0i3 */
	wake_lock_init(&trans_slv->slv_wake_lock, WAKE_LOCK_SUSPEND,
		       "iwlwifi_trans_slv_wakelock");
	if (trans->dbg_cfg.wakelock_mode != IWL_WAKELOCK_MODE_OFF)
		wake_lock(&trans_slv->slv_wake_lock);

	spin_lock_init(&trans->ref_lock);
	wake_lock_init(&trans->ref_wake_lock, WAKE_LOCK_SUSPEND,
		       "iwlwifi_trans_ref_wakelock");
	wake_lock_init(&trans->timed_wake_lock, WAKE_LOCK_SUSPEND,
		       "iwlwifi_trans_timed_wakelock");
#endif

#ifdef CONFIG_PM_RUNTIME
	/* in case of previous error, reset power.runtime_error */
	pm_runtime_set_active(trans_slv->d0i3_dev);
#endif

	if (iwlwifi_mod_params.d0i3_disable)
		IWL_DEBUG_RPM(trans, "D0i3 transition disabled\n");

	return 0;
error:
	IWL_ERR(trans, "%s failed, ret %d\n", __func__, ret);
	return ret;
}

int iwl_slv_register_drivers(void)
{
	int ret;

#ifdef CONFIG_PM_RUNTIME
	/*
	 * register a new class because some older kernels
	 * don't support calling the runtime_pm callbacks
	 * of the device itself, but only those of the class/subsystem.
	 */
	ret = class_register(&iwl_slv_rpm_class);
	if (ret)
		return ret;
#endif
	ret = iwl_sdio_register_driver();
	if (ret)
		goto unregister_class;

	return 0;

unregister_class:
#ifdef CONFIG_PM_RUNTIME
	class_unregister(&iwl_slv_rpm_class);
#endif
	return ret;
}

void iwl_slv_unregister_drivers(void)
{
	iwl_sdio_unregister_driver();
#ifdef CONFIG_PM_RUNTIME
	class_unregister(&iwl_slv_rpm_class);
#endif
}

/* iwl_slv_tx_get_cmd_entry - get requested cmd entry */

static struct iwl_slv_tx_cmd_entry *
iwl_slv_tx_get_cmd_entry(struct iwl_trans *trans,
			 struct iwl_rx_packet *pkt)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[trans_slv->cmd_queue];
	u16 sequence = le16_to_cpu(pkt->hdr.sequence);
	int txq_id = SEQ_TO_QUEUE(sequence);
	struct iwl_slv_txq_entry *txq_entry, *tmp;
	struct iwl_device_cmd *dev_cmd;
	struct iwl_slv_tx_cmd_entry *cmd_entry = NULL;
	int cmd_list_idx;

	if (WARN(txq_id != trans_slv->cmd_queue,
		 "wrong command queue %d (should be %d), sequence 0x%X\n",
		 txq_id, trans_slv->cmd_queue, sequence)) {
		iwl_print_hex_error(priv, pkt, 32);
		return NULL;
	}

	/* FIXME - when not found? */
	spin_lock_bh(&trans_slv->txq_lock);

	if (WARN(list_empty(&txq->sent), "empty sent queue.\n")) {
		spin_unlock_bh(&trans_slv->txq_lock);
		return NULL;
	}

	cmd_list_idx = 0;
	list_for_each_entry_safe(txq_entry, tmp, &txq->sent, list) {
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		dev_cmd = iwl_cmd_entry_get_dev_cmd(trans_slv, cmd_entry);

		if (dev_cmd->hdr.sequence != pkt->hdr.sequence) {
			cmd_list_idx++;
			continue;
		}

		if (cmd_list_idx)
			IWL_WARN(trans, "%s not first entry, idx %d\n",
				 __func__, cmd_list_idx);

		list_del(&txq_entry->list);
		atomic_dec(&txq->sent_count);

		/* get out of the loop when the required command is found */
		break;
	}

	iwl_slv_recalc_rpm_ref(trans);
	spin_unlock_bh(&trans_slv->txq_lock);

	return cmd_entry;
}

/**
 * iwl_slv_tx_cmd_complete - handler for processing command response;
 * called from the Rx flow. DTU resources are freed in
 * iwl_slv_tx_get_cmd_entry.
 */
static void iwl_slv_tx_cmd_complete(struct iwl_trans *trans,
				    struct iwl_rx_cmd_buffer *rxcb,
				    struct iwl_slv_tx_cmd_entry *cmd_entry)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_device_cmd *dev_cmd;
	u32 cmd;

	if (WARN_ON(!cmd_entry)) {
		IWL_WARN(trans, "Invalid cmd entry\n");
		return;
	}

	if (cmd_entry->hcmd_meta.flags & CMD_WANT_SKB) {
		struct page *p;

		cmd_entry->hcmd_meta.source->resp_pkt = rxb_addr(rxcb);
		p = rxb_steal_page(rxcb);

		cmd_entry->hcmd_meta.source->_rx_page_addr =
					(unsigned long)page_address(p);
		cmd_entry->hcmd_meta.source->_rx_page_order =
					rxcb->_rx_page_order;
	}

	dev_cmd = iwl_cmd_entry_get_dev_cmd(trans_slv, cmd_entry);

	if (cmd_entry->hcmd_meta.flags & CMD_WANT_ASYNC_CALLBACK)
		iwl_op_mode_async_cb(trans->op_mode, dev_cmd);

	cmd = iwl_cmd_id(dev_cmd->hdr.cmd, dev_cmd->hdr.group_id, 0);

	if (!(cmd_entry->hcmd_meta.flags & CMD_ASYNC)) {
		if (!test_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status)) {
			IWL_WARN(trans,
				 "HCMD_ACTIVE already clear for command %s\n",
				 iwl_get_cmd_string(trans, cmd));
		}
		clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
		IWL_DEBUG_INFO(trans, "Clearing HCMD_ACTIVE for command %s\n",
			       iwl_get_cmd_string(trans, cmd));
		wake_up(&trans_slv->wait_command_queue);
	}

	if (cmd_entry->hcmd_meta.flags & CMD_MAKE_TRANS_IDLE) {
		IWL_DEBUG_INFO(trans, "complete %s - mark trans as idle\n",
			       iwl_get_cmd_string(trans, cmd));
		set_bit(STATUS_TRANS_IDLE, &trans->status);
		wake_up(&trans_slv->d0i3_waitq);
	}

	if (cmd_entry->hcmd_meta.flags & CMD_WAKE_UP_TRANS) {
		IWL_DEBUG_INFO(trans, "complete %s - clear trans idle flag\n",
			       iwl_get_cmd_string(trans, cmd));
		clear_bit(STATUS_TRANS_IDLE, &trans->status);
		wake_up(&trans_slv->d0i3_waitq);
	}

	iwl_slv_free_cmd_entry(trans, cmd_entry);
}

/**
 * iwl_trans_slv_tx_data_reclaim - free until ssn, not inclusive. Assuming that ssn
 * is always ahead of the sequence in sent queue.
 */
void iwl_trans_slv_tx_data_reclaim(struct iwl_trans *trans, int txq_id,
				   int ssn, struct sk_buff_head *skbs)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[txq_id];
	struct iwl_slv_tx_data_entry *data_entry;
	struct iwl_slv_txq_entry *txq_entry, *tmp;
	int idx, tfd_num = ssn & (trans_slv->config.queue_size - 1);
	u16 seq_ctrl;
	int freed = 0;

	IWL_DEBUG_TX_REPLY(trans, "reclaim: q %d, ssn %d, tfd %d\n",
			   txq_id, ssn, tfd_num);

	spin_lock_bh(&trans_slv->txq_lock);

	list_for_each_entry_safe(txq_entry, tmp, &txq->sent, list) {
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, data_entry);

		BUG_ON(data_entry->cmd == NULL);

		seq_ctrl = le16_to_cpu(data_entry->cmd->hdr.sequence);
		idx = SEQ_TO_INDEX(seq_ctrl);
		/* freeing up to ssn - not inclusive*/
		if (idx == tfd_num)
			break;

		__skb_queue_tail(skbs, data_entry->skb);

		list_del(&txq_entry->list);
		trans_slv->config.clean_dtu(trans, txq_entry->reclaim_info);
		kmem_cache_free(trans_slv->data_entry_pool, data_entry);
		freed++;
		atomic_dec(&txq->sent_count);
	}

	if ((atomic_read(&txq->waiting_count) < IWL_SLV_TX_Q_LOW_THLD) &&
	    test_and_clear_bit(txq_id, trans_slv->queue_stopped_map)) {
		iwl_op_mode_queue_not_full(trans->op_mode, txq_id);
		IWL_DEBUG_TX(trans, "wake %d\n", txq_id);
	}

	iwl_slv_recalc_rpm_ref(trans);

	spin_unlock_bh(&trans_slv->txq_lock);

	queue_work(trans_slv->policy_wq, &trans_slv->policy_trigger);

	IWL_DEBUG_TX_REPLY(trans, "reclaim: freed %d\n", freed);
}

static void iwl_slv_tx_copy_hcmd(struct iwl_device_cmd *out_cmd,
				 struct iwl_host_cmd *cmd)
{
	int i;
	u8 *cmd_dest;

	if (out_cmd->hdr_wide.group_id)
		cmd_dest = out_cmd->payload_wide;
	else
		cmd_dest = out_cmd->payload;

	for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
		if (!cmd->len[i])
			continue;
		if (cmd->dataflags[i] & (IWL_HCMD_DFL_NOCOPY |
					 IWL_HCMD_DFL_DUP))
			break;

		memcpy(cmd_dest, cmd->data[i], cmd->len[i]);
		cmd_dest += cmd->len[i];
	}
}

static int
iwl_slv_tx_set_meta_for_hcmd(struct iwl_trans *trans,
			     struct iwl_host_cmd *cmd,
			     struct iwl_slv_tx_cmd_entry *cmd_entry)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_hcmd_meta *hcmd_meta;
	struct iwl_slv_txq_entry *txq_entry = &cmd_entry->txq_entry;
	struct iwl_slv_tx_dtu_meta *dtu_meta = &txq_entry->dtu_meta;
	struct iwl_slv_tx_chunk_info *const chunk_info = dtu_meta->chunk_info;
	int i, idx, ret;
	int group_id = iwl_cmd_groupid(cmd->id);
	bool had_nocopy = false;
	bool had_dup = false;

	hcmd_meta = &cmd_entry->hcmd_meta;
	hcmd_meta->dup_buf = NULL;
	if (group_id != 0) {
		hcmd_meta->copy_size = sizeof(struct iwl_cmd_header_wide);
		hcmd_meta->hcmd_size = sizeof(struct iwl_cmd_header_wide);
	} else {
		hcmd_meta->copy_size = sizeof(struct iwl_cmd_header);
		hcmd_meta->hcmd_size = sizeof(struct iwl_cmd_header);
	}
	ret = 0;

	/* the first block is always the copied part of dev cmd */
	idx = 1;
	dtu_meta->chunks_num = 1;
	dtu_meta->total_desc_num = 0;
	dtu_meta->scd_byte_cnt = 0;

	for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
		if (!cmd->len[i])
			continue;

		if (cmd->dataflags[i] & IWL_HCMD_DFL_NOCOPY) {
			if (WARN_ON(cmd->dataflags[i] & IWL_HCMD_DFL_DUP)) {
				ret = -EINVAL;
				goto free_dup_buf;
			}
			had_nocopy = true;
			chunk_info[idx].addr = (u8 *)cmd->data[i];
		} else if (cmd->dataflags[i] & IWL_HCMD_DFL_DUP) {
			/* only allowed once */
			if (WARN_ON(had_dup)) {
				ret = -EINVAL;
				goto free_dup_buf;
			}
			had_dup = true;
			hcmd_meta->dup_buf = kmemdup(cmd->data[i],
						     cmd->len[i],
						     GFP_ATOMIC);
			if (!hcmd_meta->dup_buf)
				return -ENOMEM;
			chunk_info[idx].addr = hcmd_meta->dup_buf;
		} else {
			/* NOCOPY and DUP must not be followed by normal! */
			if (WARN_ON(had_nocopy || had_dup)) {
				ret = -EINVAL;
				goto free_dup_buf;
			}
			hcmd_meta->copy_size += cmd->len[i];
		}
		if (had_nocopy || had_dup) {
			chunk_info[idx].len = cmd->len[i];

			/* TXCs num for the current chunk */
			trans_slv->config.calc_desc_num(trans,
							&chunk_info[idx]);

			dtu_meta->total_len += chunk_info[idx].len;
			dtu_meta->total_desc_num += chunk_info[idx].desc_num;

			dtu_meta->chunks_num++;
			idx++;
		}
		hcmd_meta->hcmd_size += cmd->len[i];
	}

	/* set up the first chunk with the copied part */
	chunk_info[0].addr = (u8 *)iwl_cmd_entry_get_dev_cmd(trans_slv,
							     cmd_entry);
	chunk_info[0].len = hcmd_meta->copy_size;
	trans_slv->config.calc_desc_num(trans, &chunk_info[0]);

	dtu_meta->total_desc_num += chunk_info[0].desc_num;
	dtu_meta->total_len += chunk_info[0].len;

	/* If any of the command structures end up being larger than
	 * the TFD_MAX_PAYLOAD_SIZE and they aren't dynamically
	 * allocated into separate TFDs, then we will need to
	 * increase the size of the buffers.
	 */
	if (WARN_ON(hcmd_meta->copy_size > TFD_MAX_PAYLOAD_SIZE)) {
		ret = -EINVAL;
		goto free_dup_buf;
	}

	if (WARN(had_nocopy && (cmd->flags & CMD_ASYNC),
		 "Bad flags: 0x%x", cmd->flags)) {
		ret = -EINVAL;
		goto free_dup_buf;
	}

	hcmd_meta->flags = cmd->flags;
	if (cmd->flags & CMD_WANT_SKB) {
		WARN_ON(cmd->flags & CMD_ASYNC);
		hcmd_meta->source = cmd;
	}

	if (had_nocopy)
		hcmd_meta->source = cmd;

free_dup_buf:
	if (ret < 0)
		kfree(hcmd_meta->dup_buf);

	return ret;
}

/**
* iwl_slv_tx_enqueue_hcmd - add host command to the queue and
* trigger policy mechanism.
*/
static int iwl_slv_tx_enqueue_hcmd(struct iwl_trans *trans,
				   struct iwl_host_cmd *cmd)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq;
	struct iwl_slv_tx_cmd_entry *cmd_entry;
	struct iwl_device_cmd *dev_cmd;
	u16 seq_num;
	int ret;
	u8 group_id = iwl_cmd_groupid(cmd->id);
	u8 cmd_opcode = iwl_cmd_opcode(cmd->id);

	BUG_ON(!trans_slv->txqs);
	BUG_ON(!cmd);

	if (WARN(!trans->wide_cmd_header &&
		 group_id > IWL_ALWAYS_LONG_GROUP,
		 "unsupported wide command %#x\n", cmd->id))
		return -EINVAL;

	IWL_DEBUG_HC(trans, "Enqueue cmd %s (%.2x.%.2x), flags 0x%x\n",
		     iwl_get_cmd_string(trans, cmd->id),
		     group_id, cmd_opcode, cmd->flags);

	txq = &trans_slv->txqs[trans_slv->cmd_queue];
	cmd_entry = kmem_cache_alloc(trans_slv->cmd_entry_pool, GFP_ATOMIC);
	if (unlikely(!cmd_entry))
		return -ENOMEM;

	memset(cmd_entry, 0, sizeof(*cmd_entry));

	ret = iwl_slv_tx_set_meta_for_hcmd(trans, cmd, cmd_entry);
	if (ret) {
		IWL_ERR(trans, "%s (%d): get_hcmd_size failed\n",
			__func__, __LINE__);
		goto error_free;
	}
	dev_cmd = iwl_cmd_entry_get_dev_cmd(trans_slv, cmd_entry);

	if (group_id != 0) {
		dev_cmd->hdr_wide.cmd = iwl_cmd_opcode(cmd->id);
		dev_cmd->hdr_wide.group_id = group_id;
		dev_cmd->hdr_wide.version = iwl_cmd_version(cmd->id);
		dev_cmd->hdr_wide.length =
			cpu_to_le16(cmd_entry->hcmd_meta.hcmd_size -
				    sizeof(struct iwl_cmd_header_wide));
		dev_cmd->hdr_wide.reserved = 0;
	} else {
		dev_cmd->hdr.cmd = iwl_cmd_opcode(cmd->id);
		dev_cmd->hdr.group_id = 0;
	}

	iwl_slv_tx_copy_hcmd(dev_cmd, cmd);

	spin_lock_bh(&trans_slv->txq_lock);

	/* Take a reference if this is the first (not SEND_IN_IDLE) command */
	if (!(cmd->flags & CMD_SEND_IN_IDLE) &&
	    !__test_and_set_bit(IWL_SLV_RPM_FLAG_REF_TAKEN,
				&trans_slv->rpm_flags))
		iwl_trans_ref(trans);

	seq_num = txq->waiting_last_idx;
	dev_cmd->hdr.sequence =
		cpu_to_le16((u16)QUEUE_TO_SEQ(trans_slv->cmd_queue) |
			    INDEX_TO_SEQ(seq_num));

	ret = txq->waiting_last_idx;

	/* FIXME: wrapping */
	atomic_inc(&txq->waiting_count);
	txq->waiting_last_idx++;
	txq->waiting_last_idx &= (trans_slv->config.queue_size - 1);

	trace_iwlwifi_dev_hcmd(trans->dev, cmd, cmd_entry->hcmd_meta.hcmd_size,
			       &dev_cmd->hdr_wide);

	/* put high priority commands at the front of the queue, behind other
	 * high priority commands.
	 */
	if (cmd->flags & CMD_HIGH_PRIO) {
		struct iwl_slv_txq_entry *txq_entry;
		struct iwl_slv_tx_cmd_entry *queued_cmd;

		list_for_each_entry(txq_entry, &txq->waiting, list) {
			queued_cmd = list_entry(txq_entry,
				struct iwl_slv_tx_cmd_entry, txq_entry);

			if (!(queued_cmd->hcmd_meta.flags & CMD_HIGH_PRIO))
				break;
		}
		list_add_tail(&cmd_entry->txq_entry.list,
			      &txq_entry->list);
	} else {
		list_add_tail(&cmd_entry->txq_entry.list, &txq->waiting);
	}

	spin_unlock_bh(&trans_slv->txq_lock);
	queue_work(trans_slv->policy_wq, &trans_slv->policy_trigger);

	return ret;

error_free:
	kmem_cache_free(trans_slv->cmd_entry_pool, cmd_entry);
	return ret;
}

#define IWL_SLV_TX_CRC_SIZE 4
#define IWL_SLV_TX_DELIMITER_SIZE 4

static void iwl_slv_comp_bc(struct iwl_trans *trans,
			      struct iwl_slv_tx_dtu_meta *dtu_meta,
			      struct iwl_tx_cmd *tx_cmd)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	u16 len;

	len = le16_to_cpu(tx_cmd->len) +
			IWL_SLV_TX_CRC_SIZE +
			IWL_SLV_TX_DELIMITER_SIZE;

	switch (tx_cmd->sec_ctl & TX_CMD_SEC_MSK) {
	case TX_CMD_SEC_CCM:
		len += IEEE80211_CCMP_MIC_LEN;
		break;
	case TX_CMD_SEC_TKIP:
		len += IEEE80211_TKIP_ICV_LEN;
		break;
	case TX_CMD_SEC_WEP:
		len += IEEE80211_WEP_IV_LEN + IEEE80211_WEP_ICV_LEN;
		break;
	}

	if (trans_slv->bc_table_dword)
		len = DIV_ROUND_UP(len, 4);

	dtu_meta->scd_byte_cnt = cpu_to_le16(len | (tx_cmd->sta_id << 12));
}

static int
iwl_slv_tx_set_meta_for_data(struct iwl_trans *trans,
			     struct iwl_slv_tx_data_entry *data_entry,
			     struct iwl_slv_tx_dtu_meta *dtu_meta)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_tx_cmd *tx_cmd;
	struct ieee80211_hdr *hdr;
	u16 len, firstlen, secondlen, hdr_len;

	hdr = (struct ieee80211_hdr *)data_entry->skb->data;
	hdr_len = ieee80211_hdrlen(hdr->frame_control);
	tx_cmd = (struct iwl_tx_cmd *)data_entry->cmd->payload;

	/* compute overall lengths */
	len = sizeof(struct iwl_tx_cmd) +
		sizeof(struct iwl_cmd_header) + hdr_len;
	firstlen = ALIGN(len, 4);
	secondlen = data_entry->skb->len - hdr_len;

	/* Tell NIC about any 2-byte padding after MAC header */
	if (firstlen != len)
		tx_cmd->tx_flags |= cpu_to_le32(TX_CMD_FLG_MH_PAD);

	/* tx data contains at most two memory chunks */
	dtu_meta->chunks_num = 1;

	dtu_meta->chunk_info[0].addr = (u8 *)data_entry->cmd;
	dtu_meta->chunk_info[0].len = firstlen;
	trans_slv->config.calc_desc_num(trans, &dtu_meta->chunk_info[0]);

	if (secondlen) {
		dtu_meta->chunks_num++;
		dtu_meta->chunk_info[1].addr =
			data_entry->skb->data + hdr_len;
		dtu_meta->chunk_info[1].len = secondlen;
		trans_slv->config.calc_desc_num(trans,
						&dtu_meta->chunk_info[1]);
	}

	dtu_meta->total_desc_num =
		dtu_meta->chunk_info[0].desc_num +
		dtu_meta->chunk_info[1].desc_num;

	dtu_meta->total_len =
		dtu_meta->chunk_info[0].len +
		dtu_meta->chunk_info[1].len;

	if (WARN_ON(dtu_meta->total_len > 0xFFF)) {
		IWL_ERR(trans, "%s: length too big (%d)\n",
			__func__, dtu_meta->total_len);
		return -EINVAL;
	}

	iwl_slv_comp_bc(trans, dtu_meta, tx_cmd);

	return 0;
}

void iwl_trans_slv_tx_set_ssn(struct iwl_trans *trans, int txq_id, int ssn)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

	spin_lock_bh(&trans_slv->txq_lock);

	trans_slv->txqs[txq_id].waiting_last_idx =
		ssn & (trans_slv->config.queue_size - 1);

	spin_unlock_bh(&trans_slv->txq_lock);
}

/**
* iwl_trans_slv_tx_data_send - process header and add packet to the waiting queue.
*/
int iwl_trans_slv_tx_data_send(struct iwl_trans *trans, struct sk_buff *skb,
			       struct iwl_device_cmd *dev_cmd, int txq_id)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct iwl_slv_tx_queue *txq;
	struct iwl_slv_tx_data_entry *data_entry;
	u16 seq_num;

	BUG_ON(!trans_slv->txqs);
	BUG_ON(!skb);

	/* verify that this skb doesn't belong to any other queue */
	if (WARN_ON(skb->next != NULL || skb->prev != NULL)) {
		IWL_ERR(trans, "Invalid skb\n");
		return -EINVAL;
	}

	if (WARN_ON(txq_id >= trans_slv->config.max_queues_num)) {
		IWL_ERR(trans, "Invalid txq id (%d)\n", txq_id);
		return -EINVAL;
	}

	txq = &trans_slv->txqs[txq_id];
	data_entry = kmem_cache_alloc(trans_slv->data_entry_pool, GFP_ATOMIC);
	if (unlikely(!data_entry))
		return -ENOMEM;

	memset(data_entry, 0, sizeof(*data_entry));

	data_entry->skb = skb;
	data_entry->cmd = dev_cmd;

	iwl_slv_tx_set_meta_for_data(trans, data_entry,
				     &data_entry->txq_entry.dtu_meta);

	spin_lock_bh(&trans_slv->txq_lock);

	seq_num = txq->waiting_last_idx;
	dev_cmd->hdr.sequence = cpu_to_le16((u16)(QUEUE_TO_SEQ(txq_id) |
					    INDEX_TO_SEQ(seq_num)));

	IWL_DEBUG_TX(trans, "txq_id %d, seq %d, last_idx %d, sequence 0x%X\n",
		     txq_id, seq_num, txq->waiting_last_idx,
		     dev_cmd->hdr.sequence);

	list_add_tail(&data_entry->txq_entry.list, &txq->waiting);

	/* Take a reference if it's not already taken */
	if (!__test_and_set_bit(IWL_SLV_RPM_FLAG_REF_TAKEN,
				&trans_slv->rpm_flags))
		iwl_trans_ref(trans);

	atomic_inc(&txq->waiting_count);
	txq->waiting_last_idx++;
	txq->waiting_last_idx &= (trans_slv->config.queue_size - 1);

	/* FIXME: compute AC for agg */
	if (!ieee80211_has_morefrags(hdr->frame_control) &&
	    (atomic_read(&txq->waiting_count) > IWL_SLV_TX_Q_HIGH_THLD) &&
	    !test_and_set_bit(txq_id, trans_slv->queue_stopped_map)) {
		iwl_op_mode_queue_full(trans->op_mode, txq_id);
		IWL_DEBUG_TX(trans, "stop %d\n", txq_id);
	}

	spin_unlock_bh(&trans_slv->txq_lock);

	queue_work(trans_slv->policy_wq, &trans_slv->policy_trigger);
	return 0;
}

static int iwl_slv_send_cmd_async(struct iwl_trans *trans,
				struct iwl_host_cmd *cmd)
{
	int ret;

	/* An asynchronous command can not expect an SKB to be set. */
	if (WARN_ON(cmd->flags & CMD_WANT_SKB))
		return -EINVAL;

	ret = iwl_slv_tx_enqueue_hcmd(trans, cmd);
	if (ret < 0) {
		IWL_ERR(trans,
			"Error sending %s: enqueue_hcmd failed: %d\n",
			iwl_get_cmd_string(trans, cmd->id), ret);
		return ret;
	}
	return 0;
}

/**
* iwl_slv_tx_cancel_cmd - cancel command, but don't delete it yet in order
* not to confuse the command complete.
*/
static void iwl_slv_tx_cancel_cmd(struct iwl_trans *trans, int cmd_idx)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	struct iwl_slv_tx_queue *txq = &trans_slv->txqs[trans_slv->cmd_queue];
	struct iwl_slv_tx_cmd_entry *cmd_entry;
	struct iwl_device_cmd *dev_cmd;
	struct iwl_slv_txq_entry *txq_entry;
	__le16 sequence;

	sequence = cpu_to_le16(QUEUE_TO_SEQ(trans_slv->cmd_queue) |
			       INDEX_TO_SEQ(cmd_idx));

	spin_lock_bh(&trans_slv->txq_lock);
	list_for_each_entry(txq_entry, &txq->sent, list) {
		IWL_SLV_TXQ_GET_ENTRY(txq_entry, cmd_entry);
		dev_cmd = iwl_cmd_entry_get_dev_cmd(trans_slv, cmd_entry);
		if (dev_cmd->hdr.sequence == sequence) {
			if (cmd_entry->hcmd_meta.flags & CMD_WANT_SKB)
				cmd_entry->hcmd_meta.flags &= ~CMD_WANT_SKB;
			break;
		}
	}
	spin_unlock_bh(&trans_slv->txq_lock);
}

static int iwl_slv_send_cmd_sync(struct iwl_trans *trans,
				struct iwl_host_cmd *cmd)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int cmd_idx;
	int ret;

	IWL_DEBUG_INFO(trans, "Attempting to send sync command %s\n",
		       iwl_get_cmd_string(trans, cmd->id));

	if (WARN_ON(test_and_set_bit(STATUS_SYNC_HCMD_ACTIVE,
				     &trans->status))) {
		IWL_ERR(trans, "Command %s: a command is already active!\n",
			iwl_get_cmd_string(trans, cmd->id));
		return -EIO;
	}

	IWL_DEBUG_INFO(trans, "Setting HCMD_ACTIVE for command %s\n",
		       iwl_get_cmd_string(trans, cmd->id));

	cmd_idx = iwl_slv_tx_enqueue_hcmd(trans, cmd);
	if (cmd_idx < 0) {
		ret = cmd_idx;
		clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
		IWL_ERR(trans,
			"Error sending %s: enqueue_hcmd failed: %d\n",
			iwl_get_cmd_string(trans, cmd->id), ret);
		return ret;
	}

	ret = wait_event_timeout(
			trans_slv->wait_command_queue,
			!test_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status),
			HOST_COMPLETE_TIMEOUT);
	if (!ret) {
		if (test_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status)) {
			IWL_ERR(trans,
				"Error sending %s: time out after %dms.\n",
				iwl_get_cmd_string(trans, cmd->id),
				jiffies_to_msecs(HOST_COMPLETE_TIMEOUT));

			clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
			IWL_DEBUG_INFO(trans,
				       "Clearing HCMD_ACTIVE for command %s\n",
				       iwl_get_cmd_string(trans, cmd->id));
			ret = -ETIMEDOUT;
			iwl_trans_fw_error(trans);
			goto cancel;
		}
	}

	if (test_bit(STATUS_FW_ERROR, &trans->status)) {
		IWL_ERR(trans, "FW error in SYNC CMD %s\n",
			iwl_get_cmd_string(trans, cmd->id));
		dump_stack();
		ret = -EIO;
		goto cancel;
	}

	if ((cmd->flags & CMD_WANT_SKB) && !cmd->resp_pkt) {
		IWL_ERR(trans, "Error: Response NULL in '%s'\n",
			iwl_get_cmd_string(trans, cmd->id));
		ret = -EIO;
		goto cancel;
	}

	return 0;

cancel:
	if (cmd->flags & CMD_WANT_SKB) {
		/*
		 * Cancel the CMD_WANT_SKB flag for the cmd in the
		 * TX cmd queue. Otherwise in case the cmd comes
		 * in later, it will possibly set an invalid
		 * address (cmd->meta.source).
		 */
		iwl_slv_tx_cancel_cmd(trans, cmd_idx);
	}

	if (cmd->resp_pkt) {
		iwl_free_resp(cmd);
		cmd->resp_pkt = NULL;
	}

	return ret;
}

int iwl_trans_slv_send_cmd(struct iwl_trans *trans, struct iwl_host_cmd *cmd)
{
	if (cmd->flags & CMD_ASYNC)
		return iwl_slv_send_cmd_async(trans, cmd);

	return iwl_slv_send_cmd_sync(trans, cmd);
}

#define IWL_FLUSH_WAIT_MS 2000
int iwl_trans_slv_wait_txq_empty(struct iwl_trans *trans, u32 txq_bm)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	unsigned long timeout = jiffies + msecs_to_jiffies(IWL_FLUSH_WAIT_MS);
	int q_id;

	for (q_id = 0; q_id < trans->cfg->base_params->num_of_queues; q_id++) {
		struct iwl_slv_tx_queue *txq = &trans_slv->txqs[q_id];

		if (q_id == trans_slv->cmd_queue)
			continue;

		if (!(BIT(q_id) & txq_bm))
			continue;

		IWL_DEBUG_TX_QUEUES(trans, "Emptying queue %d...\n", q_id);
		while (!time_after(jiffies, timeout) &&
		       (atomic_read(&txq->waiting_count) ||
			atomic_read(&txq->sent_count)))
			msleep(1);

		if (atomic_read(&txq->waiting_count) ||
		    atomic_read(&txq->sent_count)) {
			IWL_ERR(trans,
				"Fail to flush tx queue %d: waiting_cnt=%d, sent_count=%d\n",
				q_id, atomic_read(&txq->waiting_count),
				atomic_read(&txq->sent_count));
			return -ETIMEDOUT;
		}
		IWL_DEBUG_TX_QUEUES(trans, "Q %d is now empty.\n", q_id);
	}

	IWL_DEBUG_TX_QUEUES(trans, "All the queues are now empty\n");

	return 0;
}

int iwl_slv_rx_handle_dispatch(struct iwl_trans *trans,
			       struct napi_struct *napi,
			       struct iwl_rx_cmd_buffer *rxcb)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int reclaim;
	struct iwl_rx_packet *pkt = rxb_addr(rxcb);
	u32 len;

	/* Calculate length and trace */
	len = iwl_rx_packet_len(pkt);
	len += sizeof(u32); /* account for status word */

	trace_iwlwifi_dev_rx(trans->dev, trans, pkt, len);
	trace_iwlwifi_dev_rx_data(trans->dev, trans, pkt, len);

	reclaim = !(pkt->hdr.sequence & SEQ_RX_FRAME);
	if (reclaim && !pkt->hdr.group_id) {
		int i;

		for (i = 0; i < trans_slv->n_no_reclaim_cmds; i++) {
			if (trans_slv->no_reclaim_cmds[i] == pkt->hdr.cmd) {
				reclaim = false;
				break;
			}
		}
	}

	if (reclaim) {
		struct iwl_slv_tx_cmd_entry *cmd_entry =
			iwl_slv_tx_get_cmd_entry(trans, pkt);

		if (cmd_entry == NULL)
			return -EINVAL;

		if (!(IWL_D0I3_DEBUG & IWL_D0I3_DBG_KEEP_BUS) &&
		    (cmd_entry->hcmd_meta.flags & CMD_MAKE_TRANS_IDLE) &&
		    trans_slv->config.rx_dma_idle)
			trans_slv->config.rx_dma_idle(trans);

		local_bh_disable();
		iwl_op_mode_rx(trans->op_mode, napi, rxcb);
		local_bh_enable();
		if (!rxcb->_page_stolen)
			iwl_slv_tx_cmd_complete(trans, rxcb, cmd_entry);
		else
			IWL_WARN(trans, "Claim null rxb?\n");
	} else {
		local_bh_disable();
		iwl_op_mode_rx(trans->op_mode, napi, rxcb);
		local_bh_enable();
	}

	return 0;
}

#ifdef CPTCFG_IWLWIFI_DEBUGFS
#define DEBUGFS_ADD_FILE(name, parent, mode) do {			\
	if (!debugfs_create_file(#name, mode, parent, trans,		\
				 &iwl_dbgfs_##name##_ops))		\
		goto err;						\
} while (0)

#define DEBUGFS_READ_WRITE_FILE_OPS(name)				\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write = iwl_dbgfs_##name##_write,				\
	.read = iwl_dbgfs_##name##_read,				\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
};

static ssize_t iwl_dbgfs_d0i3_timeout_read(struct file *file,
					   char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	int pos = 0;
	char buf[256];

	pos += scnprintf(buf, sizeof(buf), "%d\n",
			 iwlwifi_mod_params.d0i3_entry_delay);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_d0i3_timeout_write(struct file *file,
					    const char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct iwl_trans *trans = file->private_data;
	struct iwl_trans_slv *trans_slv __maybe_unused =
				IWL_TRANS_GET_SLV_TRANS(trans);
	unsigned long value;
	int ret;

	ret = kstrtoul_from_user(user_buf, count, 10, &value);
	if (ret < 0)
		return -EINVAL;

	iwlwifi_mod_params.d0i3_entry_delay = value;
	pm_runtime_set_autosuspend_delay(trans_slv->d0i3_dev, value);
	return count;
}
DEBUGFS_READ_WRITE_FILE_OPS(d0i3_timeout);

int iwl_trans_slv_dbgfs_register(struct iwl_trans *trans)
{
	struct dentry *dir = trans->dbgfs_dir;

	DEBUGFS_ADD_FILE(d0i3_timeout, dir, S_IWUSR | S_IRUSR);
	return 0;
err:
	IWL_ERR(trans, "failed to create the trans debugfs entry\n");
	return -ENOMEM;
}
#endif /*CPTCFG_IWLWIFI_DEBUGFS */

void iwl_trans_slv_ref(struct iwl_trans *trans)
{
#ifdef CONFIG_PM_RUNTIME
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	IWL_DEBUG_RPM(trans, "rpm counter: %d\n",
		      atomic_read(&trans_slv->d0i3_dev->power.usage_count));
#ifdef CPTCFG_IWLMVM_WAKELOCK
	{
		unsigned long flags;

		spin_lock_irqsave(&trans->ref_lock, flags);
		trans->wakelock_count++;

		/* take ref wakelock on first reference */
		if (trans->wakelock_count == 1 &&
		    trans->dbg_cfg.wakelock_mode == IWL_WAKELOCK_MODE_IDLE &&
		    !trans->suspending)
			wake_lock(&trans->ref_wake_lock);

		IWL_DEBUG_RPM(trans, "wakelock_counter: %d\n",
			      trans->wakelock_count);

		spin_unlock_irqrestore(&trans->ref_lock, flags);
	}
#endif
	pm_runtime_get(trans_slv->d0i3_dev);
#endif
}

void iwl_trans_slv_unref(struct iwl_trans *trans)
{
#ifdef CONFIG_PM_RUNTIME
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	IWL_DEBUG_RPM(trans, "rpm counter: %d\n",
		      atomic_read(&trans_slv->d0i3_dev->power.usage_count));
#ifdef CPTCFG_IWLMVM_WAKELOCK
	{
		unsigned long flags;

		spin_lock_irqsave(&trans->ref_lock, flags);

		if (WARN_ON_ONCE(trans->wakelock_count == 0)) {
			spin_unlock_irqrestore(&trans->ref_lock, flags);
			return;
		}
		trans->wakelock_count--;

		/* Release ref wake lock and take timed wake lock when
		 * last reference is released.
		 */
		if (trans->wakelock_count == 0 &&
		    trans->dbg_cfg.wakelock_mode == IWL_WAKELOCK_MODE_IDLE &&
		    !trans->suspending) {
			wake_unlock(&trans->ref_wake_lock);
			wake_lock_timeout(&trans->timed_wake_lock,
				  msecs_to_jiffies(IWL_WAKELOCK_TIMEOUT_MS));
		}

		IWL_DEBUG_RPM(trans, "wakelock_counter: %d\n",
			      trans->wakelock_count);

		spin_unlock_irqrestore(&trans->ref_lock, flags);
	}
#endif
	pm_runtime_mark_last_busy(trans_slv->d0i3_dev);
	pm_runtime_put_autosuspend(trans_slv->d0i3_dev);
#endif
}

int iwl_trans_slv_suspend(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);
	int ret;

#ifdef CONFIG_PM_RUNTIME
	IWL_DEBUG_RPM(trans, "suspending: %d, rpm counter: %d\n",
		      trans_slv->suspending,
		      atomic_read(&trans_slv->d0i3_dev->power.usage_count));
#endif

	/* set the device back into d0i3 (see iwl_slv_rpm_suspend()) */
	ret = iwl_slv_fw_enter_d0i3(trans);
	if (ret)
		return ret;
	trans_slv->wowlan_enabled = true;
	return 0;
}

void iwl_trans_slv_resume(struct iwl_trans *trans)
{
	struct iwl_trans_slv *trans_slv = IWL_TRANS_GET_SLV_TRANS(trans);

#ifdef CONFIG_PM_RUNTIME
	IWL_DEBUG_RPM(trans, "rpm counter: %d\n",
		      atomic_read(&trans_slv->d0i3_dev->power.usage_count));
#endif

	/*
	 * set the device active again (mac80211 might interact with it,
	 * and the runtime_pm handlers are frozen at this point)
	 */
	iwl_slv_fw_exit_d0i3(trans);
	trans_slv->wowlan_enabled = false;
}
