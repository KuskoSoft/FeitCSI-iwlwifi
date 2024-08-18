// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "notif.h"
#include "scan.h"
#include "iwl-trans.h"
#include "fw/file.h"
#include "fw/dbg.h"
#include "fw/api/cmdhdr.h"
#include "fw/api/mac-cfg.h"
#include "session-protect.h"
#include "fw/api/time-event.h"
#include "fw/api/tx.h"

#include "mcc.h"
#include "link.h"
#include "tx.h"

/**
 * enum iwl_rx_handler_context: context for Rx handler
 * @RX_HANDLER_SYNC: this means that it will be called in the Rx path
 *	which can't acquire the wiphy->mutex.
 * @RX_HANDLER_ASYNC: If the handler needs to hold wiphy->mutex
 *	(and only in this case!), it should be set as ASYNC. In that case,
 *	it will be called from a worker with wiphy->mutex held.
 */
enum iwl_rx_handler_context {
	RX_HANDLER_SYNC,
	RX_HANDLER_ASYNC,
};

/**
 * struct iwl_rx_handler: handler for FW notification
 * @val_fn: input validation function.
 * @sizes: an array that mapps a version to the expected size.
 * @fn: the function is called when notification is handled
 * @cmd_id: command id
 * @n_sizes: number of elements in &sizes.
 * @context: see &iwl_rx_handler_context
 */
struct iwl_rx_handler {
	union {
		bool (*val_fn)(struct iwl_mld *mld, struct iwl_rx_packet *pkt);
		const struct iwl_notif_struct_size *sizes;
	};
	void (*fn)(struct iwl_mld *mld, struct iwl_rx_packet *pkt);
	u16 cmd_id;
	u8 n_sizes;
	u8 context;
};

/**
 * struct iwl_notif_struct_size: map a notif ver to the expected size
 *
 * @size: the size to expect
 * @ver: the version of the notification
 */
struct iwl_notif_struct_size {
	u32 size:24, ver:8;
};

/* Please use this in an increasing order of the versions */
#define CMD_VER_ENTRY(_ver, _struct) { .size = sizeof(struct _struct), .ver = _ver },
#define CMD_VERSIONS(name, ...) static const struct iwl_notif_struct_size iwl_notif_struct_sizes_##name[] = { __VA_ARGS__ };

#define RX_HANDLER_SIZES(_grp, _cmd, _name, _context)			\
	{.cmd_id = WIDE_ID(_grp, _cmd),					\
	 .context = _context,						\
	 .fn = iwl_mld_handle_##_name,					\
	 .sizes = iwl_notif_struct_sizes_##_name,			\
	 .n_sizes = ARRAY_SIZE(iwl_notif_struct_sizes_##_name),		\
	},

/* Use this for Rx handlers that do not need notification validation */
#define RX_HANDLER_NO_VAL(_grp, _cmd, _name, _context)			\
	{.cmd_id = WIDE_ID(_grp, _cmd),					\
	 .context = _context,						\
	 .fn = iwl_mld_handle_##_name,					\
	},

#define RX_HANDLER_VAL_FN(_grp, _cmd, _name, _context)			\
	{ .cmd_id = WIDE_ID(_grp, _cmd),				\
	  .context = _context,						\
	  .fn = iwl_mld_handle_##_name,					\
	  .val_fn = iwl_mld_validate_##_name,				\
	},

static void iwl_mld_handle_mfuart_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt)
{
	struct iwl_mfuart_load_notif *mfuart_notif = (void *)pkt->data;

	IWL_DEBUG_INFO(mld,
		       "MFUART: installed ver: 0x%08x, external ver: 0x%08x\n",
		       le32_to_cpu(mfuart_notif->installed_ver),
		       le32_to_cpu(mfuart_notif->external_ver));
	IWL_DEBUG_INFO(mld,
		       "MFUART: status: 0x%08x, duration: 0x%08x image size: 0x%08x\n",
		       le32_to_cpu(mfuart_notif->status),
		       le32_to_cpu(mfuart_notif->duration),
		       le32_to_cpu(mfuart_notif->image_size));
}

CMD_VERSIONS(scan_complete_notif,
	     CMD_VER_ENTRY(1, iwl_umac_scan_complete))
CMD_VERSIONS(scan_iter_complete_notif,
	     CMD_VER_ENTRY(2, iwl_umac_scan_iter_complete_notif))
CMD_VERSIONS(mfuart_notif,
	     CMD_VER_ENTRY(2, iwl_mfuart_load_notif))
CMD_VERSIONS(update_mcc,
	     CMD_VER_ENTRY(1, iwl_mcc_chub_notif))
CMD_VERSIONS(session_prot_notif,
	     CMD_VER_ENTRY(3, iwl_session_prot_notif))
CMD_VERSIONS(missed_beacon_notif,
	     CMD_VER_ENTRY(5, iwl_missed_beacons_notif))
CMD_VERSIONS(tx_resp_notif,
	     CMD_VER_ENTRY(7, iwl_tx_resp))

/*
 * Handlers for fw notifications
 * Convention: RX_HANDLER(grp, cmd, name, context),
 * This list should be in order of frequency for performance purposes.
 *
 * The handler can be one from three contexts, see &iwl_rx_handler_context
 */
static const struct iwl_rx_handler iwl_mld_rx_handlers[] = {
	RX_HANDLER_SIZES(LEGACY_GROUP, TX_CMD, tx_resp_notif,
			 RX_HANDLER_SYNC)
	RX_HANDLER_SIZES(LEGACY_GROUP, MCC_CHUB_UPDATE_CMD, update_mcc,
			 RX_HANDLER_ASYNC)
	RX_HANDLER_SIZES(LEGACY_GROUP, SCAN_COMPLETE_UMAC, scan_complete_notif,
			 RX_HANDLER_ASYNC)
	RX_HANDLER_SIZES(LEGACY_GROUP, SCAN_ITERATION_COMPLETE_UMAC,
			 scan_iter_complete_notif,
			 RX_HANDLER_SYNC)
	RX_HANDLER_NO_VAL(LEGACY_GROUP, MATCH_FOUND_NOTIFICATION,
			  match_found_notif, RX_HANDLER_SYNC)
	RX_HANDLER_SIZES(LEGACY_GROUP, MFUART_LOAD_NOTIFICATION, mfuart_notif,
			 RX_HANDLER_SYNC)

	RX_HANDLER_SIZES(MAC_CONF_GROUP, SESSION_PROTECTION_NOTIF,
			 session_prot_notif, RX_HANDLER_ASYNC)
	RX_HANDLER_SIZES(MAC_CONF_GROUP, MISSED_BEACONS_NOTIF,
			 missed_beacon_notif, RX_HANDLER_ASYNC)
};

static bool
iwl_mld_notif_is_valid(struct iwl_mld *mld, struct iwl_rx_packet *pkt,
		       const struct iwl_rx_handler *handler)
{
	unsigned int size = iwl_rx_packet_payload_len(pkt);
	size_t notif_ver;
	u8 grp;

	/* If n_sizes == 0, it indicates that a validation function may be used
	 * or that no validation is required.
	 */
	if (!handler->n_sizes) {
		if (handler->val_fn)
			return handler->val_fn(mld, pkt);
		return true;
	}

	/* Erroneously, FW publishes the TLV of this using LONG_GROUP instead
	 * of LEGACY_GROUP. WA this until FW is fixed.
	 */
	grp = iwl_cmd_opcode(handler->cmd_id) == TX_CMD ? LONG_GROUP :
		iwl_cmd_groupid(handler->cmd_id);

	notif_ver = iwl_fw_lookup_notif_ver(mld->fw,
					    grp,
					    iwl_cmd_opcode(handler->cmd_id),
					    IWL_FW_CMD_VER_UNKNOWN);

	for (int i = 0; i < handler->n_sizes; i++) {
		if (handler->sizes[i].ver != notif_ver)
			continue;

		if (IWL_FW_CHECK(mld, size < handler->sizes[i].size,
				 "unexpected notification 0x%04x size %d, need %d\n",
				 handler->cmd_id, size, handler->sizes[i].size))
			return false;
		return true;
	}

	IWL_FW_CHECK_FAILED(mld,
			    "notif 0x%04x ver %ld missing expected size, use version %d size\n",
			    handler->cmd_id, notif_ver,
			    handler->sizes[handler->n_sizes - 1].ver);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	/* Drop the notification in non-upstream builds to force adding
	 * support for new versions
	 */
	return false;
#endif
	return size < handler->sizes[handler->n_sizes - 1].size;
}

struct iwl_async_handler_entry {
	struct list_head list;
	struct iwl_rx_cmd_buffer rxb;
};

static void iwl_mld_rx_notif(struct iwl_mld *mld,
			     struct iwl_rx_cmd_buffer *rxb,
			     struct iwl_rx_packet *pkt)
{
	/* Do the notification wait before RX handlers so
	 * even if the RX handler consumes the RXB we have
	 * access to it in the notification wait entry.
	 */
	iwl_notification_wait_notify(&mld->notif_wait, pkt);

	for (int i = 0; i < ARRAY_SIZE(iwl_mld_rx_handlers); i++) {
		const struct iwl_rx_handler *rx_h = &iwl_mld_rx_handlers[i];
		struct iwl_async_handler_entry *entry;

		if (rx_h->cmd_id != WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd))
			continue;

		if (!iwl_mld_notif_is_valid(mld, pkt, rx_h))
			return;

		if (rx_h->context == RX_HANDLER_SYNC) {
			rx_h->fn(mld, pkt);
			return;
		}

		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		/* we can't do much... */
		if (!entry)
			return;

		/* Set the async handler entry */
		entry->rxb._page = rxb_steal_page(rxb);
		entry->rxb._offset = rxb->_offset;
		entry->rxb._rx_page_order = rxb->_rx_page_order;

		/* Add it to the list and queue the work */
		spin_lock(&mld->async_handlers_lock);
		list_add_tail(&entry->list, &mld->async_handlers_list);
		spin_unlock(&mld->async_handlers_lock);

		wiphy_work_queue(mld->hw->wiphy,
				 &mld->async_handlers_wk);
		break;
	}
}

void iwl_mld_rx(struct iwl_op_mode *op_mode, struct napi_struct *napi,
		struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mld *mld = IWL_OP_MODE_GET_MLD(op_mode);
	u16 cmd_id = WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);

	if (likely(cmd_id == WIDE_ID(LEGACY_GROUP, REPLY_RX_MPDU_CMD)))
		iwl_mld_rx_mpdu(mld, napi, rxb, 0);
	else
		iwl_mld_rx_notif(mld, rxb, pkt);
}

static void
iwl_mld_run_notif_handler(struct iwl_mld *mld, struct iwl_rx_packet *pkt)
{
	for (int i = 0; i < ARRAY_SIZE(iwl_mld_rx_handlers); i++) {
		const struct iwl_rx_handler *rx_h = &iwl_mld_rx_handlers[i];

		if (rx_h->cmd_id != WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd))
			continue;

		rx_h->fn(mld, pkt);
	}
}

void iwl_mld_async_handlers_wk(struct wiphy *wiphy, struct wiphy_work *wk)
{
	struct iwl_mld *mld =
		container_of(wk, struct iwl_mld, async_handlers_wk);
	struct iwl_async_handler_entry *entry, *tmp;
	LIST_HEAD(local_list);

	/* Sync with Rx path with a lock. Remove all the entries from this
	 * list, add them to a local one (lock free), and then handle them.
	 */
	spin_lock_bh(&mld->async_handlers_lock);
	list_splice_init(&mld->async_handlers_list, &local_list);
	spin_unlock_bh(&mld->async_handlers_lock);

	list_for_each_entry_safe(entry, tmp, &local_list, list) {
		iwl_mld_run_notif_handler(mld, rxb_addr(&entry->rxb));
		iwl_free_rxb(&entry->rxb);
		list_del(&entry->list);
		kfree(entry);
	}
}

void iwl_mld_purge_async_handlers_list(struct iwl_mld *mld)
{
	struct iwl_async_handler_entry *entry, *tmp;

	spin_lock_bh(&mld->async_handlers_lock);
	list_for_each_entry_safe(entry, tmp, &mld->async_handlers_list, list) {
		iwl_free_rxb(&entry->rxb);
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock_bh(&mld->async_handlers_lock);
}
