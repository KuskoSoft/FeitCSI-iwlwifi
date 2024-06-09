// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
#include "notif.h"
#include "iwl-trans.h"
#include "fw/file.h"
#include "fw/dbg.h"
#include "fw/api/cmdhdr.h"

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

#define RX_HANDLER_VAL_FN(_grp, _cmd, _name, _context)			\
	{ .cmd_id = WIDE_ID(_grp, _cmd),				\
	  .context = _context,						\
	  .fn = iwl_mld_handle_##_name,					\
	  .val_fn = iwl_mld_validate_##_name,				\
	},

static void iwl_mld_handle_mfuart_notif(struct iwl_mld *mld,
					struct iwl_rx_packet *pkt)
{
	struct iwl_mfuart_load_notif *mfuart_notif = (void *)pkt;

	IWL_DEBUG_INFO(mld,
		       "MFUART: installed ver: 0x%08x, external ver: 0x%08x, status: 0x%08x, duration: 0x%08x image size: 0x%08x\n",
		       le32_to_cpu(mfuart_notif->installed_ver),
		       le32_to_cpu(mfuart_notif->external_ver),
		       le32_to_cpu(mfuart_notif->status),
		       le32_to_cpu(mfuart_notif->duration),
		       le32_to_cpu(mfuart_notif->image_size));
}

CMD_VERSIONS(mfuart_notif,
	     CMD_VER_ENTRY(2, iwl_mfuart_load_notif))

/*
 * Handlers for fw notifications
 * Convention: RX_HANDLER(grp, cmd, name, context),
 * This list should be in order of frequency for performance purposes.
 *
 * The handler can be one from three contexts, see &iwl_rx_handler_context
 */
static const struct iwl_rx_handler iwl_mld_rx_handlers[] = {
	RX_HANDLER_SIZES(LEGACY_GROUP, MFUART_LOAD_NOTIFICATION, mfuart_notif,
			 RX_HANDLER_SYNC)
};

static bool
iwl_mld_notif_is_valid(struct iwl_mld *mld, struct iwl_rx_packet *pkt,
		       const struct iwl_rx_handler *handler)
{
	unsigned int size = iwl_rx_packet_payload_len(pkt);
	size_t notif_ver;

	/* n_sizes == 0 means that a validation function may be used */
	if (!handler->n_sizes && handler->val_fn)
		return handler->val_fn(mld, pkt);

	notif_ver = iwl_fw_lookup_notif_ver(mld->fw,
					    iwl_cmd_groupid(handler->cmd_id),
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

	IWL_ERR(mld,
		"notification 0x%04x version %ld doesn't have an expected size, using the size of version %d\n",
		handler->cmd_id, notif_ver,
		handler->sizes[handler->n_sizes].ver);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	/* Drop the notification in non-upstream builds to force adding
	 * support for new versions
	 */
	return false;
#endif
	return size < handler->sizes[handler->n_sizes - 1].size;
}

void iwl_mld_rx_notif(struct iwl_op_mode *op_mode, struct napi_struct *napi,
		      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mld *mld = IWL_OP_MODE_GET_MLD(op_mode);

	/* Do the notification wait before RX handlers so
	 * even if the RX handler consumes the RXB we have
	 * access to it in the notification wait entry.
	 */
	iwl_notification_wait_notify(&mld->notif_wait, pkt);

	for (int i = 0; i < ARRAY_SIZE(iwl_mld_rx_handlers); i++) {
		const struct iwl_rx_handler *rx_h = &iwl_mld_rx_handlers[i];

		if (rx_h->cmd_id != WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd))
			continue;

		if (!iwl_mld_notif_is_valid(mld, pkt, rx_h))
			return;

		if (rx_h->context == RX_HANDLER_SYNC) {
			rx_h->fn(mld, pkt);
			return;
		}
	}
}
