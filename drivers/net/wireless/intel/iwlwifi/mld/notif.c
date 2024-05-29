// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include "mld.h"
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
static const struct iwl_rx_handler iwl_mld_rx_handlers[] __attribute__((unused)) = {
	RX_HANDLER_SIZES(LEGACY_GROUP, MFUART_LOAD_NOTIFICATION, mfuart_notif,
			 RX_HANDLER_SYNC)
};
