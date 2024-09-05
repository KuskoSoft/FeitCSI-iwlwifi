/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_rx_h__
#define __iwl_mld_rx_h__

#include "mld.h"

void iwl_mld_rx_mpdu(struct iwl_mld *mld, struct napi_struct *napi,
		     struct iwl_rx_cmd_buffer *rxb, int queue);
void iwl_mld_handle_frame_release_notif(struct iwl_mld *mld,
					struct napi_struct *napi,
					struct iwl_rx_packet *pkt, int queue);
void iwl_mld_handle_bar_frame_release_notif(struct iwl_mld *mld,
					    struct napi_struct *napi,
					    struct iwl_rx_packet *pkt,
					    int queue);

#endif /* __iwl_mld_agg_h__ */
