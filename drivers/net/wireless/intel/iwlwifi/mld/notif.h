// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_notif_h__
#define __iwl_mld_notif_h__

void iwl_mld_rx(struct iwl_op_mode *op_mode, struct napi_struct *napi,
		struct iwl_rx_cmd_buffer *rxb);

void iwl_mld_async_handlers_wk(struct wiphy *wiphy, struct wiphy_work *wk);

#endif /* __iwl_mld_notif_h__ */
