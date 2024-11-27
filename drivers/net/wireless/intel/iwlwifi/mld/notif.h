// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_notif_h__
#define __iwl_mld_notif_h__

struct iwl_mld;

void iwl_mld_rx(struct iwl_op_mode *op_mode, struct napi_struct *napi,
		struct iwl_rx_cmd_buffer *rxb);

void iwl_mld_rx_rss(struct iwl_op_mode *op_mode, struct napi_struct *napi,
		    struct iwl_rx_cmd_buffer *rxb, unsigned int queue);

void iwl_mld_async_handlers_wk(struct wiphy *wiphy, struct wiphy_work *wk);

void iwl_mld_purge_async_handlers_list(struct iwl_mld *mld);

enum iwl_mld_object_type {
	IWL_MLD_OBJECT_TYPE_NONE,
	IWL_MLD_OBJECT_TYPE_LINK,
	IWL_MLD_OBJECT_TYPE_STA,
	IWL_MLD_OBJECT_TYPE_VIF,
};

void iwl_mld_cancel_notifications_of_object(struct iwl_mld *mld,
					    enum iwl_mld_object_type obj_type,
					    u32 obj_id);

#endif /* __iwl_mld_notif_h__ */
