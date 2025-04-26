/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Portions of this file
 * Copyright (C) 2019 Intel Corporation
 */

#ifdef CPTCFG_MAC80211_MESSAGE_TRACING

#if !defined(__MAC80211_MSG_DRIVER_TRACE) || defined(TRACE_HEADER_MULTI_READ)
#define __MAC80211_MSG_DRIVER_TRACE

#include <linux/tracepoint.h>
#include <net/mac80211.h>
#include "ieee80211_i.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mac80211_msg

#if LINUX_VERSION_IS_LESS(6,0,0)
#define MAX_MSG_LEN	120
#endif

DECLARE_EVENT_CLASS(mac80211_msg_event,
	TP_PROTO(struct va_format *vaf),

	TP_ARGS(vaf),

	TP_STRUCT__entry(
#if LINUX_VERSION_IS_GEQ(6,0,0)
		__vstring(msg, vaf->fmt, vaf->va)
#else
		__dynamic_array(char, msg, MAX_MSG_LEN)
#endif
	),

	TP_fast_assign(
#if LINUX_VERSION_IS_GEQ(6,0,0)
		__assign_vstr(msg, vaf->fmt, vaf->va);
#else
		WARN_ON_ONCE(vsnprintf(__get_dynamic_array(msg),
				       MAX_MSG_LEN, vaf->fmt,
				       *vaf->va) >= MAX_MSG_LEN);
#endif
	),

	TP_printk("%s", __get_str(msg))
);

DEFINE_EVENT(mac80211_msg_event, mac80211_info,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);
DEFINE_EVENT(mac80211_msg_event, mac80211_dbg,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);
DEFINE_EVENT(mac80211_msg_event, mac80211_err,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);
#endif /* !__MAC80211_MSG_DRIVER_TRACE || TRACE_HEADER_MULTI_READ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_msg
#include <trace/define_trace.h>

#endif
