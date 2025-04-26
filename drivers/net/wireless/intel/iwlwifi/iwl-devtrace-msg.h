/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 *
 * Copyright(c) 2009 - 2014 Intel Corporation. All rights reserved.
 *****************************************************************************/

#if !defined(__IWLWIFI_DEVICE_TRACE_MSG) || defined(TRACE_HEADER_MULTI_READ)
#define __IWLWIFI_DEVICE_TRACE_MSG

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM iwlwifi_msg

#define MAX_MSG_LEN	110

DECLARE_EVENT_CLASS(iwlwifi_msg_event,
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

DEFINE_EVENT(iwlwifi_msg_event, iwlwifi_err,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);

DEFINE_EVENT(iwlwifi_msg_event, iwlwifi_warn,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);

DEFINE_EVENT(iwlwifi_msg_event, iwlwifi_info,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);

DEFINE_EVENT(iwlwifi_msg_event, iwlwifi_crit,
	TP_PROTO(struct va_format *vaf),
	TP_ARGS(vaf)
);

TRACE_EVENT(iwlwifi_dbg,
	TP_PROTO(u32 level, const char *function,
		 struct va_format *vaf),
	TP_ARGS(level, function, vaf),
	TP_STRUCT__entry(
		__field(u32, level)
		__string(function, function)
#if LINUX_VERSION_IS_GEQ(6,0,0)
		__vstring(msg, vaf->fmt, vaf->va)
#else
		__dynamic_array(char, msg, MAX_MSG_LEN)
#endif
	),
	TP_fast_assign(
		__entry->level = level;
		__assign_str(function
#if LINUX_VERSION_IS_LESS(6,10,0)
			    , function
#endif
		);
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
#endif /* __IWLWIFI_DEVICE_TRACE_MSG */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE iwl-devtrace-msg
#include <trace/define_trace.h>
