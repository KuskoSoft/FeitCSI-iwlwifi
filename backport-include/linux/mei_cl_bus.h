#ifndef __BACKPORT_LINUX_MEI_CL_BUS_H
#define __BACKPORT_LINUX_MEI_CL_BUS_H
#include_next <linux/mei_cl_bus.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0))
#define mei_cl_register_event_cb(device, event_mask, read_cb, context) \
	mei_cl_register_event_cb(device, read_cb, context)
#endif


#endif /* __BACKPORT_LINUX_MEI_CL_BUS_H */
