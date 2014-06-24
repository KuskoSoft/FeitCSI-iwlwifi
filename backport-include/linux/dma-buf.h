#ifndef _BACKPORT_DMA_BUF_H__
#define _BACKPORT_DMA_BUF_H__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
#include_next <linux/dma-buf.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0) */

#endif /* _BACKPORT_DMA_BUF_H__ */
