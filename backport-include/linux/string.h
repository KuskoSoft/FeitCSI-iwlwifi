#ifndef __BACKPORT_LINUX_STRING_H
#define __BACKPORT_LINUX_STRING_H
#include_next <linux/string.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
#define memweight LINUX_BACKPORT(memweight)
extern size_t memweight(const void *ptr, size_t bytes);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0))
#define memdup_user_nul LINUX_BACKPORT(memdup_user_nul)
extern void *memdup_user_nul(const void __user *, size_t);
#endif

#endif /* __BACKPORT_LINUX_STRING_H */
