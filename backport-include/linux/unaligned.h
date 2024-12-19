#ifndef __BACKPORT_UNALIGNED_H
#define __BACKPORT_UNALIGNED_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,13,0)
#include <asm/unaligned.h>
#else
#include_next <linux/unaligned.h>
#endif

#endif /* __BACKPORT_UNALIGNED_H */
