#ifndef __BACKPORT_SLAB_H
#define __BACKPORT_SLAB_H
#include_next <linux/slab.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(5,9,0)
#define kfree_sensitive(x)	kzfree(x)
#endif

#ifdef __free_kfree
#undef __free_kfree
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))
#endif

#if LINUX_VERSION_IS_LESS(6,5,0)
#include <linux/cleanup.h>
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))
#endif

#endif /* __BACKPORT_SLAB_H */
