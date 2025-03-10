#ifndef __BACKPORT_SLAB_H
#define __BACKPORT_SLAB_H
#include_next <linux/slab.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(5,9,0)
#define kfree_sensitive(x)	kzfree(x)
#endif

#if LINUX_VERSION_IS_LESS(6,8,10)
#include <linux/cleanup.h>
DEFINE_FREE(backport_kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))
#define __free_kfree __free_backport_kfree
#endif

#endif /* __BACKPORT_SLAB_H */
