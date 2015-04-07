/* Automatically created during backport process */
#ifndef CPTCFG_BPAUTO_RHASHTABLE
#include_next <linux/rhashtable.h>
#else
#undef lockdep_rht_mutex_is_held
#define lockdep_rht_mutex_is_held LINUX_BACKPORT(lockdep_rht_mutex_is_held)
#undef lockdep_rht_bucket_is_held
#define lockdep_rht_bucket_is_held LINUX_BACKPORT(lockdep_rht_bucket_is_held)
#undef rhashtable_expand
#define rhashtable_expand LINUX_BACKPORT(rhashtable_expand)
#undef rhashtable_shrink
#define rhashtable_shrink LINUX_BACKPORT(rhashtable_shrink)
#undef rhashtable_insert
#define rhashtable_insert LINUX_BACKPORT(rhashtable_insert)
#undef rhashtable_remove
#define rhashtable_remove LINUX_BACKPORT(rhashtable_remove)
#undef rhashtable_lookup
#define rhashtable_lookup LINUX_BACKPORT(rhashtable_lookup)
#undef rhashtable_lookup_compare
#define rhashtable_lookup_compare LINUX_BACKPORT(rhashtable_lookup_compare)
#undef rhashtable_lookup_insert
#define rhashtable_lookup_insert LINUX_BACKPORT(rhashtable_lookup_insert)
#undef rhashtable_lookup_compare_insert
#define rhashtable_lookup_compare_insert LINUX_BACKPORT(rhashtable_lookup_compare_insert)
#undef rhashtable_walk_init
#define rhashtable_walk_init LINUX_BACKPORT(rhashtable_walk_init)
#undef rhashtable_walk_exit
#define rhashtable_walk_exit LINUX_BACKPORT(rhashtable_walk_exit)
#undef rhashtable_walk_start
#define rhashtable_walk_start LINUX_BACKPORT(rhashtable_walk_start)
#undef rhashtable_walk_next
#define rhashtable_walk_next LINUX_BACKPORT(rhashtable_walk_next)
#undef rhashtable_walk_stop
#define rhashtable_walk_stop LINUX_BACKPORT(rhashtable_walk_stop)
#undef rhashtable_init
#define rhashtable_init LINUX_BACKPORT(rhashtable_init)
#undef rhashtable_destroy
#define rhashtable_destroy LINUX_BACKPORT(rhashtable_destroy)
#include <linux/backport-rhashtable.h>
#endif /* CPTCFG_BPAUTO_RHASHTABLE */
