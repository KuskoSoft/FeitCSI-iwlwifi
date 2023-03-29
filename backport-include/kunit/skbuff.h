#ifndef __BP_KUNIT_SKBUFF_H
#define __BP_KUNIT_SKBUFF_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,4,0)
#include <kunit/test.h>
#include <linux/skbuff.h>

/**
 * kunit_zalloc_skb() - Allocate and initialize a resource managed skb.
 * @test: The test case to which the skb belongs
 * @len: size to allocate
 * @gfp: allocation mask
 *
 * Allocate a new struct sk_buff, zero fill the give length and add it as a
 * resource to the kunit test for automatic cleanup.
 *
 * The function will not return in case of an allocation error.
 */
static inline struct sk_buff *kunit_zalloc_skb(struct kunit *test, int len,
					       gfp_t gfp)
{
	struct sk_buff *res = alloc_skb(len, gfp);

	KUNIT_ASSERT_NOT_NULL(test, res);
	KUNIT_ASSERT_EQ(test, skb_pad(res, len), 0);

	kunit_add_cleanup(test, (kunit_cleanup_t) kfree_skb, res, gfp);

	return res;
}

#else /* LINUX_VERSION_IS_LESS(6,4,0) */
#include_next <kunit/skbuff.h>
#endif /* LINUX_VERSION_IS_LESS(6,4,0) */

#endif /* __BP_KUNIT_SKBUFF_H */
