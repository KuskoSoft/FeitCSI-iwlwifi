#ifndef __BP_KUNIT_TEST_H
#define __BP_KUNIT_TEST_H
#include <linux/version.h>

#include_next <kunit/test.h>

#if LINUX_VERSION_IS_LESS(6,4,0)
/**
 * KUNIT_ARRAY_PARAM_DESC() - Define test parameter generator from an array.
 * @name:  prefix for the test parameter generator function.
 * @array: array of test parameters.
 * @desc_member: structure member from array element to use as description
 *
 * Define function @name_gen_params which uses @array to generate parameters.
 */
#define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)					\
	static const void *name##_gen_params(const void *prev, char *desc)			\
	{											\
		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
		if (__next - (array) < ARRAY_SIZE((array))) {					\
			strscpy(desc, __next->desc_member, KUNIT_PARAM_DESC_SIZE);		\
			return __next;								\
		}										\
		return NULL;									\
	}

typedef void (*kunit_cleanup_t)(const void *);

/**
 * kunit_add_cleanup() - Add post-test cleanup action.
 * @test: The test case to which the resource belongs.
 * @cleanup_func: function to call at end of test.
 * @data: data to pass to @free_func.
 * @internal_gfp: gfp to use for internal allocations, if unsure, use GFP_KERNEL
 *
 * This adds a cleanup action to be executed after the test completes.
 * Internally this is handled using a *test managed resource*.
 *
 * This function will abort the test on failure.
 *
 * Note: KUnit needs to allocate memory for a kunit_resource object. You must
 * specify an @internal_gfp that is compatible with the current context.
 */
void kunit_add_cleanup(struct kunit *test, kunit_cleanup_t cleanup_func,
		       const void *data, gfp_t internal_gfp);
#endif /* LINUX_VERSION_IS_LESS(6,4,0) */

#endif /* __BP_KUNIT_TEST_H */
