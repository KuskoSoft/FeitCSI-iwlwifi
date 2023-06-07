// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/netdevice.h>

#if LINUX_VERSION_IS_GEQ(6,2,0) && IS_ENABLED(CONFIG_KUNIT)
#include <kunit/test.h>

struct kunit_auto_cleanup {
	struct kunit_resource resource;
	kunit_cleanup_t cleanup_func;
};

static void kunit_auto_cleanup_free(struct kunit_resource *res)
{
	struct kunit_auto_cleanup *cleanup;

	cleanup = container_of(res, struct kunit_auto_cleanup, resource);

	cleanup->cleanup_func(cleanup->resource.data);
}

void kunit_add_cleanup(struct kunit *test, kunit_cleanup_t cleanup_func,
		       const void *data, gfp_t internal_gfp)
{
	struct kunit_auto_cleanup *res;

	KUNIT_ASSERT_NOT_NULL_MSG(test, cleanup_func,
				  "Cleanup function must not be NULL");

	res = kzalloc(sizeof(*res), internal_gfp);
	if (!res) {
		cleanup_func(data);
		KUNIT_ASSERT_FAILURE(test, "Could not allocate resource for cleanup");
	}

	res->cleanup_func = cleanup_func;
	res->resource.should_kfree = true;

	/* Cannot fail as init is NULL */
	__kunit_add_resource(test, NULL, kunit_auto_cleanup_free,
			     &res->resource, (void *)data);
}
EXPORT_SYMBOL_GPL(kunit_add_cleanup);
#endif /* LINUX_VERSION_IS_GEQ(6,2,0) */
