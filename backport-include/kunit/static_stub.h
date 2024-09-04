#ifndef __BP_KUNIT_STATIC_STUB_H
#define __BP_KUNIT_STATIC_STUB_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,3,0)
#define KUNIT_STATIC_STUB_REDIRECT(real_fn_name, args...) do {} while (0)
#else
#include_next <kunit/static_stub.h>
#endif /* LINUX_VERSION_IS_LESS(6,3,0) */

#endif /* __BP_KUNIT_STATIC_STUB_H */
