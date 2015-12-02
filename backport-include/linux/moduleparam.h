#ifndef __BACKPORT_LINUX_MODULEPARAM_H
#define __BACKPORT_LINUX_MODULEPARAM_H
#include_next <linux/moduleparam.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#define kernel_param_lock LINUX_BACKPORT(kernel_param_lock)
static inline void kernel_param_lock(struct module *mod)
{
	__kernel_param_lock();
}
#define kernel_param_unlock LINUX_BACKPORT(kernel_param_unlock)
static inline void kernel_param_unlock(struct module *mod)
{
	__kernel_param_unlock();
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
extern struct kernel_param_ops param_ops_ullong;
extern int param_set_ullong(const char *val, const struct kernel_param *kp);
extern int param_get_ullong(char *buffer, const struct kernel_param *kp);
#define param_check_ullong(name, p) __param_check(name, p, unsigned long long)
#endif

#endif /* __BACKPORT_LINUX_MODULEPARAM_H */
