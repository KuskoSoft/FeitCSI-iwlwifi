#ifndef __BACKPORT_LINUX_WORKQUEUE_H
#define __BACKPORT_LINUX_WORKQUEUE_H
#include_next <linux/workqueue.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
#define mod_delayed_work LINUX_BACKPORT(mod_delayed_work)
bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork,
		      unsigned long delay);
#endif

#ifndef create_freezable_workqueue
/* note freez_a_ble -> freez_ea_able */
#define create_freezable_workqueue create_freezeable_workqueue
#endif

#ifndef alloc_ordered_workqueue
#define alloc_ordered_workqueue(name, flags) create_singlethread_workqueue(name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define alloc_workqueue(name, flags, max_active) __create_workqueue(name, flags, max_active)
#endif

#ifndef alloc_workqueue
#define alloc_workqueue(name, flags, max_active) __create_workqueue(name, flags, max_active, 0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define system_wq LINUX_BACKPORT(system_wq)
extern struct workqueue_struct *system_wq;
#define system_long_wq LINUX_BACKPORT(system_long_wq)
extern struct workqueue_struct *system_long_wq;
#define system_nrt_wq LINUX_BACKPORT(system_nrt_wq)
extern struct workqueue_struct *system_nrt_wq;

void backport_system_workqueue_create(void);
void backport_system_workqueue_destroy(void);

#define schedule_work LINUX_BACKPORT(schedule_work)
int schedule_work(struct work_struct *work);
#define schedule_work_on LINUX_BACKPORT(schedule_work_on)
int schedule_work_on(int cpu, struct work_struct *work);
#define schedule_delayed_work LINUX_BACKPORT(schedule_delayed_work)
int schedule_delayed_work(struct delayed_work *dwork,
			  unsigned long delay);
#define schedule_delayed_work_on LINUX_BACKPORT(schedule_delayed_work_on)
int schedule_delayed_work_on(int cpu,
			     struct delayed_work *dwork,
			     unsigned long delay);
#define flush_scheduled_work LINUX_BACKPORT(flush_scheduled_work)
void flush_scheduled_work(void);

enum {
	/* bit mask for work_busy() return values */
	WORK_BUSY_PENDING       = 1 << 0,
	WORK_BUSY_RUNNING       = 1 << 1,
};

#define work_busy LINUX_BACKPORT(work_busy)
extern unsigned int work_busy(struct work_struct *work);

#else

static inline void backport_system_workqueue_create(void)
{
}

static inline void backport_system_workqueue_destroy(void)
{
}
#endif /* < 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* I can't find a more suitable replacement... */
#define flush_work(work) cancel_work_sync(work)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static inline void flush_delayed_work(struct delayed_work *dwork)
{
	if (del_timer_sync(&dwork->timer)) {
		/*
		 * This is what would happen on 2.6.32 but since we don't have
		 * access to the singlethread_cpu we can't really backport this,
		 * so avoid really *flush*ing the work... Oh well. Any better ideas?

		struct cpu_workqueue_struct *cwq;
		cwq = wq_per_cpu(keventd_wq, get_cpu());
		__queue_work(cwq, &dwork->work);
		put_cpu();

		*/
	}
	flush_work(&dwork->work);
}
#endif

#endif /* __BACKPORT_LINUX_WORKQUEUE_H */
