#ifndef _BACKPORT_TIMER_H
#define _BACKPORT_TIMER_H

#include_next <linux/timer.h>

#ifndef setup_deferrable_timer
/*
 * The TIMER_DEFERRABLE flag has not been around since 3.0 so
 * two different backports are needed here.
 */
#ifdef TIMER_DEFERRABLE
#define setup_deferrable_timer(timer, fn, data)                         \
        __setup_timer((timer), (fn), (data), TIMER_DEFERRABLE)
#else
static inline void setup_deferrable_timer_key(struct timer_list *timer,
					      const char *name,
					      struct lock_class_key *key,
					      void (*func)(unsigned long),
					      unsigned long data)
{
	timer->function = func;
	timer->data = data;
	init_timer_deferrable_key(timer, name, key);
}
#define setup_deferrable_timer(timer, fn, data)				\
	do {								\
		static struct lock_class_key __key;			\
		setup_deferrable_timer_key((timer), #timer, &__key,	\
					   (fn), (data));		\
	} while (0)
#endif

#endif

#endif /* _BACKPORT_TIMER_H */
