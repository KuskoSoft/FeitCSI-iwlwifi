#ifndef __BACKPORT_LINUX_LEDS_H
#define __BACKPORT_LINUX_LEDS_H
#include_next <linux/leds.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(4,5,0)
#define led_set_brightness_sync LINUX_BACKPORT(led_set_brightness_sync)
/**
 * led_set_brightness_sync - set LED brightness synchronously
 * @led_cdev: the LED to set
 * @brightness: the brightness to set it to
 *
 * Set an LED's brightness immediately. This function will block
 * the caller for the time required for accessing device registers,
 * and it can sleep.
 *
 * Returns: 0 on success or negative error value on failure
 */
extern int led_set_brightness_sync(struct led_classdev *led_cdev,
				   enum led_brightness value);
#endif /* < 4.5 */

#if LINUX_VERSION_IS_LESS(4,5,0)
#define devm_led_trigger_register LINUX_BACKPORT(devm_led_trigger_register)
extern int devm_led_trigger_register(struct device *dev,
				     struct led_trigger *trigger);
#endif /* < 4.5 */

#if LINUX_VERSION_IS_LESS(6,5,0)

static inline void backport_led_trigger_blink_oneshot(struct led_trigger *trigger,
						      unsigned long delay_on,
						      unsigned long delay_off,
						      int invert)
{
	led_trigger_blink_oneshot(trigger, &delay_on, &delay_off, invert);
}
#define led_trigger_blink_oneshot LINUX_BACKPORT(led_trigger_blink_oneshot)

static inline void backport_led_trigger_blink(struct led_trigger *trigger,
					      unsigned long delay_on,
					      unsigned long delay_off)
{
	led_trigger_blink(trigger, &delay_on, &delay_off);
}
#define led_trigger_blink LINUX_BACKPORT(led_trigger_blink)

#endif /*  < 6.5 */

#endif /* __BACKPORT_LINUX_LEDS_H */
