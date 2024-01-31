// SPDX-License-Identifier: GPL-2.0

#include <linux/compat.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/usb.h>

#include <uapi/linux/if.h>

#if LINUX_VERSION_IS_GEQ(4,6,0)

int get_user_ifreq(struct ifreq *ifr, void __user **ifrdata, void __user *arg)
{
#ifdef CONFIG_COMPAT
	if (in_compat_syscall()) {
		struct compat_ifreq *ifr32 = (struct compat_ifreq *)ifr;

		memset(ifr, 0, sizeof(*ifr));
		if (copy_from_user(ifr32, arg, sizeof(*ifr32)))
			return -EFAULT;

		if (ifrdata)
			*ifrdata = compat_ptr(ifr32->ifr_data);

		return 0;
	}
#endif

	if (copy_from_user(ifr, arg, sizeof(*ifr)))
		return -EFAULT;

	if (ifrdata)
		*ifrdata = ifr->ifr_data;

	return 0;
}
EXPORT_SYMBOL(get_user_ifreq);

int put_user_ifreq(struct ifreq *ifr, void __user *arg)
{
	size_t size = sizeof(*ifr);

#ifdef CONFIG_COMPAT
	if (in_compat_syscall())
		size = sizeof(struct compat_ifreq);
#endif

	if (copy_to_user(arg, ifr, size))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL(put_user_ifreq);

#endif /* >= 4.6.0 */

/**
 * usb_find_endpoint() - Given an endpoint address, search for the endpoint's
 * usb_host_endpoint structure in an interface's current altsetting.
 * @intf: the interface whose current altsetting should be searched
 * @ep_addr: the endpoint address (number and direction) to find
 *
 * Search the altsetting's list of endpoints for one with the specified address.
 *
 * Return: Pointer to the usb_host_endpoint if found, %NULL otherwise.
 */
static const struct usb_host_endpoint *usb_find_endpoint(
		const struct usb_interface *intf, unsigned int ep_addr)
{
	int n;
	const struct usb_host_endpoint *ep;

	n = intf->cur_altsetting->desc.bNumEndpoints;
	ep = intf->cur_altsetting->endpoint;
	for (; n > 0; (--n, ++ep)) {
		if (ep->desc.bEndpointAddress == ep_addr)
			return ep;
	}
	return NULL;
}

/**
 * usb_check_bulk_endpoints - Check whether an interface's current altsetting
 * contains a set of bulk endpoints with the given addresses.
 * @intf: the interface whose current altsetting should be searched
 * @ep_addrs: 0-terminated array of the endpoint addresses (number and
 * direction) to look for
 *
 * Search for endpoints with the specified addresses and check their types.
 *
 * Return: %true if all the endpoints are found and are bulk, %false otherwise.
 */
bool usb_check_bulk_endpoints(
		const struct usb_interface *intf, const u8 *ep_addrs)
{
	const struct usb_host_endpoint *ep;

	for (; *ep_addrs; ++ep_addrs) {
		ep = usb_find_endpoint(intf, *ep_addrs);
		if (!ep || !usb_endpoint_xfer_bulk(&ep->desc))
			return false;
	}
	return true;
}
EXPORT_SYMBOL_GPL(usb_check_bulk_endpoints);
