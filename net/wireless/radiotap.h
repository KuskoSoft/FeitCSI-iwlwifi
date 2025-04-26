/*
 * Copyright (C) 2023 Miroslav Hutar
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 */

#ifndef __RADIOTAP
#define __RADIOTAP

int ieee80211_radiotap_iterator_init(struct ieee80211_radiotap_iterator *iterator,
									 struct ieee80211_radiotap_header *radiotap_header,
									 int max_length,
									 const struct ieee80211_radiotap_vendor_namespaces *vns);

int ieee80211_radiotap_iterator_next(struct ieee80211_radiotap_iterator *iterator);

#endif
