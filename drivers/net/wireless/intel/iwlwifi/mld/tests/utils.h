// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#ifndef __iwl_mld_kunit_utils_h__
#define __iwl_mld_kunit_utils_h__

#include <net/mac80211.h>
#include <kunit/test-bug.h>

struct iwl_mld;

int kunit_test_init(struct kunit *test);

enum nl80211_iftype;

struct ieee80211_vif *kunit_add_vif(bool mlo, enum nl80211_iftype type);

struct ieee80211_bss_conf *kunit_add_link(struct ieee80211_vif *vif,
					  int link_id);

#define CHANNEL(_name, _band, _freq)				\
static struct ieee80211_channel _name = {			\
	.band = (_band),					\
	.center_freq = (_freq),					\
	.hw_value = (_freq),					\
}

#define CHANDEF(_name, _channel, _freq1, _width)		\
__maybe_unused static struct cfg80211_chan_def _name = {	\
	.chan = &(_channel),					\
	.center_freq1 = (_freq1),				\
	.width = (_width),					\
}

CHANNEL(chan_2ghz, NL80211_BAND_2GHZ, 2412);
CHANNEL(chan_5ghz, NL80211_BAND_5GHZ, 5200);
CHANNEL(chan_6ghz, NL80211_BAND_6GHZ, 6115);
/* Feel free to add more */

CHANDEF(chandef_2ghz, chan_2ghz, 2412, NL80211_CHAN_WIDTH_20);
CHANDEF(chandef_5ghz, chan_5ghz, 5200, NL80211_CHAN_WIDTH_40);
CHANDEF(chandef_6ghz, chan_6ghz, 6115, NL80211_CHAN_WIDTH_160);
/* Feel free to add more */

//struct cfg80211_chan_def;

struct ieee80211_chanctx_conf *
kunit_add_chanctx_from_def(struct cfg80211_chan_def *def);

static inline struct ieee80211_chanctx_conf *
kunit_add_chanctx(enum nl80211_band band)
{
	struct kunit *test = kunit_get_current_test();
	struct cfg80211_chan_def *chandef;

	switch (band) {
	case NL80211_BAND_2GHZ:
		chandef = &chandef_2ghz;
		break;
	case NL80211_BAND_5GHZ:
		chandef = &chandef_5ghz;
		break;
	case NL80211_BAND_6GHZ:
		chandef = &chandef_6ghz;
		break;
	default:
		KUNIT_FAIL(test, "Wrong band %d\n", band);
	}

	return kunit_add_chanctx_from_def(chandef);
}

#endif /* __iwl_mld_kunit_utils_h__ */
