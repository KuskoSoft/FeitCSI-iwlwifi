// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#ifndef __iwl_mld_kunit_utils_h__
#define __iwl_mld_kunit_utils_h__

#include <net/mac80211.h>
#include <kunit/test-bug.h>

struct iwl_mld;

int iwlmld_kunit_test_init(struct kunit *test);

enum nl80211_iftype;

struct ieee80211_vif *iwlmld_kunit_add_vif(bool mlo, enum nl80211_iftype type);

struct ieee80211_bss_conf *
iwlmld_kunit_add_link(struct ieee80211_vif *vif, int link_id);

#define KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, size)			\
do {									\
	(ptr) = kunit_kzalloc((test), (size), GFP_KERNEL);		\
	KUNIT_ASSERT_NOT_NULL((test), (ptr));				\
} while (0)

#define KUNIT_ALLOC_AND_ASSERT(test, ptr)				\
	KUNIT_ALLOC_AND_ASSERT_SIZE(test, ptr, sizeof(*(ptr)))

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
iwlmld_kunit_add_chanctx_from_def(struct cfg80211_chan_def *def);

static inline struct ieee80211_chanctx_conf *
iwlmld_kunit_add_chanctx(enum nl80211_band band)
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

	return iwlmld_kunit_add_chanctx_from_def(chandef);
}

void iwlmld_kunit_assign_chanctx_to_link(struct ieee80211_vif *vif,
					 struct ieee80211_bss_conf *link,
					 struct ieee80211_chanctx_conf *ctx);

/* Allocate a sta, initialize it and move it to the wanted state */
struct ieee80211_sta *iwlmld_kunit_setup_sta(struct ieee80211_vif *vif,
					     enum ieee80211_sta_state state,
					     int link_id);

struct ieee80211_vif *iwlmld_kunit_setup_mlo_assoc(u16 valid_links,
						   u8 assoc_link_id,
						   enum nl80211_band band);
struct ieee80211_vif *iwlmld_kunit_setup_non_mlo_assoc(enum nl80211_band band);

struct iwl_rx_packet *
_iwl_mld_kunit_create_pkt(const void *notif, size_t notif_sz);

#define iwl_mld_kunit_create_pkt(_notif)	\
	_iwl_mld_kunit_create_pkt(&(_notif), sizeof(_notif))

struct ieee80211_vif *iwlmld_kunit_assoc_emlsr(u16 valid_links,
					       enum nl80211_band band1,
					       enum nl80211_band band2);

#endif /* __iwl_mld_kunit_utils_h__ */
