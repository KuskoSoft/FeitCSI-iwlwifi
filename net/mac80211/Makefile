# SPDX-License-Identifier: GPL-2.0
obj-$(CPTCFG_MAC80211) += mac80211.o

ifeq ($(CPTCFG_IWLWIFI_SIMULATION),y)
UBSAN_SANITIZE := y
endif

# mac80211 objects
mac80211-y := \
	main.o status.o \
	driver-ops.o \
	sta_info.o \
	wep.o \
	aead_api.o \
	wpa.o \
	scan.o offchannel.o \
	ht.o agg-tx.o agg-rx.o \
	vht.o \
	he.o \
	s1g.o \
	ibss.o \
	iface.o \
	link.o \
	rate.o \
	michael.o \
	tkip.o \
	aes_cmac.o \
	aes_gmac.o \
	fils_aead.o \
	cfg.o \
	ethtool.o \
	rx.o \
	spectmgmt.o \
	tx.o \
	key.o \
	util.o parse.o \
	wme.o \
	chan.o \
	trace.o mlme.o \
	tdls.o \
	ocb.o \
	airtime.o \
	eht.o

mac80211-$(CPTCFG_MAC80211_LEDS) += led.o
mac80211-$(CPTCFG_MAC80211_DEBUGFS) += \
	debugfs.o \
	debugfs_sta.o \
	debugfs_netdev.o \
	debugfs_key.o

mac80211-$(CPTCFG_MAC80211_MESH) += \
	mesh.o \
	mesh_pathtbl.o \
	mesh_plink.o \
	mesh_hwmp.o \
	mesh_sync.o \
	mesh_ps.o

mac80211-$(CONFIG_PM) += pm.o

CFLAGS_trace.o := -I$(src)
subdir-ccflags-y += $(call cc-option,-Wimplicit-fallthrough)

rc80211_minstrel-y := \
	rc80211_minstrel_ht.o

rc80211_minstrel-$(CPTCFG_MAC80211_DEBUGFS) += \
	rc80211_minstrel_ht_debugfs.o

mac80211-$(CPTCFG_MAC80211_RC_MINSTREL) += $(rc80211_minstrel-y)

obj-y += tests/

mac80211-y += wbrf.o

ccflags-y += -DDEBUG
