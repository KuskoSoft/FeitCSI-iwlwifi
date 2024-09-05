# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
obj-$(CPTCFG_IWLMLD)   += iwlmld.o
obj-$(CPTCFG_IWLWIFI_KUNIT_TESTS) += tests/

iwlmld-y += mld.o notif.o mac80211.o fw.o power.o iface.o link.o rx.o mcc.o session-protect.o phy.o
iwlmld-y += scan.o sta.o tx.o coex.o
iwlmld-$(CPTCFG_IWLWIFI_DEBUGFS) += debugfs.o
iwlmld-$(CPTCFG_IWLWIFI_LEDS) += led.o

# non-upstream things
iwlmld-$(CPTCFG_IWL_VENDOR_CMDS) += vendor-cmd.o

subdir-ccflags-y += -I$(src)/../
