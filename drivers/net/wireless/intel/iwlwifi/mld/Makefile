# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
obj-$(CPTCFG_IWLMLD)   += iwlmld.o
obj-$(CPTCFG_IWLWIFI_KUNIT_TESTS) += tests/

iwlmld-y += mld.o notif.o mac80211.o fw.o power.o
iwlmld-$(CPTCFG_IWLWIFI_DEBUGFS) += debugfs.o

subdir-ccflags-y += -I$(src)/../
