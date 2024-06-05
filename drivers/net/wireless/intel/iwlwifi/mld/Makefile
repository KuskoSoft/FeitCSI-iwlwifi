obj-$(CPTCFG_IWLMLD)   += iwlmld.o
obj-$(CPTCFG_IWLWIFI_KUNIT_TESTS) += tests/

iwlmld-y += mld.o notif.o mac80211.o hcmd.o fw.o
iwlmld-$(CPTCFG_IWLWIFI_DEBUGFS) += debugfs.o

subdir-ccflags-y += -I$(src)/../
