obj-$(CPTCFG_IWLMLD)   += iwlmld.o

iwlmld-y += mld.o notif.o mac80211.o hcmd.o
iwlmld-$(CPTCFG_IWLWIFI_DEBUGFS) += debugfs.o

subdir-ccflags-y += -I$(src)/../
