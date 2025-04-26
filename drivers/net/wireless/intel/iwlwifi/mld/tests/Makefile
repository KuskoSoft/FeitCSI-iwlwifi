# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
iwlmld-tests-y += module.o hcmd.o utils.o example.o link.o rx.o agg.o link-selection.o rfi.o emlsr_with_bt.o

ccflags-y += -I$(src)/../
obj-$(CPTCFG_IWLWIFI_KUNIT_TESTS) += iwlmld-tests.o
