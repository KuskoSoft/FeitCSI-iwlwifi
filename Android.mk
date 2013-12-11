#
# Copyright (C) - Intel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#

# for integrated compat build
# ** The below two lines is OTC tree specific & this will be addressed/removed shortly **
COMPAT_KERNEL_MODULES += external/intel_iwlwifi

ifeq ($(INTEL_COMPAT_INTEGRATED_BUILD),)

# Run only this build if variant define the needed configuration
# e.g. Enabling iwlwifi for XMM6321
# BOARD_USING_INTEL_IWL := true      - this will enable iwlwifi building
# INTEL_IWL_BOARD_CONFIG := xmm6321  - the configuration, defconfig-xmm6321
# INTEL_IWL_USE_COMPAT_INSTALL := y  - this will use kernel modules installation
# INTEL_IWL_COMPAT_INSTALL_DIR := updates - the folder that the modules will be installed in
# INTEL_IWL_COMPAT_INSTALL_PATH ?= $(ANDROID_BUILD_TOP)/$(TARGET_OUT) - the install path for the modules
ifeq ($(BOARD_USING_INTEL_IWL),true)

.PHONY: iwlwifi

INTEL_IWL_SRC_DIR := $(call my-dir)
INTEL_IWL_OUT_DIR := $(ANDROID_BUILD_TOP)/$(PRODUCT_OUT)/iwlwifi
INTEL_IWL_COMPAT_INSTALL_PATH ?= $(ANDROID_BUILD_TOP)/$(TARGET_OUT)

ifeq ($(TARGET_ARCH),arm)
ifeq ($(CROSS_COMPILE),)
$(warning You are building for an ARM platform, but no CROSS_COMPILE is set. This is likely an error.)
endif
endif

ifeq ($(INTEL_IWL_USE_COMPAT_INSTALL),y)
INTEL_IWL_COMPAT_INSTALL := iwlwifi_install
INTEL_IWL_KERNEL_DEPEND := $(INSTALLED_KERNEL_TARGET)
else
# use system install
copy_modules_to_root: iwlwifi
ALL_KERNEL_MODULES += $(INTEL_IWL_OUT_DIR)
INTEL_IWL_KERNEL_DEPEND := build_bzImage
endif

ifeq ($(INTEL_IWL_USE_RM_MAC_CFG),y)
copy_modules_to_root: iwlwifi
INTEL_IWL_COMPAT_INSTALL_PATH := $(ANDROID_BUILD_TOP)/$(KERNEL_OUT_MODINSTALL)
INTEL_IWL_KERNEL_DEPEND := modules_install
INTEL_IWL_RM_MAC_CFG_DEPEND := iwlwifi_rm_mac_cfg
INTEL_IWL_INSTALL_MOD_STRIP := INSTALL_MOD_STRIP=1
endif

# check if the modules.dep file should be edited and fixed with scripts
ifeq ($(INTEL_IWL_EDIT_MOD_DEP),y)
iwlwifi_install: iwlwifi_save_mod_dep
INTEL_IWL_MOD_DEP := iwlwifi_run_dep_scripts
# this will cause iwlwifi to be built as an extra module after
# other modules have been installed
EXTRA_KERNEL_MODULES += iwlwifi
endif

iwlwifi: iwlwifi_build $(INTEL_IWL_COMPAT_INSTALL) $(INTEL_IWL_MOD_DEP)

iwlwifi_copy:
	@mkdir -p $(INTEL_IWL_OUT_DIR)
	@cp -rfl $(INTEL_IWL_SRC_DIR)/. $(INTEL_IWL_OUT_DIR)/

iwlwifi_configure: $(INTEL_IWL_KERNEL_DEPEND) iwlwifi_copy
	@$(info Configuring kernel module iwlwifi with defconfig-$(INTEL_IWL_BOARD_CONFIG))
	@$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR) defconfig-$(INTEL_IWL_BOARD_CONFIG)

iwlwifi_build: iwlwifi_configure
	@$(info Building kernel module iwlwifi in $(INTEL_IWL_OUT_DIR))
	@$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR)

iwlwifi_install: iwlwifi_build $(INTEL_IWL_RM_MAC_CFG_DEPEND)
	@$(info Installing kernel modules in $(INTEL_IWL_COMPAT_INSTALL_PATH))
	@$(MAKE) -C $(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR) M=$(INTEL_IWL_OUT_DIR)/ INSTALL_MOD_DIR=$(INTEL_IWL_COMPAT_INSTALL_DIR) INSTALL_MOD_PATH=$(INTEL_IWL_COMPAT_INSTALL_PATH) $(INTEL_IWL_INSTALL_MOD_STRIP) modules_install

iwlwifi_rm_mac_cfg: iwlwifi_build
	$(info Remove kernel cfg80211.ko and mac80211.ko)
	@find $(KERNEL_OUT_MODINSTALL)/lib/modules/ -name "mac80211.ko" | xargs rm -f
	@find $(KERNEL_OUT_MODINSTALL)/lib/modules/ -name "cfg80211.ko" | xargs rm -f

iwlwifi_save_mod_dep:
	@find $(INTEL_IWL_COMPAT_INSTALL_PATH) -name modules.dep -exec cp {} $(INTEL_IWL_OUT_DIR)/modules.dep.orig \;

iwlwifi_run_dep_scripts: iwlwifi_install
	@find $(INTEL_IWL_COMPAT_INSTALL_PATH) -path \*updates\*\.ko -type f -exec $(INTEL_IWL_SRC_DIR)/intc-scripts/mv-compat-mod.py {} iwlmvm \;
	@find $(INTEL_IWL_COMPAT_INSTALL_PATH) -name modules.dep -exec $(INTEL_IWL_SRC_DIR)/intc-scripts/ren-compat-deps.py {} updates iwlmvm \;
	@find $(INTEL_IWL_COMPAT_INSTALL_PATH) -name modules.dep -exec sh -c 'cat $(INTEL_IWL_OUT_DIR)/modules.dep.orig >> {}' \;
	@find $(INTEL_IWL_COMPAT_INSTALL_PATH) -name modules.alias -exec $(INTEL_IWL_SRC_DIR)/intc-scripts/ren-compat-aliases.py {} iwlwifi \;

endif
endif
