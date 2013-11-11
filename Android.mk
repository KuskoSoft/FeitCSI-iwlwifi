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
ifeq ($(BOARD_USING_INTEL_IWL),true)

.PHONY: iwlwifi

INTEL_IWL_SRC_DIR := $(call my-dir)
INTEL_IWL_OUT_DIR := $(ANDROID_BUILD_TOP)/$(PRODUCT_OUT)/iwlwifi

ifeq ($(TARGET_ARCH),arm)
ifeq ($(CROSS_COMPILE),)
$(warning You are building for an ARM platform, but no CROSS_COMPILE is set. This is likely an error.)
endif
endif

ifeq ($(INTEL_IWL_USE_COMPAT_INSTALL),y)
INTEL_IWL_COMPAT_INSTALL := iwlwifi_install
else
# use system install
copy_modules_to_root: iwlwifi
ALL_KERNEL_MODULES += $(INTEL_IWL_OUT_DIR)
endif

iwlwifi: iwlwifi_build $(INTEL_IWL_COMPAT_INSTALL)

iwlwifi_copy:
	@mkdir -p $(INTEL_IWL_OUT_DIR)
	@cp -rfl $(INTEL_IWL_SRC_DIR)/. $(INTEL_IWL_OUT_DIR)/

iwlwifi_configure: $(INSTALLED_KERNEL_TARGET) iwlwifi_copy
	$(info Configuring kernel module iwlwifi with defconfig-$(INTEL_IWL_BOARD_CONFIG))
	$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR) defconfig-$(INTEL_IWL_BOARD_CONFIG)

iwlwifi_build: iwlwifi_configure
	$(info Building kernel module iwlwifi in $(INTEL_IWL_OUT_DIR))
	$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR)

iwlwifi_install: iwlwifi_build
	$(info Installing kernel modules in $(ANDROID_BUILD_TOP)/$(TARGET_OUT))
	$(MAKE) -C $(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR) M=$(INTEL_IWL_OUT_DIR)/ INSTALL_MOD_DIR=$(INTEL_IWL_COMPAT_INSTALL_DIR) INSTALL_MOD_PATH=$(ANDROID_BUILD_TOP)/$(TARGET_OUT) modules_install

endif
endif
