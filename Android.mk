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
COMPAT_KERNEL_MODULES += external/intel_iwlwifi

ifeq ($(INTEL_COMPAT_INTEGRATED_BUILD),)

IWLWIFI_COMPAT_DIR := $(call my-dir)

IWLWIFI_BUILD_COMPAT: $(INSTALLED_KERNEL_TARGET)
	@echo iwlwifi-dev building iwlwifi-dev stack
	@echo $(mk_iwlwifi_compat) KLIB_BUILD=$(KBUILD_OUTPUT)
	$(MAKE) -C $(IWLWIFI_COMPAT_DIR) ARCH=$(TARGET_ARCH) KLIB_BUILD=$(KBUILD_OUTPUT)

IWLWIFI_INSTALL_COMPAT: IWLWIFI_BUILD_COMPAT
	@echo iwlwifi-dev installing iwlwifi-dev stack
	$(MAKE) -C $(KBUILD_OUTPUT) M=$(PWD)/$(IWLWIFI_COMPAT_DIR) INSTALL_MOD_DIR=updates INSTALL_MOD_PATH=$(PWD)/$(TARGET_OUT) modules_install


.PHONY: iwlwifi-dev
iwlwifi-dev: IWLWIFI_INSTALL_COMPAT

endif
