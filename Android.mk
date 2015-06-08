#
# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright 2015  Intel Deutschland GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
# USA
#
# The full GNU General Public License is included in this distribution
# in the file called COPYING.
#
# Contact Information:
#  Intel Linux Wireless <ilw@linux.intel.com>
# Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
#
# BSD LICENSE
#
# Copyright 2015  Intel Deutschland GmbH
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# # Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# # Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# # Neither the name Intel Corporation nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

ifeq ($(CROSS_COMPILE),)
ifneq ($(TARGET_TOOLS_PREFIX),)
CROSS_COMPILE := CROSS_COMPILE=$(notdir $(TARGET_TOOLS_PREFIX))
endif
endif

ifeq ($(CROSS_COMPILE),)
ifeq ($(TARGET_ARCH),arm)
$(warning You are building for an ARM platform, but no CROSS_COMPILE is set. This is likely an error.)
else
$(warning CROSS_COMPILE variant is not set; Defaulting to host gcc.)
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

ifeq ($(INTEL_IWL_USE_SYSTEM_COMPAT_MOD_BUILD),y)
# Build iwlwifi modules using system compat install
LOCAL_PATH := $(INTEL_IWL_SRC_DIR)

include $(CLEAR_VARS)

LOCAL_MODULE := IWLWIFI
LOCAL_KERNEL_COMPAT_DEFCONFIG := $(INTEL_IWL_BOARD_CONFIG)

# $1: INSTALL_MOD_PATH
# $2: Module source dir
define COMPAT_PRIVATE_$(LOCAL_MODULE)_PREINSTALL
        find $(1) -name modules.dep -exec cp {} $(2)/modules.dep.orig \;
endef

# $1: INSTALL_MOD_PATH
# $2: Module source dir
define COMPAT_PRIVATE_$(LOCAL_MODULE)_POSTINSTALL
        find $(1) -path \*updates\*\.ko -type f -exec $(2)/intc-scripts/mv-compat-mod.py {} iwlmvm \;
        find $(1) -name modules.dep -exec $(2)/intc-scripts/ren-compat-deps.py {} updates iwlmvm \;
        find $(1) -name modules.dep -exec sh -c 'cat $(2)/modules.dep.orig >> {}' \;
        find $(1) -name modules.alias -exec $(2)/intc-scripts/ren-compat-aliases.py {} iwlwifi \;
endef

include $(BUILD_COMPAT_MODULE)

else
# Build iwlwifi modules using this makefile

# IWLWIFI_CONFIGURE is a rule to use a defconfig for iwlwifi
IWLWIFI_CONFIGURE := $(INTEL_IWL_OUT_DIR)/.config

# some build envs define KERNEL_OUT_DIR as relative to ANDROID_BUILD_TOP,
# while others define it as the absolute path. check for it
# and define KERNEL_OUT_ABS_DIR appropriately.
ifeq (/,$(shell echo $(KERNEL_OUT_DIR) | cut -c1))
KERNEL_OUT_ABS_DIR := $(KERNEL_OUT_DIR)
else
KERNEL_OUT_ABS_DIR := $(ANDROID_BUILD_TOP)/$(KERNEL_OUT_DIR)
endif

iwlwifi: iwlwifi_build $(INTEL_IWL_COMPAT_INSTALL) $(INTEL_IWL_MOD_DEP)

$(INTEL_IWL_OUT_DIR): $(INTEL_IWL_SRC_DIR)
	@echo Copying directory $(INTEL_IWL_SRC_DIR) to $(INTEL_IWL_OUT_DIR)
	@rm -rf $(INTEL_IWL_OUT_DIR)
	@mkdir -p $(INTEL_IWL_OUT_DIR)
	@cp -rfl $(INTEL_IWL_SRC_DIR)/. $(INTEL_IWL_OUT_DIR)/

$(IWLWIFI_CONFIGURE): $(INTEL_IWL_KERNEL_DEPEND) | $(INTEL_IWL_OUT_DIR)
	@echo Configuring kernel module iwlwifi with defconfig-$(INTEL_IWL_BOARD_CONFIG)
	@$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(KERNEL_OUT_ABS_DIR) defconfig-$(INTEL_IWL_BOARD_CONFIG)

iwlwifi_build: $(IWLWIFI_CONFIGURE)
	@$(info Building kernel module iwlwifi in $(INTEL_IWL_OUT_DIR))
	@$(MAKE) -C $(INTEL_IWL_OUT_DIR)/ ARCH=$(TARGET_ARCH) $(CROSS_COMPILE) KLIB_BUILD=$(KERNEL_OUT_ABS_DIR)

iwlwifi_install: iwlwifi_build $(INTEL_IWL_RM_MAC_CFG_DEPEND)
	@$(info Installing kernel modules in $(INTEL_IWL_COMPAT_INSTALL_PATH))
	@$(MAKE) -C $(KERNEL_OUT_ABS_DIR) M=$(INTEL_IWL_OUT_DIR)/ INSTALL_MOD_DIR=$(INTEL_IWL_COMPAT_INSTALL_DIR) INSTALL_MOD_PATH=$(INTEL_IWL_COMPAT_INSTALL_PATH) $(INTEL_IWL_INSTALL_MOD_STRIP) modules_install

iwlwifi_rm_mac_cfg: iwlwifi_build
	$(info Remove kernel cfg80211.ko and mac80211.ko)
	@find $(KERNEL_OUT_MODINSTALL)/lib/modules/ -name "mac80211.ko" | xargs rm -f
	@find $(KERNEL_OUT_MODINSTALL)/lib/modules/ -name "cfg80211.ko" | xargs rm -f

.PHONY: iwlwifi_clean
iwlwifi_clean:
	rm -rf $(INTEL_IWL_OUT_DIR)
endif
endif
endif
