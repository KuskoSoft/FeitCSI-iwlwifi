// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2005-2014, 2018-2025 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/acpi.h>

#include "fw/acpi.h"

#include "iwl-trans.h"
#include "iwl-drv.h"
#include "iwl-prph.h"
#include "internal.h"

#define _IS_A(cfg, _struct) __builtin_types_compatible_p(typeof(cfg),	\
							 struct _struct)
extern int _invalid_type;
#define _TRANS_CFG_CHECK(cfg)						\
	(__builtin_choose_expr(_IS_A(cfg, iwl_cfg_trans_params),	\
			       0, _invalid_type))
#define _ASSIGN_CFG(cfg) (_TRANS_CFG_CHECK(cfg) + (kernel_ulong_t)&(cfg))

#define IWL_PCI_DEVICE(dev, subdev, cfg) \
	.vendor = PCI_VENDOR_ID_INTEL,  .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = (subdev), \
	.driver_data = _ASSIGN_CFG(cfg)

/* Hardware specific file defines the PCI IDs table for that hardware module */
VISIBLE_IF_IWLWIFI_KUNIT const struct pci_device_id iwl_hw_card_ids[] = {

#if IS_ENABLED(CPTCFG_IWLMVM)
/* 7260 Series */
	{IWL_PCI_DEVICE(0x08B1, 0x4070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4072, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4170, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4C60, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4C70, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4060, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x406A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4160, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4062, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4162, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4270, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4272, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4260, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x426A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4262, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4470, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4472, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4460, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x446A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4462, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4870, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x486E, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4A70, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4A6E, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4A6C, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4570, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4560, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4370, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4360, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x5070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x5072, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x5170, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x5770, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4020, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x402A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0x4220, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0x4420, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC072, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC170, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC060, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC06A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC160, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC062, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC162, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC770, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC760, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC270, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xCC70, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xCC60, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC272, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC260, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC26A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC262, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC470, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC472, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC460, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC462, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC570, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC560, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC370, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC360, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC020, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC02A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B2, 0xC220, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B1, 0xC420, iwl7000_trans_cfg)},

/* 3160 Series */
	{IWL_PCI_DEVICE(0x08B3, 0x0070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0072, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0170, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0172, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0060, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0062, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x0270, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x0272, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0470, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x0472, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x0370, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8072, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8170, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8172, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8060, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8062, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x8270, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x8370, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B4, 0x8272, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8470, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x8570, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x1070, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x08B3, 0x1170, iwl7000_trans_cfg)},

/* 3165 Series */
	{IWL_PCI_DEVICE(0x3165, 0x4010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x4012, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3166, 0x4212, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x4410, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x4510, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x4110, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3166, 0x4310, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3166, 0x4210, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x8010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x3165, 0x8110, iwl7000_trans_cfg)},

/* 3168 Series */
	{IWL_PCI_DEVICE(0x24FB, 0x2010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FB, 0x2110, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FB, 0x2050, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FB, 0x2150, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FB, 0x0000, iwl7000_trans_cfg)},

/* 7265 Series */
	{IWL_PCI_DEVICE(0x095A, 0x5010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5110, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5100, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5310, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5302, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5210, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5C10, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5012, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5412, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5410, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5510, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5400, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x1010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5000, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x500A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5200, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5002, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5102, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5202, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9010, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9012, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x900A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9110, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9112, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x9210, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x9200, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9510, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x9310, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9410, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5020, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x502A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5420, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5090, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5190, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5590, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5290, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5490, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x5F10, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x5212, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095B, 0x520A, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9000, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9400, iwl7000_trans_cfg)},
	{IWL_PCI_DEVICE(0x095A, 0x9E10, iwl7000_trans_cfg)},

/* 8000 Series */
	{IWL_PCI_DEVICE(0x24F3, 0x0010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x10B0, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0132, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1132, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x01F0, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0012, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1012, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0250, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0150, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x1150, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0x0030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0x1030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xC010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xC110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xD010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xC050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xD050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xD0B0, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0xB0B0, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0x8030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0x9030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0xC030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F4, 0xD030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8132, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9132, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x8150, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x9150, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0004, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0044, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F5, 0x0010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F6, 0x0030, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0810, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0910, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0850, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0950, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0930, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x0000, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24F3, 0x4010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x1110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x1130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x1010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x10D0, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0150, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x9010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x8110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x8050, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x8010, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0810, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x9110, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x8130, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0910, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0930, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0950, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0850, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x1014, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x3E02, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x3E01, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x1012, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0012, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x0014, iwl8000_trans_cfg)},
	{IWL_PCI_DEVICE(0x24FD, 0x9074, iwl8000_trans_cfg)},
#endif /* IS_ENABLED(CPTCFG_IWLMVM) */

#if IS_ENABLED(CPTCFG_IWLMVM)
/* 9000 Series */
	{IWL_PCI_DEVICE(0x2526, PCI_ANY_ID, iwl9000_trans_cfg)},
	{IWL_PCI_DEVICE(0x271B, PCI_ANY_ID, iwl9000_trans_cfg)},
	{IWL_PCI_DEVICE(0x271C, PCI_ANY_ID, iwl9000_trans_cfg)},
	{IWL_PCI_DEVICE(0x30DC, PCI_ANY_ID, iwl9560_long_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0x31DC, PCI_ANY_ID, iwl9560_shared_clk_trans_cfg)},
	{IWL_PCI_DEVICE(0x9DF0, PCI_ANY_ID, iwl9560_trans_cfg)},
	{IWL_PCI_DEVICE(0xA370, PCI_ANY_ID, iwl9560_trans_cfg)},

/* Qu devices */
	{IWL_PCI_DEVICE(0x02F0, PCI_ANY_ID, iwl_qu_trans_cfg)},
	{IWL_PCI_DEVICE(0x06F0, PCI_ANY_ID, iwl_qu_trans_cfg)},

	{IWL_PCI_DEVICE(0x34F0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0x3DF0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0x4DF0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},

	{IWL_PCI_DEVICE(0x43F0, PCI_ANY_ID, iwl_qu_long_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0xA0F0, PCI_ANY_ID, iwl_qu_long_latency_trans_cfg)},

	{IWL_PCI_DEVICE(0x2723, PCI_ANY_ID, iwl_ax200_trans_cfg)},

/* So devices */
	{IWL_PCI_DEVICE(0x2725, PCI_ANY_ID, iwl_so_trans_cfg)},
	{IWL_PCI_DEVICE(0x7A70, PCI_ANY_ID, iwl_so_long_latency_imr_trans_cfg)},
	{IWL_PCI_DEVICE(0x7AF0, PCI_ANY_ID, iwl_so_trans_cfg)},
	{IWL_PCI_DEVICE(0x51F0, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0x51F1, PCI_ANY_ID, iwl_so_long_latency_imr_trans_cfg)},
	{IWL_PCI_DEVICE(0x54F0, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
	{IWL_PCI_DEVICE(0x7F70, PCI_ANY_ID, iwl_so_trans_cfg)},

/* Ma devices */
	{IWL_PCI_DEVICE(0x2729, PCI_ANY_ID, iwl_ma_trans_cfg)},
	{IWL_PCI_DEVICE(0x7E40, PCI_ANY_ID, iwl_ma_trans_cfg)},
#endif /* CPTCFG_IWLMVM */
#if IS_ENABLED(CPTCFG_IWLMLD)
/* Bz devices */
	{IWL_PCI_DEVICE(0x272b, PCI_ANY_ID, iwl_gl_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0000, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0090, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0094, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0098, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x009C, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00C0, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00C4, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00E0, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00E4, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00E8, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x00EC, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0100, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0110, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0114, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0118, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x011C, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0310, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0314, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0510, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x0A10, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1671, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1672, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1771, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1772, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1791, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x1792, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x4090, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x40C4, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x40E0, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x4110, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0xA840, 0x4314, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0x7740, PCI_ANY_ID, iwl_bz_trans_cfg)},
	{IWL_PCI_DEVICE(0x4D40, PCI_ANY_ID, iwl_bz_trans_cfg)},

/* Sc devices */
	{IWL_PCI_DEVICE(0xE440, PCI_ANY_ID, iwl_sc_trans_cfg)},
	{IWL_PCI_DEVICE(0xE340, PCI_ANY_ID, iwl_sc_trans_cfg)},
	{IWL_PCI_DEVICE(0xD340, PCI_ANY_ID, iwl_sc_trans_cfg)},
	{IWL_PCI_DEVICE(0x6E70, PCI_ANY_ID, iwl_sc_trans_cfg)},

/* Dr devices */
	{IWL_PCI_DEVICE(0x272F, PCI_ANY_ID, iwl_dr_trans_cfg)},
#endif /* CPTCFG_IWLMLD */

	{0}
};
MODULE_DEVICE_TABLE(pci, iwl_hw_card_ids);
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_hw_card_ids);

#define _IWL_DEV_INFO(_cfg, _name, ...) {	\
	.cfg = &_cfg,				\
	.name = _name,				\
	.device = IWL_CFG_ANY,			\
	.subdevice = IWL_CFG_ANY,		\
	.subdevice_mask = ~0,			\
	.mac_type = IWL_CFG_ANY,		\
	.mac_step = IWL_CFG_ANY,		\
	.rf_type = IWL_CFG_ANY,			\
	.rf_step = IWL_CFG_ANY,			\
	.bw_limit = IWL_CFG_ANY,		\
	.jacket = IWL_CFG_ANY,			\
	.cores = IWL_CFG_ANY,			\
	.rf_id = IWL_CFG_ANY,			\
	.cdb = IWL_CFG_ANY,			\
	__VA_ARGS__				\
}
#define IWL_DEV_INFO(_cfg, _name, ...)		\
	_IWL_DEV_INFO(_cfg, _name, __VA_ARGS__)

#define DEVICE(n)	.device = (n)
#define SUBDEV(n)	.subdevice = (n)
#define SUBDEV_MASKED(v, m)			\
			.subdevice = (v),	\
			.subdevice_mask = (m)
#define MAC_TYPE(n)	.mac_type = IWL_CFG_MAC_TYPE_##n
#define MAC_STEP(n)	.mac_step = SILICON_##n##_STEP
#define RF_TYPE(n)	.rf_type = IWL_CFG_RF_TYPE_##n
#define RF_STEP(n)	.rf_step = SILICON_##n##_STEP
#define CORES(n)	.cores = IWL_CFG_CORES_##n
#define RF_ID(n)	.rf_id = IWL_CFG_RF_ID_##n
#define NO_CDB		.cdb = IWL_CFG_NO_CDB
#define CDB		.cdb = IWL_CFG_CDB
#define BW_NOT_LIMITED	.bw_limit = 0
#define BW_LIMITED	.bw_limit = 1

VISIBLE_IF_IWLWIFI_KUNIT const struct iwl_dev_info iwl_dev_info_table[] = {

#if IS_ENABLED(CPTCFG_IWLMVM)
/* 7260 Series */
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B1)), // unlisted ones fall through to here
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4060)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x406A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4160)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0x4062)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0x4162)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4460)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x446A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0x4462)),
	IWL_DEV_INFO(iwl7260_high_temp_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B1), SUBDEV(0x4A70)),
	IWL_DEV_INFO(iwl7260_high_temp_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B1), SUBDEV(0x4A6E)),
	IWL_DEV_INFO(iwl7260_high_temp_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B1), SUBDEV(0x4A6C)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4560)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4020)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x402A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0x4420)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC060)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC06A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC160)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0xC062)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0xC162)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC760)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC460)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B1), SUBDEV(0xC462)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC560)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC360)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC020)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC02A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B1), SUBDEV(0xC420)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0x4270)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0x4272)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0x4260)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0x426A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B2), SUBDEV(0x4262)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0x4370)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0x4360)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0x4220)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0xC270)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0xC272)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0xC260)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B2), SUBDEV(0xC26A)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_n_name,
		     DEVICE(0x08B2), SUBDEV(0xC262)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2ac_name,
		     DEVICE(0x08B2), SUBDEV(0xC370)),
	IWL_DEV_INFO(iwl7260_cfg, iwl7260_2n_name,
		     DEVICE(0x08B2), SUBDEV(0xC220)),

/* 3160 Series */
	IWL_DEV_INFO(iwl3160_cfg, iwl3160_2ac_name,
		     DEVICE(0x08B3)),

	IWL_DEV_INFO(iwl3160_cfg, iwl3160_n_name,
		     DEVICE(0x08B3), SUBDEV_MASKED(0x62, 0xFF)),
	IWL_DEV_INFO(iwl3160_cfg, iwl3160_2n_name,
		     DEVICE(0x08B3), SUBDEV_MASKED(0x60, 0xFF)),

	IWL_DEV_INFO(iwl3160_cfg, iwl3160_2ac_name,
		     DEVICE(0x08B4)),

/* 3165 Series */
	IWL_DEV_INFO(iwl3165_2ac_cfg, iwl3165_2ac_name,
		     DEVICE(0x3165)),
	IWL_DEV_INFO(iwl3165_2ac_cfg, iwl3165_2ac_name,
		     DEVICE(0x3166)),

/* 3168 Series */
	IWL_DEV_INFO(iwl3168_2ac_cfg, iwl3168_2ac_name,
		     DEVICE(0x24FB)),

/* 7265 Series */
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2ac_name,
		     DEVICE(0x095A)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095A), SUBDEV(0x5000)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095A), SUBDEV(0x500A)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_n_name,
		     DEVICE(0x095A), SUBDEV(0x5002)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_n_name,
		     DEVICE(0x095A), SUBDEV(0x5102)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095A), SUBDEV(0x5020)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095A), SUBDEV(0x502A)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095A), SUBDEV(0x5420)),

	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2ac_name,
		     DEVICE(0x095B)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_n_name,
		     DEVICE(0x095B), SUBDEV(0x5302)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_2n_name,
		     DEVICE(0x095B), SUBDEV(0x5200)),
	IWL_DEV_INFO(iwl7265_cfg, iwl7265_n_name,
		     DEVICE(0x095B), SUBDEV(0x5202)),

/* 8000 Series */
	IWL_DEV_INFO(iwl8260_cfg, iwl8260_2ac_name,
		     DEVICE(0x24F3)),
	IWL_DEV_INFO(iwl8265_cfg, iwl8265_2ac_name,
		     DEVICE(0x24FD)),
	IWL_DEV_INFO(iwl8265_cfg, iwl8275_2ac_name,
		     DEVICE(0x24FD), SUBDEV(0x3E02)),
	IWL_DEV_INFO(iwl8265_cfg, iwl8275_2ac_name,
		     DEVICE(0x24FD), SUBDEV(0x3E01)),
	IWL_DEV_INFO(iwl8265_cfg, iwl8275_2ac_name,
		     DEVICE(0x24FD), SUBDEV(0x1012)),
	IWL_DEV_INFO(iwl8265_cfg, iwl8275_2ac_name,
		     DEVICE(0x24FD), SUBDEV(0x0012)),
/* 9000 */
	IWL_DEV_INFO(iwl9260_2ac_cfg, iwl9260_killer_1550_name,
		     DEVICE(0x2526), SUBDEV(0x1550)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_name,
		     DEVICE(0x2526), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_name,
		     DEVICE(0x2526), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_name,
		     DEVICE(0x30DC), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_name,
		     DEVICE(0x30DC), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_name,
		     DEVICE(0x31DC), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_name,
		     DEVICE(0x31DC), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_name,
		     DEVICE(0xA370), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_name,
		     DEVICE(0xA370), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_160_name,
		     DEVICE(0x54F0), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_name,
		     DEVICE(0x54F0), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_160_name,
		     DEVICE(0x51F0), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_160_name,
		     DEVICE(0x51F0), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name,
		     DEVICE(0x51F0), SUBDEV(0x1691)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name,
		     DEVICE(0x51F0), SUBDEV(0x1692)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name,
		     DEVICE(0x51F1), SUBDEV(0x1692)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name,
		     DEVICE(0x54F0), SUBDEV(0x1691)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name,
		     DEVICE(0x54F0), SUBDEV(0x1692)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name,
		     DEVICE(0x7A70), SUBDEV(0x1691)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name,
		     DEVICE(0x7A70), SUBDEV(0x1692)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name,
		     DEVICE(0x7AF0), SUBDEV(0x1691)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name,
		     DEVICE(0x7AF0), SUBDEV(0x1692)),

	IWL_DEV_INFO(iwl9260_2ac_cfg, iwl9260_1_name,
		     DEVICE(0x271C), SUBDEV(0x0214)),
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax411_killer_1690s_name,
		     DEVICE(0x7E40), SUBDEV(0x1691)),
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax411_killer_1690i_name,
		     DEVICE(0x7E40), SUBDEV(0x1692)),

/* AX200 */
	IWL_DEV_INFO(iwl_ax200_cfg_cc, iwl_ax200_name,
		     DEVICE(0x2723)),
	IWL_DEV_INFO(iwl_ax200_cfg_cc, iwl_ax200_killer_1650w_name,
		     DEVICE(0x2723), SUBDEV(0x1653)),
	IWL_DEV_INFO(iwl_ax200_cfg_cc, iwl_ax200_killer_1650x_name,
		     DEVICE(0x2723), SUBDEV(0x1654)),

	/* Qu with Hr */
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x43F0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x43F0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x43F0), SUBDEV(0x4070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x0A10)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0xA0F0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0xA0F0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x4070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0xA0F0), SUBDEV(0x6074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x6074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x02F0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x02F0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x02F0), SUBDEV(0x4070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x06F0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x06F0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x06F0), SUBDEV(0x4070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x34F0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x34F0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x34F0), SUBDEV(0x4070)),

	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x3DF0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x3DF0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x3DF0), SUBDEV(0x4070)),

	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x0070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x0074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x0078)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x007C)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650s_name,
		     DEVICE(0x4DF0), SUBDEV(0x1651)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_killer_1650i_name,
		     DEVICE(0x4DF0), SUBDEV(0x1652)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x2074)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x4070)),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name,
		     DEVICE(0x4DF0), SUBDEV(0x6074)),

	/* So with HR */
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x2725), SUBDEV(0x0090)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x0020)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x2020)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x0024)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x0510)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x0A10)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0xE020)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0xE024)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x4020)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x6020)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_name,
		     DEVICE(0x2725), SUBDEV(0x6024)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_killer_1675w_name,
		     DEVICE(0x2725), SUBDEV(0x1673)),
	IWL_DEV_INFO(iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_killer_1675x_name,
		     DEVICE(0x2725), SUBDEV(0x1674)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7A70), SUBDEV(0x0090)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7A70), SUBDEV(0x0098)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name,
		     DEVICE(0x7A70), SUBDEV(0x00B0)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7A70), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7A70), SUBDEV(0x0510)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7A70), SUBDEV(0x0A10)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7AF0), SUBDEV(0x0090)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7AF0), SUBDEV(0x0098)),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name,
		     DEVICE(0x7AF0), SUBDEV(0x00B0)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7AF0), SUBDEV(0x0310)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7AF0), SUBDEV(0x0510)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name,
		     DEVICE(0x7AF0), SUBDEV(0x0A10)),

	/* So with JF */
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_160_name,
		     DEVICE(0x7A70), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_160_name,
		     DEVICE(0x7A70), SUBDEV(0x1552)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550s_160_name,
		     DEVICE(0x7AF0), SUBDEV(0x1551)),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_killer_1550i_160_name,
		     DEVICE(0x7AF0), SUBDEV(0x1552)),

	/* SO with GF2 */
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x2726), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x2726), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x51F0), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x51F0), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x51F1), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x51F1), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x54F0), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x54F0), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x7A70), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x7A70), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x7AF0), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x7AF0), SUBDEV(0x1672)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name,
		     DEVICE(0x7F70), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name,
		     DEVICE(0x7F70), SUBDEV(0x1672)),

	/* MA with GF2 */
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax211_killer_1675s_name,
		     DEVICE(0x7E40), SUBDEV(0x1671)),
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax211_killer_1675i_name,
		     DEVICE(0x7E40), SUBDEV(0x1672)),

	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9461_160_name, MAC_TYPE(PU),
		     RF_TYPE(JF1), RF_ID(JF1),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc_80mhz, iwl9461_name, MAC_TYPE(PU),
		     RF_TYPE(JF1), RF_ID(JF1),
		     BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9462_160_name, MAC_TYPE(PU),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc_80mhz, iwl9462_name, MAC_TYPE(PU),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_2ac_cfg_soc, iwl9560_160_name, MAC_TYPE(PU),
		     RF_TYPE(JF2), RF_ID(JF),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_2ac_cfg_soc_80mhz, iwl9560_name, MAC_TYPE(PU),
		     RF_TYPE(JF2), RF_ID(JF),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9260_2ac_cfg, iwl9270_160_name, DEVICE(0x2526),
		     MAC_TYPE(TH), RF_TYPE(JF2),
		     BW_NOT_LIMITED, CORES(BT_GNSS), NO_CDB),
	IWL_DEV_INFO(iwl9260_2ac_cfg_80mhz, iwl9270_name, DEVICE(0x2526),
		     MAC_TYPE(TH), RF_TYPE(JF2),
		     BW_LIMITED, CORES(BT_GNSS), NO_CDB),

	IWL_DEV_INFO(iwl9260_2ac_cfg, iwl9162_160_name, DEVICE(0x271B),
		     MAC_TYPE(TH), RF_TYPE(JF1),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9260_2ac_cfg_80mhz, iwl9162_name, DEVICE(0x271B),
		     MAC_TYPE(TH), RF_TYPE(JF1),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9260_2ac_cfg, iwl9260_160_name, DEVICE(0x2526),
		     MAC_TYPE(TH), RF_TYPE(JF2),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9260_2ac_cfg_80mhz, iwl9260_name, DEVICE(0x2526),
		     MAC_TYPE(TH), RF_TYPE(JF2),
		     BW_LIMITED, CORES(BT), NO_CDB),

/* Qu with Jf */
	/* Qu B step */
	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9461_160_name,
		     MAC_TYPE(QU), MAC_STEP(B), RF_TYPE(JF1), RF_ID(JF1),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9461_name,
		     MAC_TYPE(QU), MAC_STEP(B), RF_TYPE(JF1), RF_ID(JF1),
		     BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9462_160_name,
		     MAC_TYPE(QU), MAC_STEP(B),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9462_name,
		     MAC_TYPE(QU), MAC_STEP(B),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9560_160_name,
		     MAC_TYPE(QU), MAC_STEP(B),
		     RF_TYPE(JF2), RF_ID(JF),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9560_name,
		     MAC_TYPE(QU), MAC_STEP(B),
		     RF_TYPE(JF2), RF_ID(JF),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9560_killer_1550s_name,
		     SUBDEV(0x1551), MAC_TYPE(QU), MAC_STEP(B), RF_TYPE(JF2)),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9560_killer_1550i_name,
		     SUBDEV(0x1552), MAC_TYPE(QU), MAC_STEP(B), RF_TYPE(JF2)),

	/* Qu C step */
	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9461_160_name,
		     MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(JF1), RF_ID(JF1),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9461_name,
		     MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(JF1), RF_ID(JF1),
		     BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9462_160_name,
		     MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9462_name,
		     MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(JF1), RF_ID(JF1_DIV),
		     BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9560_160_name, MAC_TYPE(QU),
		     MAC_STEP(C), RF_TYPE(JF2), RF_ID(JF), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9560_name, MAC_TYPE(QU),
		     MAC_STEP(C), RF_TYPE(JF2), RF_ID(JF), BW_LIMITED, CORES(BT),
		     NO_CDB),

	IWL_DEV_INFO(iwl9560_qu_jf_cfg, iwl9560_killer_1550s_name,
		     SUBDEV(0x1551), MAC_TYPE(QU), MAC_STEP(C), RF_TYPE(JF2)),
	IWL_DEV_INFO(iwl9560_qu_jf_cfg_80mhz, iwl9560_killer_1550i_name,
		     SUBDEV(0x1552), MAC_TYPE(QU), MAC_STEP(C), RF_TYPE(JF2)),

	/* QuZ */
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg, iwl9461_160_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF1), RF_ID(JF1), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg_80mhz, iwl9461_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF1), RF_ID(JF1), BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg, iwl9462_160_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg_80mhz, iwl9462_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg, iwl9560_160_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF2), RF_ID(JF), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg_80mhz, iwl9560_name, MAC_TYPE(QUZ),
		     RF_TYPE(JF2), RF_ID(JF), BW_LIMITED, CORES(BT), NO_CDB),

	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg, iwl9560_killer_1550s_name,
		     SUBDEV(0x1551), MAC_TYPE(QUZ), RF_TYPE(JF2)),
	IWL_DEV_INFO(iwl9560_quz_a0_jf_b0_cfg_80mhz, iwl9560_killer_1550i_name,
		     SUBDEV(0x1552), MAC_TYPE(QUZ), RF_TYPE(JF2)),

/* Qu with Hr */
	/* Qu B step */
	IWL_DEV_INFO(iwl_qu_hr1, iwl_ax101_name, MAC_TYPE(QU),
		     MAC_STEP(B), RF_TYPE(HR1), NO_CDB),
	IWL_DEV_INFO(iwl_qu_hr_80mhz, iwl_ax203_name, MAC_TYPE(QU), MAC_STEP(B),
		     RF_TYPE(HR2), BW_LIMITED, NO_CDB),

	/* Qu C step */
	IWL_DEV_INFO(iwl_qu_hr1, iwl_ax101_name, MAC_TYPE(QU),
		     MAC_STEP(C), RF_TYPE(HR1), NO_CDB),
	IWL_DEV_INFO(iwl_qu_hr_80mhz, iwl_ax203_name, MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(HR2), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name, MAC_TYPE(QU), MAC_STEP(C),
		     RF_TYPE(HR2), BW_NOT_LIMITED, NO_CDB),

	/* QuZ */
	IWL_DEV_INFO(iwl_qu_hr1, iwl_ax101_name, MAC_TYPE(QUZ),
		     RF_TYPE(HR1), NO_CDB),
	IWL_DEV_INFO(iwl_qu_hr_80mhz, iwl_ax203_name, MAC_TYPE(QUZ),
		     MAC_STEP(B), RF_TYPE(HR2), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_qu_hr, iwl_ax201_name, MAC_TYPE(QUZ),
		     MAC_STEP(B), RF_TYPE(HR2), BW_NOT_LIMITED, NO_CDB),

/* Ma */
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax201_name, MAC_TYPE(MA), RF_TYPE(HR2),
		     NO_CDB),
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax211_name, MAC_TYPE(MA), RF_TYPE(GF)),
	IWL_DEV_INFO(iwl_cfg_ma, iwl_ax231_name, MAC_TYPE(MA), RF_TYPE(FM),
		     NO_CDB),

/* So with Hr */
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0_80mhz, iwl_ax203_name, MAC_TYPE(SO),
		     RF_TYPE(HR2), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0_80mhz, iwl_ax101_name, MAC_TYPE(SO),
		     RF_TYPE(HR1), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0, iwl_ax201_name, MAC_TYPE(SO),
		     RF_TYPE(HR2), BW_NOT_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0, iwl_ax201_killer_1650i_name,
		     DEVICE(0x51f0), SUBDEV(0x1652),
		     MAC_TYPE(SO), RF_TYPE(HR2)),

/* So-F with Hr */
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0_80mhz, iwl_ax203_name, MAC_TYPE(SOF),
		     RF_TYPE(HR2), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0_80mhz, iwl_ax101_name, MAC_TYPE(SOF),
		     RF_TYPE(HR1), BW_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_so_a0_hr_a0, iwl_ax201_name, MAC_TYPE(SOF),
		     RF_TYPE(HR2), BW_NOT_LIMITED, NO_CDB),

/* So-F with Gf */
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name, MAC_TYPE(SOF),
		     RF_TYPE(GF), BW_NOT_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name, MAC_TYPE(SOF),
		     RF_TYPE(GF), BW_NOT_LIMITED, CDB),

/* SoF with JF2 */
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9560_160_name, MAC_TYPE(SOF),
		     RF_TYPE(JF2), RF_ID(JF), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9560_name, MAC_TYPE(SOF),
		     RF_TYPE(JF2), RF_ID(JF), BW_LIMITED, CORES(BT), NO_CDB),

/* SoF with JF */
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9461_160_name, MAC_TYPE(SOF),
		     RF_TYPE(JF1), RF_ID(JF1), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9462_160_name, MAC_TYPE(SOF),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9461_name, MAC_TYPE(SOF),
		     RF_TYPE(JF1), RF_ID(JF1), BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9462_name, MAC_TYPE(SOF),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_LIMITED, CORES(BT), NO_CDB),

/* So with GF */
	IWL_DEV_INFO(iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name, MAC_TYPE(SO),
		     RF_TYPE(GF), BW_NOT_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name, MAC_TYPE(SO),
		     RF_TYPE(GF), BW_NOT_LIMITED, CDB),

/* So with JF2 */
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9560_160_name, MAC_TYPE(SO),
		     RF_TYPE(JF2), RF_ID(JF), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9560_name, MAC_TYPE(SO),
		     RF_TYPE(JF2), RF_ID(JF), BW_LIMITED, CORES(BT), NO_CDB),

/* So with JF */
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9461_160_name, MAC_TYPE(SO),
		     RF_TYPE(JF1), RF_ID(JF1), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0, iwl9462_160_name, MAC_TYPE(SO),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_NOT_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9461_name, MAC_TYPE(SO),
		     RF_TYPE(JF1), RF_ID(JF1), BW_LIMITED, CORES(BT), NO_CDB),
	IWL_DEV_INFO(iwlax210_2ax_cfg_so_jf_b0_80mhz, iwl9462_name, MAC_TYPE(SO),
		     RF_TYPE(JF1), RF_ID(JF1_DIV), BW_LIMITED, CORES(BT), NO_CDB),

#endif /* CPTCFG_IWLMVM */
#if IS_ENABLED(CPTCFG_IWLMLD)
/* Bz */
	IWL_DEV_INFO(iwl_cfg_bz, iwl_ax201_name, MAC_TYPE(BZ), RF_TYPE(HR2)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_ax211_name, MAC_TYPE(BZ), RF_TYPE(GF)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_fm_name, MAC_TYPE(BZ), RF_TYPE(FM)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_wh_name, MAC_TYPE(BZ), RF_TYPE(WH)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_ax201_name, MAC_TYPE(BZ_W), RF_TYPE(HR2)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_ax211_name, MAC_TYPE(BZ_W), RF_TYPE(GF)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_fm_name, MAC_TYPE(BZ_W), RF_TYPE(FM)),

	IWL_DEV_INFO(iwl_cfg_bz, iwl_wh_name, MAC_TYPE(BZ_W), RF_TYPE(WH)),

/* Ga (Gl) */
	IWL_DEV_INFO(iwl_cfg_bz, iwl_gl_name, MAC_TYPE(GL), RF_TYPE(FM),
		     BW_NOT_LIMITED, NO_CDB),
	IWL_DEV_INFO(iwl_cfg_bz_160mhz, iwl_mtp_name, MAC_TYPE(GL), RF_TYPE(FM),
		     BW_LIMITED, NO_CDB),

/* Sc */
	IWL_DEV_INFO(iwl_cfg_sc, iwl_ax211_name, MAC_TYPE(SC), RF_TYPE(GF)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_fm_name, MAC_TYPE(SC), RF_TYPE(FM)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_wh_name, MAC_TYPE(SC), RF_TYPE(WH),
		     BW_NOT_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc_160mhz, iwl_sp_name, MAC_TYPE(SC), RF_TYPE(WH),
		     BW_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_pe_name, MAC_TYPE(SC), RF_TYPE(PE)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_ax211_name, MAC_TYPE(SC2), RF_TYPE(GF)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_fm_name, MAC_TYPE(SC2), RF_TYPE(FM)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_wh_name, MAC_TYPE(SC2), RF_TYPE(WH),
		     BW_NOT_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc_160mhz, iwl_sp_name, MAC_TYPE(SC2), RF_TYPE(WH),
		     BW_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_pe_name, MAC_TYPE(SC2), RF_TYPE(PE)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_ax211_name, MAC_TYPE(SC2F), RF_TYPE(GF)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_fm_name, MAC_TYPE(SC2F), RF_TYPE(FM)),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_wh_name, MAC_TYPE(SC2F), RF_TYPE(WH),
		     BW_NOT_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc_160mhz, iwl_sp_name, MAC_TYPE(SC2F), RF_TYPE(WH),
		     BW_LIMITED),
	IWL_DEV_INFO(iwl_cfg_sc, iwl_pe_name, MAC_TYPE(SC2F), RF_TYPE(PE)),

/* Dr */
	IWL_DEV_INFO(iwl_cfg_dr, iwl_dr_name, MAC_TYPE(DR)),

/* Br */
	IWL_DEV_INFO(iwl_cfg_dr, iwl_br_name, MAC_TYPE(BR)),
#endif /* CPTCFG_IWLMLD */
};
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_dev_info_table);

#if IS_ENABLED(CPTCFG_IWLWIFI_KUNIT_TESTS)
const unsigned int iwl_dev_info_table_size = ARRAY_SIZE(iwl_dev_info_table);
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_dev_info_table_size);
#endif

/*
 * Read rf id and cdb info from prph register and store it
 */
static void get_crf_id(struct iwl_trans *iwl_trans)
{
	u32 sd_reg_ver_addr;
	u32 val = 0;
	u8 step;

	if (iwl_trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_AX210)
		sd_reg_ver_addr = SD_REG_VER_GEN2;
	else
		sd_reg_ver_addr = SD_REG_VER;

	/* Enable access to peripheral registers */
	val = iwl_read_umac_prph_no_grab(iwl_trans, WFPM_CTRL_REG);
	val |= WFPM_AUX_CTL_AUX_IF_MAC_OWNER_MSK;
	iwl_write_umac_prph_no_grab(iwl_trans, WFPM_CTRL_REG, val);

	/* Read crf info */
	iwl_trans->hw_crf_id = iwl_read_prph_no_grab(iwl_trans, sd_reg_ver_addr);

	/* Read cnv info */
	iwl_trans->hw_cnv_id =
		iwl_read_prph_no_grab(iwl_trans, CNVI_AUX_MISC_CHIP);

	/* For BZ-W, take B step also when A step is indicated */
	if (CSR_HW_REV_TYPE(iwl_trans->hw_rev) == IWL_CFG_MAC_TYPE_BZ_W)
		step = SILICON_B_STEP;

	/* In BZ, the MAC step must be read from the CNVI aux register */
	if (CSR_HW_REV_TYPE(iwl_trans->hw_rev) == IWL_CFG_MAC_TYPE_BZ) {
		step = CNVI_AUX_MISC_CHIP_MAC_STEP(iwl_trans->hw_cnv_id);

		/* For BZ-U, take B step also when A step is indicated */
		if ((CNVI_AUX_MISC_CHIP_PROD_TYPE(iwl_trans->hw_cnv_id) ==
		    CNVI_AUX_MISC_CHIP_PROD_TYPE_BZ_U) &&
		    step == SILICON_A_STEP)
			step = SILICON_B_STEP;
	}

	if (CSR_HW_REV_TYPE(iwl_trans->hw_rev) == IWL_CFG_MAC_TYPE_BZ ||
	    CSR_HW_REV_TYPE(iwl_trans->hw_rev) == IWL_CFG_MAC_TYPE_BZ_W) {
		iwl_trans->hw_rev_step = step;
		iwl_trans->hw_rev |= step;
	}

	/* Read cdb info (also contains the jacket info if needed in the future */
	iwl_trans->hw_wfpm_id =
		iwl_read_umac_prph_no_grab(iwl_trans, WFPM_OTP_CFG1_ADDR);
	IWL_INFO(iwl_trans, "Detected crf-id 0x%x, cnv-id 0x%x wfpm id 0x%x\n",
		 iwl_trans->hw_crf_id, iwl_trans->hw_cnv_id,
		 iwl_trans->hw_wfpm_id);
}

/*
 * In case that there is no OTP on the NIC, map the rf id and cdb info
 * from the prph registers.
 */
static int map_crf_id(struct iwl_trans *iwl_trans)
{
	int ret = 0;
	u32 val = iwl_trans->hw_crf_id;
	u32 step_id = REG_CRF_ID_STEP(val);
	u32 slave_id = REG_CRF_ID_SLAVE(val);
	u32 jacket_id_cnv  = REG_CRF_ID_SLAVE(iwl_trans->hw_cnv_id);
	u32 jacket_id_wfpm  = WFPM_OTP_CFG1_IS_JACKET(iwl_trans->hw_wfpm_id);
	u32 cdb_id_wfpm  = WFPM_OTP_CFG1_IS_CDB(iwl_trans->hw_wfpm_id);

	/* Map between crf id to rf id */
	switch (REG_CRF_ID_TYPE(val)) {
	case REG_CRF_ID_TYPE_JF_1:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_JF1 << 12);
		break;
	case REG_CRF_ID_TYPE_JF_2:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_JF2 << 12);
		break;
	case REG_CRF_ID_TYPE_HR_NONE_CDB_1X1:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_HR1 << 12);
		break;
	case REG_CRF_ID_TYPE_HR_NONE_CDB:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_HR2 << 12);
		break;
	case REG_CRF_ID_TYPE_HR_CDB:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_HR2 << 12);
		break;
	case REG_CRF_ID_TYPE_GF:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_GF << 12);
		break;
	case REG_CRF_ID_TYPE_FM:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_FM << 12);
		break;
	case REG_CRF_ID_TYPE_WHP:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_WH << 12);
		break;
	case REG_CRF_ID_TYPE_PE:
		iwl_trans->hw_rf_id = (IWL_CFG_RF_TYPE_PE << 12);
		break;
	default:
		ret = -EIO;
		IWL_ERR(iwl_trans,
			"Can't find a correct rfid for crf id 0x%x\n",
			REG_CRF_ID_TYPE(val));
		goto out;

	}

	/* Set Step-id */
	iwl_trans->hw_rf_id |= (step_id << 8);

	/* Set CDB capabilities */
	if (cdb_id_wfpm || slave_id) {
		iwl_trans->hw_rf_id += BIT(28);
		IWL_INFO(iwl_trans, "Adding cdb to rf id\n");
	}

	/* Set Jacket capabilities */
	if (jacket_id_wfpm || jacket_id_cnv) {
		iwl_trans->hw_rf_id += BIT(29);
		IWL_INFO(iwl_trans, "Adding jacket to rf id\n");
	}

	IWL_INFO(iwl_trans,
		 "Detected rf-type 0x%x step-id 0x%x slave-id 0x%x from crf id 0x%x\n",
		 REG_CRF_ID_TYPE(val), step_id, slave_id, iwl_trans->hw_rf_id);
	IWL_INFO(iwl_trans,
		 "Detected cdb-id 0x%x jacket-id 0x%x from wfpm id 0x%x\n",
		 cdb_id_wfpm, jacket_id_wfpm, iwl_trans->hw_wfpm_id);
	IWL_INFO(iwl_trans, "Detected jacket-id 0x%x from cnvi id 0x%x\n",
		 jacket_id_cnv, iwl_trans->hw_cnv_id);

out:
	return ret;
}

/* PCI registers */
#define PCI_CFG_RETRY_TIMEOUT	0x041

VISIBLE_IF_IWLWIFI_KUNIT const struct iwl_dev_info *
iwl_pci_find_dev_info(u16 device, u16 subsystem_device,
		      u8 mac_type, u8 mac_step, u16 rf_type, u8 cdb,
		      u8 jacket, u8 rf_id, u8 bw_limit, u8 cores, u8 rf_step)
{
	int i;

	if (ARRAY_SIZE(iwl_dev_info_table) == 0)
		return NULL;

	for (i = ARRAY_SIZE(iwl_dev_info_table) - 1; i >= 0; i--) {
		const struct iwl_dev_info *dev_info = &iwl_dev_info_table[i];

		if (dev_info->device != (u16)IWL_CFG_ANY &&
		    dev_info->device != device)
			continue;

		if (dev_info->subdevice != (u16)IWL_CFG_ANY &&
		    dev_info->subdevice != (subsystem_device & dev_info->subdevice_mask))
			continue;

		if (dev_info->mac_type != (u8)IWL_CFG_ANY &&
		    dev_info->mac_type != mac_type)
			continue;

		if (dev_info->mac_step != (u8)IWL_CFG_ANY &&
		    dev_info->mac_step != mac_step)
			continue;

		if (dev_info->rf_type != (u16)IWL_CFG_ANY &&
		    dev_info->rf_type != rf_type)
			continue;

		if (dev_info->cdb != (u8)IWL_CFG_ANY &&
		    dev_info->cdb != cdb)
			continue;

		if (dev_info->jacket != (u8)IWL_CFG_ANY &&
		    dev_info->jacket != jacket)
			continue;

		if (dev_info->rf_id != (u8)IWL_CFG_ANY &&
		    dev_info->rf_id != rf_id)
			continue;

		if (dev_info->bw_limit != (u8)IWL_CFG_ANY &&
		    dev_info->bw_limit != bw_limit)
			continue;

		if (dev_info->cores != (u8)IWL_CFG_ANY &&
		    dev_info->cores != cores)
			continue;

		if (dev_info->rf_step != (u8)IWL_CFG_ANY &&
		    dev_info->rf_step != rf_step)
			continue;

		return dev_info;
	}

	return NULL;
}
EXPORT_SYMBOL_IF_IWLWIFI_KUNIT(iwl_pci_find_dev_info);

static void iwl_pcie_recheck_me_status(struct work_struct *wk)
{
	struct iwl_trans_pcie *trans_pcie = container_of(wk,
							 typeof(*trans_pcie),
							 me_recheck_wk.work);
	u32 val;

	val = iwl_read32(trans_pcie->trans, CSR_HW_IF_CONFIG_REG);
	trans_pcie->me_present = !!(val & CSR_HW_IF_CONFIG_REG_IAMT_UP);
}

static void iwl_pcie_check_me_status(struct iwl_trans *trans)
{
	struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
	u32 val;

	trans_pcie->me_present = -1;

	INIT_DELAYED_WORK(&trans_pcie->me_recheck_wk,
			  iwl_pcie_recheck_me_status);

	/* we don't have a good way of determining this until BZ */
	if (trans->trans_cfg->device_family < IWL_DEVICE_FAMILY_BZ)
		return;

	val = iwl_read_prph(trans, CNVI_SCU_REG_FOR_ECO_1);
	if (val & CNVI_SCU_REG_FOR_ECO_1_WIAMT_KNOWN) {
		trans_pcie->me_present =
			!!(val & CNVI_SCU_REG_FOR_ECO_1_WIAMT_PRESENT);
		return;
	}

	val = iwl_read32(trans, CSR_HW_IF_CONFIG_REG);
	if (val & (CSR_HW_IF_CONFIG_REG_ME_OWN |
		   CSR_HW_IF_CONFIG_REG_IAMT_UP)) {
		trans_pcie->me_present = 1;
		return;
	}

	/* recheck again later, ME might still be initializing */
	schedule_delayed_work(&trans_pcie->me_recheck_wk, HZ);
}

static int iwl_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	const struct iwl_cfg_trans_params *trans;
	const struct iwl_dev_info *dev_info;
	struct iwl_trans *iwl_trans;
	struct iwl_trans_pcie *trans_pcie;
	int ret;

	trans = (void *)ent->driver_data;

	iwl_trans = iwl_trans_pcie_alloc(pdev, trans);
	if (IS_ERR(iwl_trans))
		return PTR_ERR(iwl_trans);

	trans_pcie = IWL_TRANS_GET_PCIE_TRANS(iwl_trans);

	iwl_trans_pcie_check_product_reset_status(pdev);
	iwl_trans_pcie_check_product_reset_mode(pdev);

	/*
	 * Let's try to grab NIC access early here. Sometimes, NICs may
	 * fail to initialize, and if that happens it's better if we see
	 * issues early on (and can reprobe, per the logic inside), than
	 * first trying to load the firmware etc. and potentially only
	 * detecting any problems when the first interface is brought up.
	 */
	ret = iwl_pcie_prepare_card_hw(iwl_trans);
	if (!ret) {
		ret = iwl_finish_nic_init(iwl_trans);
		if (ret)
			goto out_free_trans;
		if (iwl_trans_grab_nic_access(iwl_trans)) {
			get_crf_id(iwl_trans);
			/* all good */
			iwl_trans_release_nic_access(iwl_trans);
		} else {
			ret = -EIO;
			goto out_free_trans;
		}
	}

	iwl_trans->hw_rf_id = iwl_read32(iwl_trans, CSR_HW_RF_ID);

	/*
	 * The RF_ID is set to zero in blank OTP so read version to
	 * extract the RF_ID.
	 * This is relevant only for family 9000 and up.
	 */
	if (iwl_trans->trans_cfg->rf_id &&
	    iwl_trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_9000 &&
	    !CSR_HW_RFID_TYPE(iwl_trans->hw_rf_id) && map_crf_id(iwl_trans)) {
		ret = -EINVAL;
		goto out_free_trans;
	}

	IWL_INFO(iwl_trans, "PCI dev %04x/%04x, rev=0x%x, rfid=0x%x\n",
		 pdev->device, pdev->subsystem_device,
		 iwl_trans->hw_rev, iwl_trans->hw_rf_id);

	dev_info = iwl_pci_find_dev_info(pdev->device, pdev->subsystem_device,
					 CSR_HW_REV_TYPE(iwl_trans->hw_rev),
					 iwl_trans->hw_rev_step,
					 CSR_HW_RFID_TYPE(iwl_trans->hw_rf_id),
					 CSR_HW_RFID_IS_CDB(iwl_trans->hw_rf_id),
					 CSR_HW_RFID_IS_JACKET(iwl_trans->hw_rf_id),
					 IWL_SUBDEVICE_RF_ID(pdev->subsystem_device),
					 IWL_SUBDEVICE_BW_LIM(pdev->subsystem_device),
					 IWL_SUBDEVICE_CORES(pdev->subsystem_device),
					 CSR_HW_RFID_STEP(iwl_trans->hw_rf_id));
	if (dev_info) {
		iwl_trans->cfg = dev_info->cfg;
		iwl_trans->name = dev_info->name;
	}

#if IS_ENABLED(CPTCFG_IWLMVM)

	/*
	 * special-case 7265D, it has the same PCI IDs.
	 *
	 * Note that because we already pass the cfg to the transport above,
	 * all the parameters that the transport uses must, until that is
	 * changed, be identical to the ones in the 7265D configuration.
	 */
	if (iwl_trans->cfg == &iwl7265_cfg &&
	    (iwl_trans->hw_rev & CSR_HW_REV_TYPE_MSK) == CSR_HW_REV_TYPE_7265D)
		iwl_trans->cfg = &iwl7265d_cfg;
#endif
	if (!iwl_trans->cfg) {
		pr_err("No config found for PCI dev %04x/%04x, rev=0x%x, rfid=0x%x\n",
		       pdev->device, pdev->subsystem_device,
		       iwl_trans->hw_rev, iwl_trans->hw_rf_id);
		ret = -EINVAL;
		goto out_free_trans;
	}

	IWL_INFO(iwl_trans, "Detected %s\n", iwl_trans->name);

	if (iwl_trans->trans_cfg->mq_rx_supported) {
		if (WARN_ON(!iwl_trans->cfg->num_rbds)) {
			ret = -EINVAL;
			goto out_free_trans;
		}
		trans_pcie->num_rx_bufs = iwl_trans->cfg->num_rbds;
	} else {
		trans_pcie->num_rx_bufs = RX_QUEUE_SIZE;
	}

	if (!iwl_trans->trans_cfg->integrated) {
		u16 link_status;

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);

		iwl_trans->pcie_link_speed =
			u16_get_bits(link_status, PCI_EXP_LNKSTA_CLS);
	}

	ret = iwl_trans_init(iwl_trans);
	if (ret)
		goto out_free_trans;

	pci_set_drvdata(pdev, iwl_trans);

	iwl_pcie_check_me_status(iwl_trans);

	/* try to get ownership so that we'll know if we don't own it */
	iwl_pcie_prepare_card_hw(iwl_trans);

	iwl_trans->drv = iwl_drv_start(iwl_trans);

	if (IS_ERR(iwl_trans->drv)) {
		ret = PTR_ERR(iwl_trans->drv);
		goto out_free_trans;
	}

	/* register transport layer debugfs here */
	iwl_trans_pcie_dbgfs_register(iwl_trans);

	return 0;

out_free_trans:
	iwl_trans_pcie_free(iwl_trans);
	return ret;
}

static void iwl_pci_remove(struct pci_dev *pdev)
{
	struct iwl_trans *trans = pci_get_drvdata(pdev);
	struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);

	if (!trans)
		return;

	cancel_delayed_work_sync(&trans_pcie->me_recheck_wk);

	iwl_drv_stop(trans->drv);

	iwl_trans_pcie_free(trans);
}

#ifdef CONFIG_PM_SLEEP

static int iwl_pci_suspend(struct device *device)
{
	/* Before you put code here, think about WoWLAN. You cannot check here
	 * whether WoWLAN is enabled or not, and your code will run even if
	 * WoWLAN is enabled - don't kill the NIC, someone may need it in Sx.
	 */

	return 0;
}

static int _iwl_pci_resume(struct device *device, bool restore)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct iwl_trans *trans = pci_get_drvdata(pdev);
	struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
	bool device_was_powered_off = false;

	/* Before you put code here, think about WoWLAN. You cannot check here
	 * whether WoWLAN is enabled or not, and your code will run even if
	 * WoWLAN is enabled - the NIC may be alive.
	 */

	/*
	 * We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state.
	 */
	pci_write_config_byte(pdev, PCI_CFG_RETRY_TIMEOUT, 0x00);

	if (!trans->op_mode)
		return 0;

	/*
	 * Scratch value was altered, this means the device was powered off, we
	 * need to reset it completely.
	 * Note: MAC (bits 0:7) will be cleared upon suspend even with wowlan,
	 * so assume that any bits there mean that the device is usable.
	 */
	if (trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_BZ &&
	    !iwl_read32(trans, CSR_FUNC_SCRATCH))
		device_was_powered_off = true;

	if (restore || device_was_powered_off) {
		trans->state = IWL_TRANS_NO_FW;
		/* Hope for the best here ... If one of those steps fails we
		 * won't really know how to recover.
		 */
		iwl_pcie_prepare_card_hw(trans);
		iwl_finish_nic_init(trans);
		iwl_op_mode_device_powered_off(trans->op_mode);
	}

	/* In WOWLAN, let iwl_trans_pcie_d3_resume do the rest of the work */
	if (test_bit(STATUS_DEVICE_ENABLED, &trans->status))
		return 0;

	/* reconfigure the MSI-X mapping to get the correct IRQ for rfkill */
	iwl_pcie_conf_msix_hw(trans_pcie);

	/*
	 * Enable rfkill interrupt (in order to keep track of the rfkill
	 * status). Must be locked to avoid processing a possible rfkill
	 * interrupt while in iwl_pcie_check_hw_rf_kill().
	 */
	mutex_lock(&trans_pcie->mutex);
	iwl_enable_rfkill_int(trans);
	iwl_pcie_check_hw_rf_kill(trans);
	mutex_unlock(&trans_pcie->mutex);

	return 0;
}

static int iwl_pci_restore(struct device *device)
{
	return _iwl_pci_resume(device, true);
}

static int iwl_pci_resume(struct device *device)
{
	return _iwl_pci_resume(device, false);
}

static const struct dev_pm_ops iwl_dev_pm_ops = {
	.suspend = pm_sleep_ptr(iwl_pci_suspend),
	.resume = pm_sleep_ptr(iwl_pci_resume),
	.freeze = pm_sleep_ptr(iwl_pci_suspend),
	.thaw = pm_sleep_ptr(iwl_pci_resume),
	.poweroff = pm_sleep_ptr(iwl_pci_suspend),
	.restore = pm_sleep_ptr(iwl_pci_restore),
};

#define IWL_PM_OPS	(&iwl_dev_pm_ops)

#else /* CONFIG_PM_SLEEP */

#define IWL_PM_OPS	NULL

#endif /* CONFIG_PM_SLEEP */

static struct pci_driver iwl_pci_driver = {
	.name = DRV_NAME,
	.id_table = iwl_hw_card_ids,
	.probe = iwl_pci_probe,
	.remove = iwl_pci_remove,
	.driver.pm = IWL_PM_OPS,
};

int __must_check iwl_pci_register_driver(void)
{
	int ret;
	ret = pci_register_driver(&iwl_pci_driver);
	if (ret)
		pr_err("Unable to initialize PCI module\n");

	return ret;
}

void iwl_pci_unregister_driver(void)
{
	pci_unregister_driver(&iwl_pci_driver);
}
