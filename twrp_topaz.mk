#
# Copyright (C) 2025 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#

DEVICE_PATH := device/lenovo/topaz

# Inherit from device.mk configuration
$(call inherit-product, $(DEVICE_PATH)/device.mk)

# Release name
PRODUCT_RELEASE_NAME := tb710fu

## Device identifier
PRODUCT_DEVICE := topaz
PRODUCT_NAME := twrp_topaz
PRODUCT_BRAND := lenovo
PRODUCT_SYSTEM_DEVICE := TB710FU
PRODUCT_MODEL := TB710FU
PRODUCT_MANUFACTURER := lenovo


# Assert
TARGET_OTA_ASSERT_DEVICE := $(PRODUCT_RELEASE_NAME)

# Theme
TW_STATUS_ICONS_ALIGN := center
TW_Y_OFFSET := 111
TW_H_OFFSET := -111