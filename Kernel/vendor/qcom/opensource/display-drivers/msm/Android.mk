DISPLAY_SELECT := CONFIG_DRM_MSM=m

LOCAL_PATH := $(call my-dir)
LOCAL_MODULE_DDK_BUILD := true
include $(CLEAR_VARS)

BOARD_OPENSOURCE_DIR ?= vendor/qcom/opensource
BOARD_COMMON_DIR ?= device/qcom/common

# This makefile is only for DLKM
ifneq ($(findstring vendor,$(LOCAL_PATH)),)

ifneq ($(findstring opensource,$(LOCAL_PATH)),)
	DISPLAY_BLD_DIR := $(TOP)/$(BOARD_OPENSOURCE_DIR)/display-drivers
endif # opensource

DLKM_DIR := $(TOP)/$(BOARD_COMMON_DIR)/dlkm

LOCAL_ADDITIONAL_DEPENDENCIES := $(wildcard $(LOCAL_PATH)/**/*) $(wildcard $(LOCAL_PATH)/*)

# Build display.ko as msm_drm.ko
###########################################################
# This is set once per LOCAL_PATH, not per (kernel) module
KBUILD_OPTIONS := DISPLAY_ROOT=$(DISPLAY_BLD_DIR)
KBUILD_OPTIONS += MODNAME=msm_drm
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += $(DISPLAY_SELECT)

ifneq ($(TARGET_BOARD_AUTO),true)
ifeq ($(CONFIG_MSM_MMRM), y)
	KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS+=$(PWD)/$(call intermediates-dir-for,DLKM,mmrm-module-symvers)/Module.symvers
endif
ifneq ($(call is-board-platform-in-list, taro monaco), true)
	KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS+=$(PWD)/$(call intermediates-dir-for,DLKM,sync-fence-module-symvers)/Module.symvers
	KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS+=$(PWD)/$(call intermediates-dir-for,DLKM,msm-ext-disp-module-symvers)/Module.symvers
	KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS+=$(PWD)/$(call intermediates-dir-for,DLKM,hw-fence-module-symvers)/Module.symvers
	ifeq ($(CONFIG_HDCP_QSEECOM), y)
	KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS+=$(PWD)/$(call intermediates-dir-for,DLKM,sec-module-symvers)/Module.symvers
	endif
endif
endif

###########################################################
include $(CLEAR_VARS)
LOCAL_SRC_FILES   := $(wildcard $(LOCAL_PATH)/**/*) $(wildcard $(LOCAL_PATH)/*)
LOCAL_MODULE              := msm_drm.ko
LOCAL_MODULE_KBUILD_NAME  := msm_drm.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_DEBUG_ENABLE := true
LOCAL_MODULE_PATH         := $(KERNEL_MODULES_OUT)

ifneq ($(TARGET_BOARD_AUTO),true)
ifeq ($(CONFIG_MSM_MMRM), y)
	LOCAL_REQUIRED_MODULES    += mmrm-module-symvers
	LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,DLKM,mmrm-module-symvers)/Module.symvers
endif
ifneq ($(call is-board-platform-in-list, taro monaco), true)
	LOCAL_REQUIRED_MODULES    += sync-fence-module-symvers
	LOCAL_REQUIRED_MODULES    += msm-ext-disp-module-symvers
	LOCAL_REQUIRED_MODULES    += hw-fence-module-symvers
	ifeq ($(CONFIG_HDCP_QSEECOM), y)
	LOCAL_REQUIRED_MODULES    += sec-module-symvers
	endif
	LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,DLKM,sync-fence-module-symvers)/Module.symvers
	LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,DLKM,msm-ext-disp-module-symvers)/Module.symvers
	LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,DLKM,hw-fence-module-symvers)/Module.symvers
	ifeq ($(CONFIG_HDCP_QSEECOM), y)
	LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,DLKM,sec-module-symvers)/Module.symvers
	endif
endif
endif

include $(DLKM_DIR)/Build_external_kernelmodule.mk

# CONFIG_DISPLAY_SAMSUNG start
# include panel Android.mk file to make PDF.h file.
SAMSUNG_MK := $(wildcard $(DISPLAY_BLD_DIR)/msm/samsung/**/*.mk)
ifneq ($(strip $(SAMSUNG_MK) ), )
	include $(DISPLAY_BLD_DIR)/msm/samsung/**/*.mk
endif
$(info sec_display_Kconfig = $(shell cat $(DISPLAY_BLD_DIR)/sec_display_Kconfig))
$(info sec_display_defconfig = $(shell cat $(DISPLAY_BLD_DIR)/sec_display_defconfig))
# CONFIG_DISPLAY_SAMSUNG end

###########################################################
endif # DLKM check
