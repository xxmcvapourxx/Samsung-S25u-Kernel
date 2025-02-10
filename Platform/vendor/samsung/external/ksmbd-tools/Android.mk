#########################################################################################################################################################
# KSMBD with Android NDK build
#########################################################################################################################################################

LOCAL_PATH := $(call my-dir)

############################################################ KSMBD project flags ######################################################################

ANDROID_DIR := /data/misc/hwrs

KSMB_DIR_CONFIG_CFLAGS                                                                  := \
    -DSYSCONFDIR=\"$(ANDROID_DIR)\"                                                        \
    -DRUNSTATEDIR=\"$(ANDROID_DIR)\"                                                       \
    $(NULL)

COMMON_CFLAGS :=                                                                           \
    -fno-common                                                                            \
    -DHAVE_CONFIG_H                                                                        \
    $(NULL)


GLIB_INCLUDES                                                                           := \
    $(LOCAL_PATH)/prebuilt/include/glib-2.0                                                \
    $(NULL)

ifneq ($(wildcard external/libnl),)
LIBNL_INCLUDES                                                                          := \
    external/libnl/include                                                                 \
    $(NULL)
else
LIBNL_INCLUDES                                                                          := \
    external/libnl-headers                                                                 \
    $(NULL)
endif

KSMBD_INCLUDES                                                                          := \
    $(LOCAL_PATH)                                                                          \
    $(LOCAL_PATH)/include                                                                  \
    $(NULL)

############################################################ Prebuilt Libraries #######################################################################

include $(CLEAR_VARS)
LOCAL_MODULE := glibc-2.0-prebuilt
LOCAL_SRC_FILES := prebuilt/libglib-2.0.a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MULTILIB := first
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := intl-prebuilt
LOCAL_SRC_FILES := prebuilt/libintl.a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MULTILIB := first
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := iconv-prebuilt
LOCAL_SRC_FILES := prebuilt/libiconv.a
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MULTILIB := first
include $(BUILD_PREBUILT)

############################### addshare ###############################

include $(CLEAR_VARS)
LOCAL_MODULE := addshare
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS                                                                            := \
    $(KSMB_DIR_CONFIG_CFLAGS)                                                              \
    $(GLIB_CFLAGS)                                                                         \
    $(COMMON_CFLAGS)                                                                       \
    $(LIBNL_INCLUDES)                                                                      \
    -Wno-switch                                                                            \
    $(NULL)

LOCAL_C_INCLUDES                                                                        := \
    $(KSMBD_INCLUDES)                                                                      \
    $(GLIB_INCLUDES)                                                                       \
    $(LOCAL_PATH)/addshare                                                                 \
    $(NULL)

LOCAL_SRC_FILES                                                                         := \
    addshare/addshare.c                                                                    \
    addshare/share_admin.c                                                                 \
    $(NULL)

include $(BUILD_STATIC_LIBRARY)

############################### adduser ###############################
include $(CLEAR_VARS)
LOCAL_MODULE := adduser
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS                                                                            := \
    $(KSMB_DIR_CONFIG_CFLAGS)                                                              \
    $(GLIB_CFLAGS)                                                                         \
    $(LIBNL_CFLAGS)                                                                        \
    $(COMMON_CFLAGS)                                                                       \
    $(NULL)

LOCAL_C_INCLUDES                                                                        := \
    $(KSMBD_INCLUDES)                                                                      \
    $(GLIB_INCLUDES)                                                                       \
    $(LIBNL_INCLUDES)                                                                      \
    $(LOCAL_PATH)/adduser                                                                  \
    $(NULL)

LOCAL_SRC_FILES                                                                         := \
    adduser/adduser.c                                                                      \
    adduser/user_admin.c                                                                   \
    adduser/md4_hash.c                                                                     \
    $(NULL)

include $(BUILD_STATIC_LIBRARY)

############################### control ###############################
include $(CLEAR_VARS)
LOCAL_MODULE := control
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS                                                                            := \
    $(KSMB_DIR_CONFIG_CFLAGS)                                                              \
    $(GLIB_CFLAGS)                                                                         \
    $(LIBNL_CFLAGS)                                                                        \
    $(COMMON_CFLAGS)                                                                       \
    $(NULL)

LOCAL_C_INCLUDES                                                                        := \
    $(KSMBD_INCLUDES)                                                                      \
    $(GLIB_INCLUDES)                                                                       \
    $(LIBNL_INCLUDES)                                                                      \
    $(LOCAL_PATH)/control                                                                  \
    $(NULL)

LOCAL_SRC_FILES                                                                         := \
    control/control.c                                                                      \
    $(NULL)

include $(BUILD_STATIC_LIBRARY)

############################### mountd ###############################
include $(CLEAR_VARS)
LOCAL_MODULE := mountd
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS                                                                            := \
    $(KSMB_DIR_CONFIG_CFLAGS)                                                              \
    $(GLIB_CFLAGS)                                                                         \
    $(LIBNL_CFLAGS)                                                                        \
    $(COMMON_CFLAGS)                                                                       \
    $(NULL)

LOCAL_C_INCLUDES                                                                        := \
    $(KSMBD_INCLUDES)                                                                      \
    $(GLIB_INCLUDES)                                                                       \
    $(LIBNL_INCLUDES)                                                                      \
    $(LOCAL_PATH)/mount                                                                    \
    $(NULL)

LOCAL_SRC_FILES                                                                         := \
    mountd/worker.c                                                                        \
    mountd/ipc.c                                                                           \
    mountd/rpc.c                                                                           \
    mountd/rpc_srvsvc.c                                                                    \
    mountd/rpc_wkssvc.c                                                                    \
    mountd/mountd.c                                                                        \
    mountd/smbacl.c                                                                        \
    mountd/rpc_samr.c                                                                      \
    mountd/rpc_lsarpc.c                                                                    \
    $(NULL)

include $(BUILD_STATIC_LIBRARY)


############################### tools ###############################
include $(CLEAR_VARS)

LOCAL_MODULE := ksmbd.tools
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS                                                                           := \
    $(KSMB_DIR_CONFIG_CFLAGS)                                                             \
    $(GLIB_CFLAGS)                                                                        \
    $(COMMON_CFLAGS)                                                                      \
    -Wno-sometimes-uninitialized                                                          \
    -Wno-switch                                                                           \
    $(NULL)

LOCAL_C_INCLUDES                                                                       := \
    $(KSMBD_INCLUDES)                                                                     \
    $(GLIB_INCLUDES)                                                                      \
    $(LOCAL_PATH)/tools                                                                   \
    $(NULL)

LOCAL_SRC_FILES                                                                        := \
    tools/management/tree_conn.c                                                          \
    tools/management/user.c                                                               \
    tools/management/share.c                                                              \
    tools/management/session.c                                                            \
    tools/config_parser.c                                                                 \
    tools/tools.c                                                                         \
    $(NULL)

LOCAL_STATIC_LIBRARIES                                                                 := \
    glibc-2.0-prebuilt                                                                    \
    intl-prebuilt                                                                         \
    iconv-prebuilt                                                                        \
    adduser                                                                               \
    addshare                                                                              \
    control                                                                               \
    mountd                                                                                \
    $(NULL)

ifneq ($(wildcard external/libnl),)
LOCAL_SHARED_LIBRARIES                                                                 := \
    libnl                                                                                 \
    $(NULL)
else
LOCAL_SHARED_LIBRARIES                                                                 := \
    libnl_2                                                                               \
    $(NULL)
endif

LOCAL_POST_INSTALL_CMD := \
    ln -sf /system/bin/ksmbd.tools $(TARGET_OUT)/bin/ksmbd.adduser;                       \
    ln -sf /system/bin/ksmbd.tools $(TARGET_OUT)/bin/ksmbd.addshare;                      \
    ln -sf /system/bin/ksmbd.tools $(TARGET_OUT)/bin/ksmbd.control;                       \
    ln -sf /system/bin/ksmbd.tools $(TARGET_OUT)/bin/ksmbd.mountd;                        \
	
include $(BUILD_EXECUTABLE)
