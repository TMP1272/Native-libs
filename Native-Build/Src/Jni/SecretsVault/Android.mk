LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := secretsvault
LOCAL_SRC_FILES := decrypt.cpp Include/aes.h
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../../../Include

LOCAL_CFLAGS += -Os -ffunction-sections -fdata-sections
LOCAL_LDFLAGS += -Wl,--gc-sections
LOCAL_LDLIBS += -llog

include $(BUILD_SHARED_LIBRARY)
