LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE        := firebaseconfig
LOCAL_SRC_FILES     := decryptfisecoig.cpp ../../../../../Include/aes.c
LOCAL_C_INCLUDES    := $(LOCAL_PATH)/../../../../../Include
LOCAL_STRIP_MODULE  := true
LOCAL_CFLAGS        += -O3 -flto -ffunction-sections -fdata-sections -fvisibility=hidden
LOCAL_LDFLAGS       += -s -flto -Wl,--gc-sections
LOCAL_LDLIBS        += -llog
include $(BUILD_SHARED_LIBRARY)
