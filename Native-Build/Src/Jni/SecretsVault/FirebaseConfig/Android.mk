LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE       := firebaseconfig
LOCAL_SRC_FILES    := FirebaseConfig/decryptfisecoig.cpp $(LOCAL_PATH)/Include/aes.c
LOCAL_C_INCLUDES   := $(LOCAL_PATH)/Include
LOCAL_STRIP_MODULE := true

LOCAL_LDLIBS  += -llog
LOCAL_CFLAGS  += -O3 -flto -ffunction-sections -fdata-sections -fvisibility=hidden
LOCAL_LDFLAGS += -s -flto -Wl,--gc-sections

include $(BUILD_SHARED_LIBRARY)
