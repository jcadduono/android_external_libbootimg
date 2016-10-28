LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libbootimg-static
LOCAL_SRC_FILES := libbootimg.c mincrypt/sha.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS += -Os
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libbootimg
LOCAL_SRC_FILES := libbootimg.c mincrypt/sha.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_MODULE_TAGS := optional
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := bootimg
LOCAL_SRC_FILES := bootimg.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_STATIC_LIBRARIES := libbootimg-static
#LOCAL_CFLAGS := -DDEBUG
#LOCAL_SHARED_LIBRARIES := liblog
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := libbootimg
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_SRC_FILES := libbootimg.c mincrypt/sha.c
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := bootimg
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_SRC_FILES := bootimg.c
LOCAL_SHARED_LIBRARIES := libbootimg
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_EXECUTABLE)
