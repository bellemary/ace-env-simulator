LOCAL_PATH := $(call my-dir)

# ===== 共享库 (JNI 接口) =====
include $(CLEAR_VARS)
LOCAL_MODULE := aceprobe
LOCAL_SRC_FILES := ace_probe.cpp
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# ===== 独立扫描二进制 (root 执行, process_vm_readv) =====
include $(CLEAR_VARS)
LOCAL_MODULE := ace_scanner
LOCAL_SRC_FILES := ace_scanner.cpp
LOCAL_CFLAGS := -Wall -Wextra -O2
LOCAL_LDLIBS := -llog
include $(BUILD_EXECUTABLE)
