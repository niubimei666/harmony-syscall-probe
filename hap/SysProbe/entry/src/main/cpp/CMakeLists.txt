cmake_minimum_required(VERSION 3.5.0)
project(sysprobe)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)

# 主探针模块（syscall 能力地图）
add_library(entry SHARED sysprobe.cpp)
target_link_libraries(entry PUBLIC libace_napi.z.so libhilog_ndk.z.so)

# 执行测试模块（fork + execve 一个静态 ELF）
add_library(execprobe SHARED execprobe.cpp)
target_link_libraries(execprobe PUBLIC libace_napi.z.so libhilog_ndk.z.so)

# dlopen 测试模块（把 .so 映射进当前进程）
add_library(dlprobe SHARED dlprobe.cpp)
target_link_libraries(dlprobe PUBLIC libace_napi.z.so libhilog_ndk.z.so libdl.so)

# 被 dlopen 的目标库：纯 C、不链接任何运行时
add_library(probelib SHARED probelib.c)
set_target_properties(probelib PROPERTIES LINK_FLAGS "-nostdlib" C_VISIBILITY_PRESET default)
