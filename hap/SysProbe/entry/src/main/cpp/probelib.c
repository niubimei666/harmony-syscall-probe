/*
 * 最小共享库，用来验证应用沙箱能否 dlopen。
 *
 * 关键：不链接 libc++_shared.so。
 * 否则 dlopen 会因找不到 C++ 运行时依赖报 "No error information"，
 * 那不是沙箱限制，是构建问题。
 *
 * 构建：先编译成 .so，再 strip，然后 base64 内嵌进 ArkTS。
 * 必须确认符号是 GLOBAL DEFAULT，否则 dlsym 找不到。
 */

__attribute__((visibility("default"))) int probe_answer(void) {
    return 42;
}

__attribute__((visibility("default"))) const char* probe_hello(void) {
    return "DLOPEN_OK";
}
