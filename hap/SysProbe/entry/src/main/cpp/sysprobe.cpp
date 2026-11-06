/*
 * SysProbe NAPI 模块 —— 鸿蒙应用沙箱 syscall 能力探针
 *
 * 核心思路：不「执行一个 ELF 文件」，而是直接在应用进程里内联汇编发 svc #0。
 *   1. 跑在自己沙箱里，绕开对 /data/local/tmp 的 execute 限制
 *   2. 拿到真实返回值 + errno，比只吞 exit code 精确（能区分 ENOSYS / EPERM / EFAULT）
 *   3. 测的就是 App 进程上下文
 *
 * 信号安全（重要，见文末注释）：
 *   - 所有跨 siglongjmp 的状态都放在 volatile 全局里
 *   - 测完恢复「原始」handler，绝不设成 SIG_DFL
 *   - 用 sigprocmask 在测试区间屏蔽这批信号，避免 pending 信号重入
 *   - 不用 SA_NODEFER
 */

#include <napi/native_api.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------- 信号状态

constexpr int kSignals[] = {SIGSYS, SIGSEGV, SIGBUS, SIGILL};
constexpr int kSignalCount = 4;

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_caught_sig = 0;
static volatile sig_atomic_t g_in_probe = 0;

static struct sigaction g_old[kSignalCount];
static bool g_old_valid = false;

static sigset_t g_old_mask;
static bool g_mask_saved = false;

static void ResetCaught() {
    g_caught_sig = 0;
}

static void ResetJmp() {
    memset(&g_jmp, 0, sizeof(g_jmp));
}

static void ProbeSignalHandler(int sig) {
    g_caught_sig = sig;
    if (g_in_probe) {
        g_in_probe = 0;
        siglongjmp(g_jmp, 1);
    }
    // 不在探针里还收到这些信号，说明别处真出问题了，直接结束避免死循环
    _exit(128 + sig);
}

static void InstallHandlers() {
    if (!g_old_valid) {
        for (int i = 0; i < kSignalCount; i++) {
            sigaction(kSignals[i], nullptr, &g_old[i]);
        }
        g_old_valid = true;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ProbeSignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   // 不用 SA_NODEFER
    for (int i = 0; i < kSignalCount; i++) {
        sigaction(kSignals[i], &sa, nullptr);
    }

    if (!g_mask_saved) {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSYS);
        sigaddset(&mask, SIGSEGV);
        sigaddset(&mask, SIGBUS);
        sigaddset(&mask, SIGILL);
        sigprocmask(SIG_BLOCK, &mask, &g_old_mask);
        g_mask_saved = true;
    }
}

static void RestoreHandlers() {
    if (!g_mask_saved) {
        return;
    }
    sigprocmask(SIG_SETMASK, &g_old_mask, nullptr);
    g_mask_saved = false;

    if (!g_old_valid) {
        return;
    }
    for (int i = 0; i < kSignalCount; i++) {
        sigaction(kSignals[i], &g_old[i], nullptr);
    }
}

// ---------------------------------------------------------------- 探针结果
// 用文件作用域变量记录，避免 longjmp 后读到未定义值

static volatile long g_ret;
static volatile int g_err;
static volatile int g_caught;

static void DoSyscall(long nr) {
    g_ret = 0;
    g_err = 0;
    g_caught = 0;
    ResetCaught();
    ResetJmp();

    sigjmp_buf local_jmp;
    if (sigsetjmp(local_jmp, 1) == 0) {
        g_in_probe = 1;
        errno = 0;
        // 6 个参数全 0，用内联汇编直发 svc，确保寄存器状态可控
        register long x8 __asm__("x8") = nr;
        register long x0 __asm__("x0") = 0;
        register long x1 __asm__("x1") = 0;
        register long x2 __asm__("x2") = 0;
        register long x3 __asm__("x3") = 0;
        register long x4 __asm__("x4") = 0;
        register long x5 __asm__("x5") = 0;
        __asm__ volatile(
            "svc #0"
            : "+r"(x0)
            : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
            : "memory");
        g_in_probe = 0;
        g_ret = x0;
        g_err = errno;
    } else {
        g_in_probe = 0;
        g_caught = (int)g_caught_sig;
        g_ret = -1;
        g_err = EINTR;
    }
    ResetJmp();
}

// ---------------------------------------------------------------- 判定

static const char* Classify() {
    if (g_caught == SIGSYS) {
        return "KILL(SIGSYS)";
    }
    if (g_caught == SIGSEGV) {
        return "SIGSEGV";
    }
    if (g_caught == SIGBUS) {
        return "SIGBUS";
    }
    if (g_caught == SIGILL) {
        return "SIGILL";
    }
    if (g_caught != 0) {
        return "SIGNAL";
    }
    if (g_ret == -1) {
        if (g_err == ENOSYS) {
            return "ENOSYS";
        }
        if (g_err == EPERM || g_err == EACCES) {
            return "EPERM";
        }
        if (g_err == EFAULT) {
            return "ALLOWED(EFAULT)";
        }
        if (g_err == EINVAL) {
            return "ALLOWED(EINVAL)";
        }
        if (g_err == EBADF) {
            return "ALLOWED(EBADF)";
        }
        return "ERRNO";
    }
    return "ALLOWED";
}

// ---------------------------------------------------------------- NAPI：批量

static napi_value RunProbes(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    std::vector<long> numbers;
    if (argc >= 1) {
        napi_valuetype t;
        napi_typeof(env, argv[0], &t);
        if (t == napi_string) {
            size_t len = 0;
            napi_get_value_string_utf8(env, argv[0], nullptr, 0, &len);
            std::string buf(len + 1, '\0');
            napi_get_value_string_utf8(env, argv[0], &buf[0], len + 1, &len);
            buf.resize(len);
            size_t pos = 0;
            while (pos < buf.size()) {
                size_t comma = buf.find(',', pos);
                if (comma == std::string::npos) {
                    comma = buf.size();
                }
                std::string tok = buf.substr(pos, comma - pos);
                if (!tok.empty()) {
                    numbers.push_back(strtol(tok.c_str(), nullptr, 10));
                }
                pos = comma + 1;
            }
        }
    }
    if (numbers.empty()) {
        for (long i = 0; i <= 461; i++) {
            numbers.push_back(i);
        }
    }

    InstallHandlers();

    std::string json = "[";
    bool first = true;
    for (size_t i = 0; i < numbers.size(); i++) {
        long nr = numbers[i];
        DoSyscall(nr);
        char item[256];
        snprintf(item, sizeof(item),
                 "{\"nr\":%ld,\"ret\":%ld,\"errno\":%d,\"caught\":%d,\"verdict\":\"%s\"}",
                 nr, (long)g_ret, (int)g_err, (int)g_caught, Classify());
        if (!first) {
            json += ",";
        }
        first = false;
        json += item;
    }
    json += "]";

    RestoreHandlers();

    napi_value out;
    napi_create_string_utf8(env, json.c_str(), json.size(), &out);
    return out;
}

// ---------------------------------------------------------------- NAPI：单步 + 落盘
// 每测一项就把结果 append 到文件并 fsync，进程被 SECCOMP_RET_KILL 杀掉后
// 文件里仍保留已完成的项。

static napi_value RunOnePersist(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    long nr = 0;
    if (argc >= 1) {
        napi_get_value_int64(env, argv[0], &nr);
    }
    std::string path;
    if (argc >= 2) {
        size_t len = 0;
        napi_get_value_string_utf8(env, argv[1], nullptr, 0, &len);
        path.resize(len + 1, '\0');
        napi_get_value_string_utf8(env, argv[1], &path[0], len + 1, &len);
        path.resize(len);
    }

    InstallHandlers();
    DoSyscall(nr);
    char item[256];
    snprintf(item, sizeof(item),
             "{\"nr\":%ld,\"ret\":%ld,\"errno\":%d,\"caught\":%d,\"verdict\":\"%s\"}",
             nr, (long)g_ret, (int)g_err, (int)g_caught, Classify());
    RestoreHandlers();

    if (!path.empty()) {
        FILE* f = fopen(path.c_str(), "a");
        if (f != nullptr) {
            fputs(item, f);
            fputc('\n', f);
            fflush(f);
            fsync(fileno(f));   // 关键：不 fsync 的话进程被杀时数据还在页缓存
            fclose(f);
        }
    }

    napi_value out;
    napi_create_string_utf8(env, item, strlen(item), &out);
    return out;
}

// ---------------------------------------------------------------- NAPI：文件工具

static napi_value AppendLine(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc < 2) {
        napi_value out;
        napi_create_string_utf8(env, "bad-args", 8, &out);
        return out;
    }

    size_t len = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &len);
    std::string path(len + 1, '\0');
    napi_get_value_string_utf8(env, argv[0], &path[0], len + 1, &len);
    path.resize(len);

    len = 0;
    napi_get_value_string_utf8(env, argv[1], nullptr, 0, &len);
    std::string line(len + 1, '\0');
    napi_get_value_string_utf8(env, argv[1], &line[0], len + 1, &len);
    line.resize(len);

    FILE* f = fopen(path.c_str(), "a");
    if (f == nullptr) {
        napi_value out;
        napi_create_string_utf8(env, "open-fail", 9, &out);
        return out;
    }
    fputs(line.c_str(), f);
    fputc('\n', f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    napi_value out;
    napi_create_string_utf8(env, "ok", 2, &out);
    return out;
}

static napi_value ResetFile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    std::string path;
    if (argc >= 1) {
        size_t len = 0;
        napi_get_value_string_utf8(env, argv[0], nullptr, 0, &len);
        path.resize(len + 1, '\0');
        napi_get_value_string_utf8(env, argv[0], &path[0], len + 1, &len);
        path.resize(len);
    }

    napi_value out;
    if (path.empty()) {
        napi_create_string_utf8(env, "bad-path", 8, &out);
        return out;
    }
    FILE* f = fopen(path.c_str(), "w");
    if (f == nullptr) {
        napi_create_string_utf8(env, "open-fail", 9, &out);
        return out;
    }
    fclose(f);
    napi_create_string_utf8(env, "ok", 2, &out);
    return out;
}

// ---------------------------------------------------------------- NAPI：进程上下文

static napi_value GetContext(napi_env env, napi_callback_info info) {
    (void)info;

    std::string ctx = "unknown";
    FILE* f = fopen("/proc/self/attr/current", "r");
    if (f != nullptr) {
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), f) != nullptr) {
            ctx = buf;
        }
        fclose(f);
        while (!ctx.empty() && (ctx.back() == '\n' || ctx.back() == '\r' || ctx.back() == '\0')) {
            ctx.pop_back();
        }
    }

    std::string uid = "0";
    std::string seccomp = "0";
    std::string seccompFilters = "0";
    std::string capEff = "?";
    std::string capBnd = "?";
    std::string noNewPrivs = "?";

    f = fopen("/proc/self/status", "r");
    if (f != nullptr) {
        char line[512];
        while (fgets(line, sizeof(line), f) != nullptr) {
            std::string s(line);
            auto take = [&s](size_t start) {
                size_t p = s.find_first_not_of(" \t", start);
                if (p == std::string::npos) {
                    return std::string();
                }
                size_t e = s.find_first_of(" \t\r\n", p);
                if (e == std::string::npos) {
                    e = s.size();
                }
                return s.substr(p, e - p);
            };
            if (s.compare(0, 4, "Uid:") == 0) {
                uid = take(4);
            } else if (s.compare(0, 8, "Seccomp:") == 0) {
                seccomp = take(8);
            } else if (s.compare(0, 16, "Seccomp_filters:") == 0) {
                seccompFilters = take(16);
            } else if (s.compare(0, 7, "CapEff:") == 0) {
                capEff = take(7);
            } else if (s.compare(0, 7, "CapBnd:") == 0) {
                capBnd = take(7);
            } else if (s.compare(0, 11, "NoNewPrivs:") == 0) {
                noNewPrivs = take(11);
            }
        }
        fclose(f);
    }

    std::string json = "{";
    json += "\"selinux\":\"" + ctx + "\",";
    json += "\"uid\":" + (uid.empty() ? std::string("0") : uid) + ",";
    json += "\"seccomp\":" + (seccomp.empty() ? std::string("0") : seccomp) + ",";
    json += "\"seccompFilters\":" + (seccompFilters.empty() ? std::string("0") : seccompFilters) + ",";
    json += "\"capEff\":\"" + capEff + "\",";
    json += "\"capBnd\":\"" + capBnd + "\",";
    json += "\"noNewPrivs\":\"" + noNewPrivs + "\"";
    json += "}";

    napi_value out;
    napi_create_string_utf8(env, json.c_str(), json.size(), &out);
    return out;
}

}  // namespace

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"runProbes", nullptr, RunProbes, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"runOnePersist", nullptr, RunOnePersist, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"appendLine", nullptr, AppendLine, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"resetFile", nullptr, ResetFile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getContext", nullptr, GetContext, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module probeModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "sysprobe",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterModule(void) {
    napi_module_register(&probeModule);
}

/*
 * 为什么结果必须放 volatile 全局：
 *   C 标准规定 siglongjmp 跳回后，栈帧中非 volatile 局部变量值不确定。
 *   arm64 的 sigsetjmp 只保存 x19-x30 + sp + d8-d15，x0-x8 不保存。
 *   若结果结构体通过返回值传递（压在 x0/x1），longjmp 后就丢了。
 *   汇编验证过编译器会这么优化，所以必须强制走内存。
 */
