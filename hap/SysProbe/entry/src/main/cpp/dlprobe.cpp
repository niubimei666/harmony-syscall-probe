/*
 * dlopen 诊断：不只看 dlerror，逐步验证每一环
 *
 * execve 和 dlopen 走的是不同的 SELinux 判定（execute vs read+mmap），
 * 所以 execve 失败不代表进程内嵌入也不行。这里把它拆开测：
 *   1. 写入 / stat
 *   2. open(O_RDONLY) + read
 *   3. mmap(PROT_READ|PROT_EXEC)
 *   4. dlopen 各模式（在 dlerror() 前保存 errno）
 *   5. 对照组：HAP libs 目录里的 .so
 *   6. dlsym
 *
 * 实测结果（HarmonyOS NEXT）：
 *   数据目录 → mmap PROT_EXEC EACCES → dlopen 失败
 *   HAP libs/ → dlopen 成功
 * 即：只允许执行随 HAP 一起签名的代码。
 */

#include <napi/native_api.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string>
#include <vector>

namespace {

static bool WriteFile(const std::string& path, const std::string& data) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        return false;
    }
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    fsync(fd);
    close(fd);
    return true;
}

static std::string Base64Decode(const std::string& b64) {
    static const char* kTable =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int8_t rev[256];
    memset(rev, -1, sizeof(rev));
    for (int i = 0; i < 64; i++) {
        rev[(unsigned char)kTable[i]] = (int8_t)i;
    }
    std::string raw;
    raw.reserve(b64.size() * 3 / 4 + 4);
    int val = 0;
    int bits = -8;
    for (char c : b64) {
        if (c == '=' || c == '\n' || c == '\r') {
            continue;
        }
        int8_t d = rev[(unsigned char)c];
        if (d < 0) {
            continue;
        }
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 0) {
            raw.push_back((char)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return raw;
}

static std::string JsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char t[8];
                    snprintf(t, sizeof(t), "\\u%04x", (unsigned char)c);
                    o += t;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

struct Step {
    std::string name;
    bool ok;
    int err;
    std::string detail;
};

static void AddStep(std::vector<Step>& v, const std::string& name, bool ok, int err,
                    const std::string& detail = "") {
    Step s;
    s.name = name;
    s.ok = ok;
    s.err = err;
    s.detail = detail;
    v.push_back(s);
}

// NAPI: diagPayload(dir, name, base64, hapLibPath)
static napi_value DiagPayload(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value argv[4] = {nullptr, nullptr, nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    auto getStr = [&](size_t i) -> std::string {
        if (i >= argc) {
            return std::string();
        }
        size_t len = 0;
        if (napi_get_value_string_utf8(env, argv[i], nullptr, 0, &len) != napi_ok) {
            return std::string();
        }
        std::string s(len + 1, '\0');
        napi_get_value_string_utf8(env, argv[i], &s[0], len + 1, &len);
        s.resize(len);
        return s;
    };

    std::string dir = getStr(0);
    std::string name = getStr(1);
    std::string raw = Base64Decode(getStr(2));
    std::string hapLib = getStr(3);

    std::vector<Step> steps;

    // ---- 1. 写入
    std::string path = dir + "/" + name;
    bool written = WriteFile(path, raw);
    AddStep(steps, "write", written, written ? 0 : errno, path);

    // ---- 2. stat
    struct stat st;
    int sr = stat(path.c_str(), &st);
    AddStep(steps, "stat", sr == 0, sr == 0 ? 0 : errno,
            sr == 0 ? std::to_string(st.st_size) + " bytes, mode=0o" +
                          std::to_string(st.st_mode & 07777) : "");

    // ---- 3. open + read + mmap
    int fd = open(path.c_str(), O_RDONLY);
    int openErr = errno;
    if (fd >= 0) {
        char buf[16];
        ssize_t n = read(fd, buf, sizeof(buf));
        bool readOk = (n > 0);
        AddStep(steps, "open+read", readOk, readOk ? 0 : errno,
                n > 0 ? std::string("read ") + std::to_string(n) + " bytes" : "read failed");

        void* m = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        bool mapOk = (m != MAP_FAILED);
        AddStep(steps, "mmap(RX)", mapOk, mapOk ? 0 : errno, mapOk ? "ok" : "failed");
        if (mapOk) {
            munmap(m, 4096);
        }
        close(fd);
    } else {
        AddStep(steps, "open+read", false, openErr, "open failed");
    }

    // ---- 4. dlopen 各模式
    struct Mode {
        const char* label;
        int flags;
    } modes[] = {
        {"dlopen(RTLD_NOW|RTLD_LOCAL)", RTLD_NOW | RTLD_LOCAL},
        {"dlopen(RTLD_LAZY|RTLD_LOCAL)", RTLD_LAZY | RTLD_LOCAL},
        {"dlopen(RTLD_NOW|RTLD_GLOBAL)", RTLD_NOW | RTLD_GLOBAL},
    };

    bool anyOpened = false;
    void* firstHandle = nullptr;

    for (const auto& m : modes) {
        dlerror();
        errno = 0;
        void* h = dlopen(path.c_str(), m.flags);
        int dlErr = errno;   // 先存 errno，dlerror() 会覆盖它
        const char* e = dlerror();
        std::string msg = (e != nullptr) ? std::string(e) : std::string();
        AddStep(steps, m.label, h != nullptr, dlErr, msg);
        if (h != nullptr && firstHandle == nullptr) {
            firstHandle = h;
            anyOpened = true;
        }
    }

    // ---- 5. 对照组：HAP 自己 libs 目录里的 so
    if (!hapLib.empty()) {
        dlerror();
        errno = 0;
        void* h2 = dlopen(hapLib.c_str(), RTLD_NOW | RTLD_LOCAL);
        int dlErr2 = errno;
        const char* e2 = dlerror();
        std::string msg2 = (e2 != nullptr) ? std::string(e2) : std::string();
        AddStep(steps, "dlopen(HAP libs)", h2 != nullptr, dlErr2, msg2);
    }

    // ---- 6. 符号解析
    int answer = -999;
    bool answerOk = false;
    int symErrno = 0;
    std::string symErr;
    if (firstHandle != nullptr) {
        dlerror();
        errno = 0;
        auto fn = reinterpret_cast<int (*)()>(dlsym(firstHandle, "probe_answer"));
        symErrno = errno;
        const char* e3 = dlerror();
        if (e3 != nullptr) {
            symErr = e3;
        }
        if (fn != nullptr && e3 == nullptr) {
            answer = fn();
            answerOk = true;
        }
    }

    // ---- 拼 JSON
    std::string json = "{";
    json += "\"path\":\"" + JsonEscape(path) + "\",";
    json += "\"bytes\":" + std::to_string(raw.size()) + ",";
    json += "\"opened\":" + std::string(anyOpened ? "1" : "0") + ",";
    json += "\"answer\":" + std::to_string(answer) + ",";
    json += "\"answerOk\":" + std::string(answerOk ? "1" : "0") + ",";
    json += "\"symErrno\":" + std::to_string(symErrno) + ",";
    json += "\"symErr\":\"" + JsonEscape(symErr) + "\",";
    json += "\"steps\":[";
    for (size_t i = 0; i < steps.size(); i++) {
        if (i > 0) {
            json += ",";
        }
        json += "{\"name\":\"" + JsonEscape(steps[i].name) + "\",";
        json += "\"ok\":" + std::string(steps[i].ok ? "1" : "0") + ",";
        json += "\"err\":" + std::to_string(steps[i].err) + ",";
        json += "\"detail\":\"" + JsonEscape(steps[i].detail) + "\"}";
    }
    json += "]}";

    // 同时写一份到沙箱文件，方便界面装不下时直接读
    {
        std::string dumpPath = dir + "/dlopen-result.json";
        WriteFile(dumpPath, json);
    }

    napi_value out;
    napi_create_string_utf8(env, json.c_str(), json.size(), &out);
    return out;
}

static napi_value Init2(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"diagPayload", nullptr, DiagPayload, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

}  // namespace

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    return Init2(env, exports);
}
EXTERN_C_END

static napi_module dlModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "dlprobe",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterDlModule(void) {
    napi_module_register(&dlModule);
}
