/*
 * 在应用沙箱内执行外部二进制（exec 测试）
 *
 * 目的：验证纯血鸿蒙应用沙箱（*_hap:s0 域）能否 fork+exec 一个自建静态 ELF。
 * 做法：把 ELF 内容通过 NAPI 传进来，写到应用沙箱的 files/ 目录，chmod 755，
 *      然后 fork + execve，等子进程结束，拿 exit code 和输出。
 */

#include <napi/native_api.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

namespace {

constexpr int kOutCap = 4096;

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
            case '\t': o += "\\t"; break;
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

struct ExecResult {
    int started;
    int exitCode;
    int waitErrno;
    std::string output;
};

static ExecResult RunBinary(const std::string& path) {
    ExecResult r;
    r.started = 0;
    r.exitCode = -1;
    r.waitErrno = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        r.waitErrno = errno;
        return r;
    }

    pid_t pid = fork();
    if (pid < 0) {
        r.waitErrno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        return r;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        char* const argv[] = {const_cast<char*>(path.c_str()), nullptr};
        char* const envp[] = {nullptr};
        execve(path.c_str(), argv, envp);

        int e = errno;
        char msg[128];
        int n = snprintf(msg, sizeof(msg), "EXEC_FAIL errno=%d (%s)\n", e, strerror(e));
        if (n > 0) {
            ssize_t ignored = write(STDOUT_FILENO, msg, (size_t)n);
            (void)ignored;
        }
        _exit(127);
    }

    close(pipefd[1]);
    char buf[512];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        if (r.output.size() < kOutCap) {
            r.output.append(buf, (size_t)n);
        }
    }
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        r.waitErrno = errno;
        return r;
    }
    r.started = 1;
    if (WIFEXITED(status)) {
        r.exitCode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        r.exitCode = -WTERMSIG(status);
    }
    return r;
}

// NAPI: execPayload(dir, name, base64Content)
static napi_value ExecPayload(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3] = {nullptr, nullptr, nullptr};
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

    std::string path = dir + "/" + name;
    bool written = WriteFile(path, raw);
    bool chmodOk = false;
    if (written) {
        chmodOk = (chmod(path.c_str(), 0755) == 0);
    }

    ExecResult er;
    if (chmodOk) {
        er = RunBinary(path);
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"path\":\"%s\",\"bytes\":%zu,\"written\":%d,\"chmodOk\":%d,"
             "\"started\":%d,\"exitCode\":%d,\"waitErrno\":%d,\"output\":\"%s\"}",
             JsonEscape(path).c_str(), raw.size(), written ? 1 : 0, chmodOk ? 1 : 0,
             er.started, er.exitCode, er.waitErrno, JsonEscape(er.output).c_str());

    napi_value out;
    napi_create_string_utf8(env, buf, strlen(buf), &out);
    return out;
}

}  // namespace

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"execPayload", nullptr, ExecPayload, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module execModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "execprobe",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterExecModule(void) {
    napi_module_register(&execModule);
}
