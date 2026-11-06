# harmony-syscall-probe

测一台鸿蒙设备的沙箱允许哪些 syscall。

直接决定「Node 运行时 / 本机引擎能不能在设备上跑」。

---

## 先看结论

**[→ 鸿蒙沙箱能力实测（完整报告）](docs/鸿蒙沙箱能力实测.md)**

四句话版本：

| 环境 | socket | ptrace | clone3 | 结论 |
|---|---|---|---|---|
| `hdc shell` | — | — | — | Seccomp 为 0，但不能执行二进制 |
| **纯血鸿蒙原生应用** | ✅ | ✅ | 💀 | 卡在 glibc + W^X |
| 安卓兼容容器（卓易通） | ❌ | ❌ | ❌ | 物理不可行 |

1. **鸿蒙系统不拦 `socket` / `ptrace` / `clone`**，拦的是 Linux 5.x 之后的新 syscall（`clone3` / `rseq` / `openat2`）。
2. **应用沙箱有 W^X + 代码签名约束**：运行时写入的文件不能 `execve` 也不能 `mmap(PROT_EXEC)`。
3. **但 HAP `libs/` 目录里的 `.so` 可以 dlopen**（已实测）。
4. 所以要在鸿蒙原生应用里跑 Node，得把它编译成 `.so` 打进 HAP，随包签名。

---

## 两套工具

### A. 应用沙箱探针（`hap/SysProbe/`，推荐）

ArkTS + C++ NAPI，在应用进程内直发 `svc #0`，拿真实 errno。

**为什么必须用它**：`hdc shell` 的域 `Seccomp: 0 filters: 0`，没有过滤器；而且 shell 域不能执行 `/data/local/tmp` 里的二进制。在 shell 里测不出任何东西。

```powershell
# 构建
$env:DEVECO_SDK_HOME = "D:\DevEco Studio\sdk"
$env:PATH = "D:\DevEco Studio\tools\node;D:\DevEco Studio\tools\ohpm\bin;$env:PATH"
$env:NODE_HOME = "D:\DevEco Studio\tools\node"
cd hap\SysProbe
node "D:\DevEco Studio\tools\hvigor\bin\hvigorw.js" --mode module `
  -p product=default -p module=entry@default assembleHap --no-daemon

# 安装（换成你的设备序列号）
hdc install -r entry\build\default\outputs\default\entry-default-signed.hap
```

界面里：

- **19 个方块** — 点一个测一项，进程被杀后重启会标红
- **跑剩余关键项 / 跑全量 462** — 批量，自动跳过已知会杀进程的项
- **exec hello / exec socket** — 测 fork+execve
- **dlopen .so** — 逐步诊断 dlopen（write → stat → open+read → mmap → dlopen → dlsym）
- **复制报告** — 导出 Markdown

**签名**：在 `build-profile.json5` 的 `signingConfigs.material` 填自己的证书路径，
或在 DevEco Studio → Project Structure → Signing Configs 点自动生成。

### B. 容器 / shell 环境探针（`tools/`）

给「安卓 APK 跑在鸿蒙兼容容器里」的场景用。每项是一个 136 字节的静态 aarch64 ELF。

```powershell
python tools\gen_probes.py --critical    # 生成 19 个关键探针
python tools\run_probes.py --critical    # 经 hdc 推送执行
```

判读：

| exit code | 含义 |
|---|---|
| `0` | 放行 |
| `159` | 被 seccomp KILL（128 + SIGSYS 31） |
| `135` / `132` / `139` | SIGBUS / SIGILL / SIGSEGV |

---

## 目录

| 路径 | 内容 |
|---|---|
| `docs/鸿蒙沙箱能力实测.md` | **完整技术报告** |
| `hap/SysProbe/` | 应用沙箱探针 HAP 源码 |
| `hap/SysProbe/entry/src/main/cpp/sysprobe.cpp` | 内联汇编 `svc #0` + 信号保护 + fsync 落盘 |
| `hap/SysProbe/entry/src/main/cpp/execprobe.cpp` | fork + execve 测试 |
| `hap/SysProbe/entry/src/main/cpp/dlprobe.cpp` | dlopen 逐步诊断 |
| `hap/SysProbe/entry/src/main/cpp/probelib.c` | 被 dlopen 的最小库（无动态依赖） |
| `tools/gen_probes.py` | 生成单 syscall 静态 ELF |
| `tools/run_probes.py` | 经 hdc 推送执行 |
| `tools/gen_static_elf.py` | 生成 hello / socket_probe 两个静态 ELF |

---

## 环境

已验证：

- DevEco Studio 26.0.0（API 26）
- NDK 26.0.0.105（clang 15.0.4）
- hdc Ver 3.2.0f
- Python 3.11+

---

## 已知坑

写这个工具时踩过的坑，都附了验证方式：

1. **`hdc shell` 不能执行 `/data/local/tmp`** — SELinux `data_local_tmp` 无 execute 权限，`chmod` / `chcon` 都改不了。对照实验：`/system/bin/base64` 原地执行正常。
2. **`siglongjmp` 后普通局部变量不可靠** — arm64 `sigsetjmp` 只保存 x19–x30，结构体返回值压 x0/x1 就丢了。必须用 `volatile` 全局。汇编验证过编译器会这么优化。
3. **测完不能 `signal(SIGSEGV, SIG_DFL)`** — 之后任何段错误会崩掉整个 App。要保存并还原原始 `sigaction`。
4. **`dlopen` 报 `No error information` 是依赖缺失，不是权限** — 用 `-nostdlib` 编出来的 2KB 无依赖库才是干净可测的。
5. **手编 `.so` 要确认符号是 `GLOBAL DEFAULT`** — 否则 `dlsym` 找不到，会误判成沙箱拒绝。用 `llvm-readelf --dyn-syms` 检查。
6. **每项落盘必须 `fsync`** — 只 `fflush` 的话进程被 KILL 时数据还在页缓存里。
7. **界面输出要压紧** — 结果太长会被控件裁掉，看不到关键行。

---

## 许可

MIT
