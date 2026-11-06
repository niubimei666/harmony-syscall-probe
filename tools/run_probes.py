#!/usr/bin/env python3
"""
通过 hdc 把 syscall 探针推到设备上逐个执行，收集 exit code，生成报告。

⚠️ 重要限制（实测）：
   在纯血 HarmonyOS NEXT 上，`hdc shell` 的域（u:r:sh:s0）**不允许执行**
   /data/local/tmp 下的文件（SELinux 无 execute 权限，chmod/chcon 都改不了）。
   而且该域的 Seccomp 是 0（没有过滤器），测了也测不出东西。

   所以本脚本只适用于「安卓 APK 跑在鸿蒙兼容容器里」的场景
   （那里 shell 能执行文件）。要在纯血 NEXT 上测，请用 hap/SysProbe。

判读：
    0         放行
    159       被 seccomp KILL（128 + SIGSYS 31）
    135       被 SIGBUS 杀（128 + 7）
    132       被 SIGILL 杀（128 + 4）
    超时      放行但阻塞（不是被禁）

用法：
    python run_probes.py --check                 # 只检查设备连接
    python run_probes.py --critical              # 跑关键 19 项
    python run_probes.py --all                   # 跑全部 462 项
    python run_probes.py --nr 99,116,198         # 跑指定项
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_HDC = r"D:\DevEco Studio\sdk\default\openharmony\toolchains\hdc.exe"
REMOTE_DIR = "/data/local/tmp/sysprobe"

EXIT_ALLOWED = 0
EXIT_SIGSYS = 159
EXIT_SIGBUS = 135
EXIT_SIGILL = 132
EXIT_SIGSEGV = 139

VERDICT = {
    EXIT_ALLOWED: "ALLOW",
    EXIT_SIGSYS: "KILL(SIGSYS)",
    EXIT_SIGBUS: "SIGBUS",
    EXIT_SIGILL: "SIGILL",
    EXIT_SIGSEGV: "SIGSEGV",
}

CRITICAL: dict[int, str] = {
    17: "getcwd（PRoot 路径翻译的试金石）",
    99: "set_robust_list（glibc 主线程初始化）",
    100: "get_robust_list",
    117: "ptrace（PRoot 的全部前提）",
    198: "socket（任何网络 / dsh web 监听）",
    199: "socketpair",
    202: "accept",
    203: "connect（调 LLM API 必需）",
    220: "clone（线程创建的老路径）",
    221: "execve（PRoot 启动引擎）",
    222: "mmap",
    242: "accept4",
    277: "seccomp",
    278: "getrandom",
    293: "rseq（glibc 2.35+）",
    425: "io_uring_setup",
    435: "clone3（glibc 2.34+ pthread_create 首选）",
    437: "openat2",
    439: "faccessat2",
}


def load_names(probe_dir: str) -> dict[int, tuple[str, bool]]:
    path = os.path.join(probe_dir, "_syscall_names.tsv")
    out: dict[int, tuple[str, bool]] = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                try:
                    nr = int(parts[0])
                except ValueError:
                    continue
                out[nr] = (parts[1], len(parts) > 2 and parts[2].strip() == "CRITICAL")
    return out


@dataclass
class Result:
    nr: int
    name: str
    code: int | None
    verdict: str
    raw: str = ""


class Hdc:
    def __init__(self, hdc_path: str, timeout: int = 20):
        self.hdc = hdc_path
        self.timeout = timeout

    def _run(self, args: list[str], timeout: int | None = None) -> tuple[int, str]:
        env = dict(os.environ, MSYS_NO_PATHCONV="1")
        try:
            p = subprocess.run([self.hdc, *args], capture_output=True,
                               timeout=timeout or self.timeout, env=env)
            out = (p.stdout or b"") + (p.stderr or b"")
            return p.returncode, out.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return -1, "<timeout>"
        except FileNotFoundError:
            return -2, f"hdc not found: {self.hdc}"

    def list_targets(self) -> list[str]:
        rc, out = self._run(["list", "targets"], timeout=15)
        if rc != 0:
            return []
        return [l.strip() for l in out.replace("\r", "").split("\n")
                if l.strip() and "Empty" not in l and not l.startswith("[")]

    def shell(self, cmd: str, timeout: int | None = None) -> tuple[int, str]:
        return self._run(["shell", cmd], timeout=timeout)

    def send(self, local: str, remote: str) -> tuple[int, str]:
        return self._run(["file", "send", local, remote], timeout=60)


def probe_one(hdc: Hdc, nr: int, timeout: float) -> Result:
    remote = f"{REMOTE_DIR}/{nr:03d}"
    cmd = f"chmod +x {remote} 2>/dev/null; {remote}; echo __RC:$?"
    rc, out = hdc.shell(cmd, timeout=int(timeout) + 15)

    if rc == -1:
        return Result(nr, "", None, "timeout", out)

    marker = "__RC:"
    idx = out.rfind(marker)
    if idx < 0:
        return Result(nr, "", None, "error", out.strip()[:300])

    try:
        code = int(out[idx + len(marker):].strip().split()[0])
    except (ValueError, IndexError):
        return Result(nr, "", None, "error", out.strip()[:300])

    return Result(nr, "", code, VERDICT.get(code, f"exit {code}"), out.strip()[:300])


def render_report(results: list[Result], names: dict[int, tuple[str, bool]],
                  device: str, mode: str) -> str:
    allowed = [r for r in results if r.code == EXIT_ALLOWED]
    killed = [r for r in results if r.code == EXIT_SIGSYS]
    other = [r for r in results if r.code not in (EXIT_ALLOWED, EXIT_SIGSYS)]
    crit = [r for r in results if r.nr in CRITICAL]

    out: list[str] = []
    w = out.append

    w("# 鸿蒙 syscall 能力地图（容器 / shell 环境）")
    w("")
    w(f"- 设备：`{device}`")
    w(f"- 模式：{mode}")
    w(f"- 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"- 探针数：{len(results)}（放行 {len(allowed)} / SIGSYS {len(killed)} / 其它 {len(other)}）")
    w("")
    w("## 关键项")
    w("")
    w("| nr | syscall | 含义 | 结果 |")
    w("|---:|---|---|---|")
    for r in sorted(crit, key=lambda x: x.nr):
        w(f"| {r.nr} | `{names.get(r.nr, ('?', False))[0]}` | {CRITICAL[r.nr]} | **{r.verdict}** |")
    w("")

    def get(nr: int):
        for r in results:
            if r.nr == nr:
                return r.code
        return None

    w("## 判读")
    w("")
    w("| 能力 | 结论 |")
    w("|---|---|")
    w(f"| 能建 socket | {'✅ 可以' if get(198) == EXIT_ALLOWED else '❌ 不行'} |")
    w(f"| 能用 ptrace（PRoot 可用） | {'✅ 可以' if get(117) == EXIT_ALLOWED else '❌ 不行'} |")
    clone3_ok = get(435) == EXIT_ALLOWED
    clone_ok = get(220) == EXIT_ALLOWED
    w(f"| 能建线程 | {'✅ clone3' if clone3_ok else ('⚠️ 只有 clone' if clone_ok else '❌ 都不行')} |")
    w(f"| glibc 能初始化 | {'✅ 可以' if get(99) == EXIT_ALLOWED else '❌ 不行'} |")
    w("")

    if other:
        w("## 非标准退出（需人工看）")
        w("")
        for r in other:
            w(f"- `{r.nr}` {names.get(r.nr, ('?', False))[0]}：{r.verdict}"
              + (f" — `{r.raw}`" if r.raw else ""))
        w("")

    w("## 完整结果")
    w("")
    w("| nr | syscall | 结果 |")
    w("|---:|---|---|")
    for r in sorted(results, key=lambda x: x.nr):
        star = " ⭐" if r.nr in CRITICAL else ""
        w(f"| {r.nr} | `{names.get(r.nr, ('?', False))[0]}`{star} | {r.verdict} |")
    w("")
    return "\n".join(out)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    ap = argparse.ArgumentParser(description="在设备上跑 syscall 探针")
    ap.add_argument("--hdc", default=DEFAULT_HDC)
    ap.add_argument("--probe-dir", default=os.path.join(HERE, "probes"))
    ap.add_argument("--critical", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--nr", default="")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    if not os.path.exists(args.hdc):
        print(f"[错误] 找不到 hdc：{args.hdc}")
        return 2

    hdc = Hdc(args.hdc)
    print(f"hdc: {args.hdc}")
    targets = hdc.list_targets()
    if not targets:
        print("[错误] 没有检测到设备。检查 USB 连接、开发者模式、调试授权。")
        return 3

    device = targets[0]
    print(f"设备: {device}")

    if args.check:
        rc, out = hdc.shell("uname -a; echo ---; id")
        print(out.strip())
        return 0

    if args.critical:
        nrs = sorted(CRITICAL)
        probe_dir = os.path.join(HERE, "probes_critical")
        mode = "关键 19 项"
    elif args.nr:
        nrs = [int(x) for x in args.nr.split(",") if x.strip()]
        probe_dir = args.probe_dir
        mode = f"指定 {len(nrs)} 项"
    else:
        probe_dir = args.probe_dir
        nrs = sorted(int(f) for f in os.listdir(probe_dir)
                     if f.isdigit() and os.path.isfile(os.path.join(probe_dir, f)))
        mode = f"全量 {len(nrs)} 项"

    names = load_names(probe_dir)
    print(f"探针目录: {probe_dir}（{len(nrs)} 项）")

    rc, out = hdc.shell(f"mkdir -p {REMOTE_DIR} && echo OK")
    if "OK" not in out:
        print(f"[错误] 无法创建 {REMOTE_DIR}：{out.strip()[:200]}")
        return 4

    print("推送中...", end="", flush=True)
    for i, nr in enumerate(nrs, 1):
        hdc.send(os.path.join(probe_dir, f"{nr:03d}"), f"{REMOTE_DIR}/{nr:03d}")
        if i % 50 == 0 or i == len(nrs):
            print(f" {i}/{len(nrs)}", end="", flush=True)
    print()

    hdc.shell(f"chmod -R 755 {REMOTE_DIR} && echo OK")

    print("执行中...", end="", flush=True)
    results = []
    for i, nr in enumerate(nrs, 1):
        r = probe_one(hdc, nr, args.timeout)
        r.name = names.get(nr, ("?", False))[0]
        results.append(r)
        if i % 20 == 0 or i == len(nrs):
            print(f" {i}/{len(nrs)}", end="", flush=True)
    print()

    report = render_report(results, names, device, mode)
    out_path = args.out or os.path.join(
        HERE, f"report-{time.strftime('%Y%m%d-%H%M%S')}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    allowed = sum(1 for r in results if r.code == EXIT_ALLOWED)
    killed = sum(1 for r in results if r.code == EXIT_SIGSYS)
    print(f"\n结果：放行 {allowed} / SIGSYS {killed} / 其它 {len(results) - allowed - killed}")
    print(f"报告：{out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
