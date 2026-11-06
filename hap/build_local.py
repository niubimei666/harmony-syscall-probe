#!/usr/bin/env python3
"""
本地构建辅助：临时切换 bundleName + 注入签名配置，构建完自动还原。

背景：
    仓库里用的包名是 io.github.niubimei666.sysprobe，而本机签名 profile
    绑定的是另一个包名。直接构建会报：
        The bundleName in app.json5 does not match the bundleName in SigningConfigs

用法：
    python build_local.py              # 构建 + 自动还原
    python build_local.py --keep       # 构建后保留临时配置（方便反复构建）
    python build_local.py --restore    # 只还原，不构建

签名配置从 signing.local.json 读取（这个文件不进仓库，见 .gitignore）
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.join(HERE, "SysProbe")
APP_JSON = os.path.join(PROJ, "AppScope", "app.json5")
BUILD_PROFILE = os.path.join(PROJ, "build-profile.json5")
SIGN_LOCAL = os.path.join(HERE, "signing.local.json")

BACKUP_SUFFIX = ".localsign.bak"


def log(msg: str) -> None:
    print(msg, flush=True)


def read_text(p: str) -> str:
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def write_text(p: str, s: str) -> None:
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(s)


def backup(p: str) -> None:
    """备份当前文件。但如果当前文件已经是「被修改过的版本」（比如上次手动改过签
    名配置就输了），不要覆盖备份，而是用 git 把仓库版本取出来做备份基准。"""
    b = p + BACKUP_SUFFIX
    if os.path.exists(b):
        return
    # 优先用 git 里的原始版本作为基准，避免把本地泄漏内容当成「干净版」备份下来
    rel = os.path.relpath(p, HERE)
    try:
        r = subprocess.run(["git", "show", f"HEAD:{_git_relpath(p)}"],
                           cwd=os.path.dirname(HERE), capture_output=True, timeout=30)
        if r.returncode == 0 and r.stdout:
            with open(b, "wb") as fh:
                fh.write(r.stdout)
            log(f"  备份基准取自 git HEAD: {rel}")
            return
    except Exception:
        pass
    # 没有 git 时退回复制当前文件（可能不干净，但至少能还原）
    shutil.copy2(p, b)
    log(f"  [警告] 无 git 基准，备份当前文件: {rel}")


def _git_relpath(p: str) -> str:
    """把绝对路径转成 git 仓库内相对路径（仓库根在 hap/ 的上一级）"""
    repo_root = os.path.dirname(HERE)
    return os.path.relpath(p, repo_root).replace(os.sep, "/")


def restore() -> None:
    """从备份还原，删掉临时改动"""
    for p in (APP_JSON, BUILD_PROFILE):
        b = p + BACKUP_SUFFIX
        if os.path.exists(b):
            shutil.copy2(b, p)
            os.remove(b)
            log(f"  还原 {os.path.relpath(p, HERE)}")


def load_signing() -> dict:
    if not os.path.exists(SIGN_LOCAL):
        log(f"[错误] 找不到 {SIGN_LOCAL}")
        log("  该文件应包含 signingConfigs 数组，格式参考 README")
        sys.exit(2)
    with open(SIGN_LOCAL, encoding="utf-8") as fh:
        return json.load(fh)


def patch_app_json(bundle_name: str) -> None:
    s = read_text(APP_JSON)
    import re
    new = re.sub(r'"bundleName"\s*:\s*"[^"]*"',
                 f'"bundleName": "{bundle_name}"', s, count=1)
    if new == s:
        log("[警告] app.json5 里没找到 bundleName 字段")
    write_text(APP_JSON, new)


def patch_signing(signing_configs: list) -> None:
    """用精确的括号匹配替换 signingConfigs 数组，不用宽松正则（会吃掉后面的 products）"""
    s = read_text(BUILD_PROFILE)

    # 定位 "signingConfigs" 后面的数组
    key_idx = s.find('"signingConfigs"')
    if key_idx < 0:
        log("[错误] build-profile.json5 里没找到 signingConfigs 字段")
        sys.exit(3)
    # 找冒号后的第一个 '['
    arr_start = s.find('[', key_idx)
    if arr_start < 0:
        log("[错误] signingConfigs 后没有数组")
        sys.exit(3)

    # 从 '[' 开始做括号配对，找到对应的 ']'
    depth = 0
    arr_end = -1
    in_str = False
    esc = False
    for i in range(arr_start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                arr_end = i
                break

    if arr_end < 0:
        log("[错误] signingConfigs 数组括号不配对")
        sys.exit(3)

    # 生成新数组，缩进对齐到 key 所在的列
    line_start = s.rfind('\n', 0, key_idx) + 1
    indent = ' ' * (key_idx - line_start)
    items = signing_configs

    import json as _json
    parts = []
    for item in items:
        body = _json.dumps(item, ensure_ascii=False, indent=2)
        body = body.replace('\n', '\n' + indent + '  ')
        parts.append(indent + '  ' + body)
    if parts:
        new_arr = '[\n' + ',\n'.join(parts) + '\n' + indent + ']'
    else:
        new_arr = '[]'

    new_s = s[:arr_start] + new_arr + s[arr_end + 1:]
    write_text(BUILD_PROFILE, new_s)


def build() -> int:
    env = dict(os.environ)
    env["DEVECO_SDK_HOME"] = r"D:\DevEco Studio\sdk"
    env["NODE_HOME"] = r"D:\DevEco Studio\tools\node"
    env["PATH"] = (r"D:\DevEco Studio\tools\node" + os.pathsep +
                   r"D:\DevEco Studio\tools\ohpm\bin" + os.pathsep +
                   env.get("PATH", ""))
    node = r"D:\DevEco Studio\tools\node\node.exe"
    hvigor = r"D:\DevEco Studio\tools\hvigor\bin\hvigorw.js"

    log("  同步依赖...")
    subprocess.run([node, r"D:\DevEco Studio\tools\ohpm\bin\pm-cli.js", "install"],
                   cwd=PROJ, env=env, capture_output=True, timeout=300)

    log("  构建...")
    p = subprocess.run(
        [node, hvigor, "--mode", "module",
         "-p", "product=default", "-p", "module=entry@default",
         "assembleHap", "--no-daemon"],
        cwd=PROJ, env=env, capture_output=True, timeout=900)
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    for line in out.split("\n"):
        if any(k in line for k in ("BUILD", "ERROR", "Error Message", "SignHap")):
            log("  " + line.strip())
    return 0 if "BUILD SUCCESSFUL" in out else 1


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    ap = argparse.ArgumentParser(description="本地构建（临时切换包名 + 注入签名）")
    ap.add_argument("--keep", action="store_true", help="构建后保留临时配置")
    ap.add_argument("--restore", action="store_true", help="只还原，不构建")
    args = ap.parse_args()

    if args.restore:
        log("=== 还原 ===")
        restore()
        return 0

    signing = load_signing()
    bundle = signing.get("bundleName")
    if not bundle:
        log("[错误] signing.local.json 缺少 bundleName 字段")
        return 2

    log("=== 注入本地配置 ===")
    log(f"  bundleName -> {bundle}")
    backup(APP_JSON)
    backup(BUILD_PROFILE)
    patch_app_json(bundle)
    patch_signing(signing.get("signingConfigs", []))

    log("=== 构建 ===")
    try:
        rc = build()
    finally:
        if not args.keep:
            log("=== 还原仓库状态 ===")
            restore()
        else:
            log(f"  保留临时配置（用 --restore 还原）")

    if rc == 0:
        hap = os.path.join(PROJ, "entry", "build", "default", "outputs",
                           "default", "entry-default-signed.hap")
        if os.path.exists(hap):
            size = os.path.getsize(hap)
            log(f"\n产物：{hap}")
            log(f"  {size:,} 字节")
    return rc


if __name__ == "__main__":
    sys.exit(main())
