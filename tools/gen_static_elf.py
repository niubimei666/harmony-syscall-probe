#!/usr/bin/env python3
"""
生成「最小静态 ELF」，用于测试应用沙箱能否 fork+exec 外部二进制。

不依赖任何 libc：
- ET_EXEC 固定加载地址 0x400000
- 只有一个 PT_LOAD（R+X）
- hello: write(1, "SYSPROBE_EXEC_OK\n", 17) + exit(0)
- socket_probe: socket(AF_INET, SOCK_STREAM, 0) 后 write 标记 + exit(7)

判定：
  exit 0  → exec 成功且 write 生效
  exit 7  → socket 调用完成（说明没被杀）
  127     → execve 失败（子进程里写的 EXEC_FAIL）
"""

import struct
import sys

EM_AARCH64 = 183
ET_EXEC = 2
PT_LOAD = 1
PF_X, PF_R = 0x1, 0x4

BASE = 0x400000
EHDR = 64
PHDR = 56
CODE_OFF = EHDR + PHDR

SYS_write = 64
SYS_socket = 198
SYS_exit = 93


def movz(rd, imm16):
    return 0xD2800000 | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def movk(rd, imm16, shift):
    hw = shift // 16
    return 0xF2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def svc0():
    return 0xD4000001


def load_imm64(rd, value):
    """固定 4 条指令，保证不同值的指令条数一致"""
    out = [movz(rd, value & 0xFFFF)]
    for shift in (16, 32, 48):
        out.append(movk(rd, (value >> shift) & 0xFFFF, shift))
    return out


def build(message: bytes, with_socket: bool) -> tuple[bytes, int]:
    def emit(msg_addr):
        c = []
        if with_socket:
            c += load_imm64(0, 2)      # AF_INET
            c += load_imm64(1, 1)      # SOCK_STREAM
            c += load_imm64(2, 0)
            c += load_imm64(8, SYS_socket)
            c.append(svc0())
        c += load_imm64(0, 1)          # x0 = stdout
        c += load_imm64(1, msg_addr)   # x1 = buf
        c += load_imm64(2, len(message))
        c += load_imm64(8, SYS_write)
        c.append(svc0())
        c += load_imm64(8, SYS_exit)
        c += load_imm64(0, 7 if with_socket else 0)
        c.append(svc0())
        return c

    probe = emit(0)
    nbytes = len(probe) * 4
    pad = (8 - (nbytes % 8)) % 8
    msg_addr = BASE + CODE_OFF + nbytes + pad

    code = emit(msg_addr)
    assert len(code) == len(probe), "指令条数变化"

    code_bytes = b"".join(struct.pack("<I", i) for i in code) + b"\x00" * pad
    payload = code_bytes + message
    total = CODE_OFF + len(payload)

    e_ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_EXEC, EM_AARCH64, 1,
        BASE + CODE_OFF, EHDR, 0, 0,
        EHDR, PHDR, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD, PF_R | PF_X, 0, BASE, BASE, total, total, 0x1000,
    )
    return ehdr + phdr + payload, msg_addr


def verify(blob: bytes, msg_addr: int, message: bytes) -> None:
    off = msg_addr - BASE
    assert blob[off:off + len(message)] == message, "消息位置错"
    code = blob[CODE_OFF:]
    svcs = 0
    for i in range(0, len(code) - 3, 4):
        w = struct.unpack("<I", code[i:i + 4])[0]
        if w == 0:
            break
        if w == svc0():
            svcs += 1
    assert svcs >= 2, f"svc 数量 {svcs} < 2"


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    import base64
    import os

    outdir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build-tmp")
    os.makedirs(outdir, exist_ok=True)

    jobs = [
        ("hello_static", b"SYSPROBE_EXEC_OK\n", False),
        ("socket_probe", b"SOCKET_CALLED\n\0\0\0", True),
    ]

    for name, msg, sock in jobs:
        blob, addr = build(msg, sock)
        verify(blob, addr, msg)
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(blob)
        print(f"  {name}: {len(blob)} 字节，消息在 0x{addr:X}")

    # 生成 ArkTS 数据文件
    hello = open(os.path.join(outdir, "hello_static"), "rb").read()
    sock_b = open(os.path.join(outdir, "socket_probe"), "rb").read()
    h_b64 = base64.b64encode(hello).decode()
    s_b64 = base64.b64encode(sock_b).decode()

    lines = [
        "// 自动生成：两个最小静态 ELF（无 libc，只调 syscall）的 base64",
        "// hello_static: write(1, \"SYSPROBE_EXEC_OK\") + exit(0)",
        "// socket_probe: socket(AF_INET, SOCK_STREAM, 0) 后 write + exit(7)",
        "",
        "export const HELLO_ELF_B64: string =",
        f"  '{h_b64}';",
        "",
        "export const SOCKET_ELF_B64: string =",
        f"  '{s_b64}';",
    ]
    ts_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "hap", "SysProbe", "entry", "src", "main", "ets", "common", "elfData.ets")
    with open(ts_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  写入 {ts_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
