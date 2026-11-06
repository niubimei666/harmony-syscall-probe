#!/usr/bin/env python3
"""
生成「单 syscall 静态探针」aarch64 ELF。

每个 ELF 只做一件事：
    movz w8, #<syscall_nr>   ; 目标 syscall，x0-x5 全为 0
    svc  #0
    movz w8, #94             ; exit_group(0)
    svc  #0

判读：
    exit 0        -> 放行（syscall 执行了，返回值被忽略，然后正常退出）
    exit 159      -> 被 seccomp KILL（128 + SIGSYS 31）
    exit 135      -> 被 SIGBUS 杀（128 + 7），极少见
    超时          -> 该 syscall 被放行但阻塞了（不是被禁）

与 issue #24 中公布的规格一致（64 字节 ELF 头 + 56 字节程序头 + 16 字节代码），
结果可与那份 461 项表直接对比。

用法：
    python gen_probes.py                     # 生成全部 0-461
    python gen_probes.py --nr 99,116,198     # 只生成指定的
    python gen_probes.py --critical          # 只生成关键项
    python gen_probes.py --mode exec         # ET_EXEC 版（默认是 PIE/ET_DYN）
    python gen_probes.py --out probes        # 输出目录
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------- aarch64 常量

EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PF_X, PF_R = 0x1, 0x4

BASE_VADDR = 0x400000
EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFF = EHDR_SIZE + PHDR_SIZE  # 120

SYS_exit_group = 94


def movz_w8(imm16: int) -> int:
    """movz w8, #imm16  ->  0x52800008 | (imm16 << 5)"""
    if not 0 <= imm16 <= 0xFFFF:
        raise ValueError(f"imm16 out of range: {imm16}")
    return 0x52800008 | ((imm16 & 0xFFFF) << 5)


SVC_0 = 0xD4000001  # svc #0


# ---------------------------------------------------------------- ELF 构造

def build_elf(syscall_nr: int, mode: str = "pie") -> bytes:
    """构造只含一个 syscall 的静态 aarch64 ELF。"""
    code = struct.pack(
        "<IIII",
        movz_w8(syscall_nr),
        SVC_0,
        movz_w8(SYS_exit_group),
        SVC_0,
    )
    assert len(code) == 16, len(code)

    total = CODE_OFF + len(code)  # 136 字节

    if mode == "exec":
        e_type = ET_EXEC
        e_entry = BASE_VADDR + CODE_OFF
        p_vaddr = BASE_VADDR
    elif mode == "pie":
        e_type = ET_DYN
        e_entry = CODE_OFF  # 相对加载基址
        p_vaddr = 0
    else:
        raise ValueError(f"unknown mode: {mode}")

    e_ident = bytes(
        [0x7F, ord("E"), ord("L"), ord("F"),
         2,   # ELFCLASS64
         1,   # ELFDATA2LSB
         1,   # EI_VERSION
         0]   # ELFOSABI_NONE
    ) + b"\x00" * 8

    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, EM_AARCH64, 1,
        e_entry, EHDR_SIZE, 0, 0,
        EHDR_SIZE, PHDR_SIZE, 1, 0, 0, 0,
    )
    assert len(ehdr) == EHDR_SIZE, len(ehdr)

    phdr = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD, PF_R | PF_X, 0,
        p_vaddr, p_vaddr, total, total, 0x1000,
    )
    assert len(phdr) == PHDR_SIZE, len(phdr)

    blob = ehdr + phdr + code
    assert len(blob) == total, (len(blob), total)
    return blob


def verify_elf(blob: bytes, syscall_nr: int) -> None:
    """反汇编级别自检：确认代码段里确实是目标 syscall。"""
    code = blob[CODE_OFF:]
    insns = struct.unpack("<IIII", code)
    want = (movz_w8(syscall_nr), SVC_0, movz_w8(SYS_exit_group), SVC_0)
    if insns != want:
        raise AssertionError(f"code mismatch for {syscall_nr}: {insns} != {want}")
    imm = (insns[0] >> 5) & 0xFFFF
    if imm != syscall_nr:
        raise AssertionError(f"imm mismatch: {imm} != {syscall_nr}")


# ---------------------------------------------------------------- syscall 表
# arm64 (asm-generic) 系统调用表，名称用于报告可读性

SYSCALLS: dict[int, str] = {
    0: "io_setup", 1: "io_destroy", 2: "io_submit", 3: "io_cancel",
    4: "io_getevents", 5: "setxattr", 6: "lsetxattr", 7: "fsetxattr",
    8: "getxattr", 9: "lgetxattr", 10: "fgetxattr", 11: "listxattr",
    12: "llistxattr", 13: "flistxattr", 14: "removexattr", 15: "lremovexattr",
    16: "fremovexattr", 17: "getcwd", 18: "lookup_dcookie", 19: "eventfd2",
    20: "epoll_create1", 21: "epoll_ctl", 22: "epoll_pwait", 23: "dup",
    24: "dup3", 25: "fcntl", 26: "inotify_init1", 27: "inotify_add_watch",
    28: "inotify_rm_watch", 29: "ioctl", 30: "ioprio_set", 31: "ioprio_get",
    32: "flock", 33: "mknodat", 34: "mkdirat", 35: "unlinkat", 36: "symlinkat",
    37: "linkat", 38: "renameat", 39: "umount2", 40: "mount", 41: "pivot_root",
    42: "nfsservctl", 43: "statfs", 44: "fstatfs", 45: "truncate",
    46: "ftruncate", 47: "fallocate", 48: "faccessat", 49: "chdir",
    50: "fchdir", 51: "chroot", 52: "fchmod", 53: "fchmodat", 54: "fchownat",
    55: "fchown", 56: "openat", 57: "close", 58: "vhangup", 59: "pipe2",
    60: "quotactl", 61: "getdents64", 62: "lseek", 63: "read", 64: "write",
    65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64",
    69: "preadv", 70: "pwritev", 71: "sendfile", 72: "pselect6", 73: "ppoll",
    74: "signalfd4", 75: "vmsplice", 76: "splice", 77: "tee",
    78: "readlinkat", 79: "newfstatat", 80: "fstat", 81: "sync",
    82: "fsync", 83: "fdatasync", 84: "sync_file_range", 85: "timerfd_create",
    86: "timerfd_settime", 87: "timerfd_gettime", 88: "utimensat",
    89: "acct", 90: "capget", 91: "capset", 92: "personality",
    93: "exit", 94: "exit_group", 95: "waitid", 96: "set_tid_address",
    97: "unshare", 98: "futex", 99: "set_robust_list",
    100: "get_robust_list", 101: "nanosleep", 102: "getitimer",
    103: "setitimer", 104: "kexec_load", 105: "init_module",
    106: "delete_module", 107: "timer_create", 108: "timer_gettime",
    109: "timer_getoverrun", 110: "timer_settime", 111: "timer_delete",
    112: "clock_settime", 113: "clock_gettime", 114: "clock_getres",
    115: "clock_nanosleep", 116: "syslog", 117: "ptrace",
    118: "sched_setparam", 119: "sched_setscheduler", 120: "sched_getscheduler",
    121: "sched_getparam", 122: "sched_setaffinity", 123: "sched_getaffinity",
    124: "sched_yield", 125: "sched_get_priority_max",
    126: "sched_get_priority_min", 127: "sched_rr_get_interval",
    128: "restart_syscall", 129: "kill", 130: "tkill", 131: "tgkill",
    132: "sigaltstack", 133: "rt_sigsuspend", 134: "rt_sigaction",
    135: "rt_sigprocmask", 136: "rt_sigpending", 137: "rt_sigtimedwait",
    138: "rt_sigqueueinfo", 139: "rt_sigreturn", 140: "setpriority",
    141: "getpriority", 142: "reboot", 143: "setregid", 144: "setgid",
    145: "setreuid", 146: "setuid", 147: "setresuid", 148: "getresuid",
    149: "setresgid", 150: "getresgid", 151: "setfsuid", 152: "setfsgid",
    153: "times", 154: "setpgid", 155: "getpgid", 156: "getsid",
    157: "setsid", 158: "getgroups", 159: "setgroups", 160: "uname",
    161: "sethostname", 162: "setdomainname", 163: "getrlimit",
    164: "setrlimit", 165: "getrusage", 166: "umask", 167: "prctl",
    168: "getcpu", 169: "gettimeofday", 170: "settimeofday",
    171: "adjtimex", 172: "getpid", 173: "getppid", 174: "getuid",
    175: "geteuid", 176: "getgid", 177: "getegid", 178: "gettid",
    179: "sysinfo", 180: "mq_open", 181: "mq_unlink", 182: "mq_timedsend",
    183: "mq_timedreceive", 184: "mq_notify", 185: "mq_getsetattr",
    186: "msgget", 187: "msgctl", 188: "msgrcv", 189: "msgsnd",
    190: "semget", 191: "semctl", 192: "semtimedop", 193: "semop",
    194: "shmget", 195: "shmctl", 196: "shmat", 197: "shmdt",
    198: "socket", 199: "socketpair", 200: "bind", 201: "listen",
    202: "accept", 203: "connect", 204: "getsockname", 205: "getpeername",
    206: "sendto", 207: "recvfrom", 208: "setsockopt", 209: "getsockopt",
    210: "shutdown", 211: "sendmsg", 212: "recvmsg", 213: "readahead",
    214: "brk", 215: "munmap", 216: "mremap", 217: "add_key",
    218: "request_key", 219: "keyctl", 220: "clone", 221: "execve",
    222: "mmap", 223: "fadvise64", 224: "swapon", 225: "swapoff",
    226: "mprotect", 227: "msync", 228: "mlock", 229: "munlock",
    230: "mlockall", 231: "munlockall", 232: "mincore", 233: "madvise",
    234: "remap_file_pages", 235: "mbind", 236: "get_mempolicy",
    237: "set_mempolicy", 238: "migrate_pages", 239: "move_pages",
    240: "rt_tgsigqueueinfo", 241: "perf_event_open", 242: "accept4",
    243: "recvmmsg", 260: "wait4", 261: "prlimit64", 262: "fanotify_init",
    263: "fanotify_mark", 264: "name_to_handle_at", 265: "open_by_handle_at",
    266: "clock_adjtime", 267: "syncfs", 268: "setns", 269: "sendmmsg",
    270: "process_vm_readv", 271: "process_vm_writev", 272: "kcmp",
    273: "finit_module", 274: "sched_setattr", 275: "sched_getattr",
    276: "renameat2", 277: "seccomp", 278: "getrandom", 279: "memfd_create",
    280: "bpf", 281: "execveat", 282: "userfaultfd", 283: "membarrier",
    284: "mlock2", 285: "copy_file_range", 286: "preadv2", 287: "pwritev2",
    288: "pkey_mprotect", 289: "pkey_alloc", 290: "pkey_free",
    291: "statx", 292: "io_pgetevents", 293: "rseq",
    294: "kexec_file_load", 424: "pidfd_send_signal", 425: "io_uring_setup",
    426: "io_uring_enter", 427: "io_uring_register", 428: "open_tree",
    429: "move_mount", 430: "fsopen", 431: "fsconfig", 432: "fsmount",
    433: "fspick", 434: "pidfd_open", 435: "clone3", 436: "close_range",
    437: "openat2", 438: "pidfd_getfd", 439: "faccessat2",
    440: "process_madvise", 441: "epoll_pwait2", 442: "mount_setattr",
    443: "quotactl_fd", 444: "landlock_create_ruleset",
    445: "landlock_add_rule", 446: "landlock_restrict_self",
    447: "memfd_secret", 448: "process_mrelease", 449: "futex_waitv",
    450: "set_mempolicy_home_node", 451: "cachestat",
    452: "fchmodat2", 453: "map_shadow_stack",
}

# 关键项：直接决定「能不能跑 Node / 本机引擎」
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


# ---------------------------------------------------------------- 主流程

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    ap = argparse.ArgumentParser(description="生成单 syscall aarch64 静态探针")
    ap.add_argument("--out", default="probes", help="输出目录")
    ap.add_argument("--mode", choices=["pie", "exec"], default="pie")
    ap.add_argument("--nr", default="", help="只生成指定编号，逗号分隔")
    ap.add_argument("--range", default="0-461", help="编号范围")
    ap.add_argument("--critical", action="store_true", help="只生成关键项")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.critical:
        targets = sorted(CRITICAL)
    elif args.nr:
        targets = [int(x) for x in args.nr.split(",") if x.strip()]
    else:
        lo, _, hi = args.range.partition("-")
        targets = list(range(int(lo), int(hi) + 1))

    os.makedirs(args.out, exist_ok=True)

    written = 0
    for nr in targets:
        blob = build_elf(nr, args.mode)
        verify_elf(blob, nr)
        with open(os.path.join(args.out, f"{nr:03d}"), "wb") as fh:
            fh.write(blob)
        written += 1

    names_path = os.path.join(args.out, "_syscall_names.tsv")
    with open(names_path, "w", encoding="utf-8") as fh:
        for nr in sorted(set(list(SYSCALLS) + list(CRITICAL))):
            fh.write(f"{nr}\t{SYSCALLS.get(nr, 'unknown')}\t"
                     f"{'CRITICAL' if nr in CRITICAL else ''}\n")

    if not args.quiet:
        print(f"生成 {written} 个探针 -> {os.path.abspath(args.out)}")
        print(f"ELF 类型: {'ET_DYN (PIE)' if args.mode == 'pie' else 'ET_EXEC'}")
        sample = targets[0]
        print(f"每个 {len(build_elf(sample, args.mode))} 字节，已通过反汇编自检")
        print(f"名称表: {names_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
