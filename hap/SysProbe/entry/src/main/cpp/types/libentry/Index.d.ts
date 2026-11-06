/**
 * libentry.so 的类型声明
 * 与 entry/src/main/cpp/sysprobe.cpp 导出的 NAPI 接口一一对应
 */

export interface ProbeRaw {
  nr: number;
  ret: number;
  errno: number;
  caught: number;
  verdict: string;
}

export interface ProbeContext {
  selinux: string;
  uid: number;
  seccomp: number;
  seccompFilters: number;
  capEff: string;
  capBnd: string;
  noNewPrivs: string;
}

/**
 * 批量执行 syscall 探针（一次性，进程被杀则全部丢失）
 * @param numbers 逗号分隔的编号；空字符串表示 0-461 全量
 */
export function runProbes(numbers: string): string;

/**
 * 单步执行一个 syscall，并把结果追加写入文件后 fsync。
 * 进程被 SECCOMP_RET_KILL 杀掉时，已完成的项仍在文件里。
 * @param nr syscall 编号
 * @param path 追加写入的文件路径（传空字符串则不落盘）
 */
export function runOnePersist(nr: number, path: string): string;

/** 往文件追加一行（用于记录开始/结束标记、上下文） */
export function appendLine(path: string, line: string): string;

/** 清空文件 */
export function resetFile(path: string): string;

/** 读取当前进程上下文（SELinux 域、seccomp 状态、能力集） */
export function getContext(): string;
