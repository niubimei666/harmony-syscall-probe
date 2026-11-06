/**
 * libexecprobe.so 的类型声明
 */

export interface ExecResult {
  path: string;
  bytes: number;
  written: number;
  chmodOk: number;
  started: number;
  exitCode: number;
  waitErrno: number;
  output: string;
}

/**
 * 把 base64 编码的 ELF 写到 dir/name，chmod 755，然后 fork+execve 执行，
 * 捕获 stdout/stderr 与退出码。
 */
export function execPayload(dir: string, name: string, base64Content: string): string;
