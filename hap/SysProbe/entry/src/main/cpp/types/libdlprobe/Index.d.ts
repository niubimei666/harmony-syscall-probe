/**
 * libdlprobe.so 的类型声明（诊断版）
 */

export interface DiagStep {
  name: string;
  ok: number;
  err: number;
  detail: string;
}

export interface DlopenResult {
  path: string;
  bytes: number;
  opened: number;
  answer: number;
  answerOk: number;
  symErrno: number;
  symErr: string;
  steps: DiagStep[];
}

/**
 * 逐步诊断 dlopen：写入 → stat → open+read → mmap → dlopen(三种模式) → dlsym
 *
 * @param dir 目标目录
 * @param name 文件名
 * @param base64Content .so 的 base64
 * @param hapLibPath 对照组：HAP 自己 libs 目录里的 .so 绝对路径
 */
export function diagPayload(dir: string, name: string, base64Content: string,
                            hapLibPath: string): string;
