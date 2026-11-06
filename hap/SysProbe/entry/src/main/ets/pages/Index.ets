import { hilog } from '@kit.PerformanceAnalysisKit';
import { pasteboard } from '@kit.BasicServicesKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { common } from '@kit.AbilityKit';

// 原生模块（类型见 src/main/cpp/types/*/Index.d.ts）
import probe from 'libentry.so';
import { ProbeRaw, ProbeContext } from 'libentry.so';
import execprobe from 'libexecprobe.so';
import { ExecResult } from 'libexecprobe.so';
import dlprobe from 'libdlprobe.so';
import { DlopenResult, DiagStep } from 'libdlprobe.so';
import { HELLO_ELF_B64, SOCKET_ELF_B64 } from '../common/elfData';
import { PROBELIB_B64 } from '../common/probelibData';

const DOMAIN = 0x0000;

interface CritItem {
  nr: number;
  name: string;
  why: string;
}

const CRITICAL: CritItem[] = [
  { nr: 17, name: 'getcwd', why: 'PRoot 路径翻译的试金石' },
  { nr: 99, name: 'set_robust_list', why: 'glibc 主线程初始化' },
  { nr: 100, name: 'get_robust_list', why: '' },
  { nr: 117, name: 'ptrace', why: 'PRoot 的全部前提' },
  { nr: 198, name: 'socket', why: '任何网络 / dsh web 监听' },
  { nr: 199, name: 'socketpair', why: '' },
  { nr: 202, name: 'accept', why: '' },
  { nr: 203, name: 'connect', why: '调 LLM API 必需' },
  { nr: 220, name: 'clone', why: '线程创建老路径' },
  { nr: 221, name: 'execve', why: 'PRoot 启动引擎' },
  { nr: 222, name: 'mmap', why: '' },
  { nr: 242, name: 'accept4', why: '' },
  { nr: 277, name: 'seccomp', why: '' },
  { nr: 278, name: 'getrandom', why: '' },
  { nr: 293, name: 'rseq', why: 'glibc 2.35+' },
  { nr: 425, name: 'io_uring_setup', why: '' },
  { nr: 435, name: 'clone3', why: 'glibc 2.34+ pthread_create 首选' },
  { nr: 437, name: 'openat2', why: '' },
  { nr: 439, name: 'faccessat2', why: '' },
];

interface ProbeRow {
  nr: number;
  ret: number;
  err: string;
  verdict: string;
  name: string;
  crit: boolean;
  why: string;
}

const ERRNO_NAMES: Record<number, string> = {
  1: 'EPERM', 2: 'ENOENT', 3: 'ESRCH', 4: 'EINTR', 5: 'EIO', 6: 'ENXIO',
  9: 'EBADF', 11: 'EAGAIN', 12: 'ENOMEM', 13: 'EACCES', 14: 'EFAULT',
  16: 'EBUSY', 17: 'EEXIST', 19: 'ENODEV', 20: 'ENOTDIR', 21: 'EISDIR',
  22: 'EINVAL', 23: 'ENFILE', 24: 'EMFILE', 25: 'ENOTTY', 28: 'ENOSPC',
  30: 'EROFS', 32: 'EPIPE', 38: 'ENOSYS', 95: 'EOPNOTSUPP', 98: 'EADDRINUSE',
  111: 'ECONNREFUSED',
};

const VERDICT_NONE = '未测';

@Entry
@Component
struct Index {
  @State ctxText: string = '未采样';
  @State running: boolean = false;
  @State progress: string = '';
  @State rows: ProbeRow[] = [];
  @State summary: string = '';
  @State verdictText: string = '';
  @State showAll: boolean = false;
  @State resumeHint: string = '';
  @State execLog: string = '';
  @State resultMap: Map<number, ProbeRow> = new Map();

  private logPath: string = '';
  private skipSet: Set<number> = new Set();

  aboutToAppear(): void {
    this.initLogPath();
    this.loadFromLog();
  }

  private initLogPath(): string {
    if (this.logPath.length > 0) {
      return this.logPath;
    }
    try {
      const ctx = getContext(this) as common.UIAbilityContext;
      this.logPath = ctx.filesDir + '/sysprobe.log';
    } catch (e) {
      this.logPath = '/data/storage/el2/base/files/sysprobe.log';
    }
    return this.logPath;
  }

  private loadFromLog(): void {
    const p = this.initLogPath();
    try {
      if (!fs.accessSync(p)) {
        return;
      }
      const content = fs.readTextSync(p);
      const lines = content.split('\n');
      const map: Map<number, ProbeRow> = new Map();
      let ctxLine = '';
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('# CTX ')) {
          ctxLine = line.substring(6).split(' | ').join('\n');
        } else if (line.startsWith('# KILLED ')) {
          this.skipSet.add(Number(line.substring(9).trim()));
        } else if (line.startsWith('{')) {
          const one = this.buildRows(`[${line}]`);
          for (let j = 0; j < one.length; j++) {
            map.set(one[j].nr, one[j]);
          }
        }
      }
      if (ctxLine.length > 0) {
        this.ctxText = ctxLine;
      }
      this.resultMap = map;
      this.rows = this.criticalRows();

      const finished = content.indexOf('# END') >= 0;
      if (map.size > 0) {
        if (finished) {
          this.resumeHint = `日志里已有 ${map.size} 项结果（上次跑完）`;
        } else {
          this.resumeHint = `上次跑到第 ${this.lastNr(map)} 号就断了（共 ${map.size} 项有效）`;
        }
        this.analyze();
      }
    } catch (e) {
      hilog.warn(DOMAIN, 'SysProbe', 'loadFromLog: %{public}s', JSON.stringify(e));
    }
  }

  private lastNr(map: Map<number, ProbeRow>): number {
    let maxNr = -1;
    map.forEach((_v: ProbeRow, k: number) => {
      if (k > maxNr) {
        maxNr = k;
      }
    });
    return maxNr;
  }

  private criticalRows(): ProbeRow[] {
    const out: ProbeRow[] = [];
    for (let i = 0; i < CRITICAL.length; i++) {
      const hit: ProbeRow | undefined = this.resultMap.get(CRITICAL[i].nr);
      if (hit !== undefined) {
        out.push(hit);
      }
    }
    return out;
  }

  private buildRows(raw: string): ProbeRow[] {
    const arr: ProbeRaw[] = JSON.parse(raw) as ProbeRaw[];
    const critMap: Map<number, CritItem> = new Map();
    for (let i = 0; i < CRITICAL.length; i++) {
      critMap.set(CRITICAL[i].nr, CRITICAL[i]);
    }
    const out: ProbeRow[] = [];
    for (let i = 0; i < arr.length; i++) {
      const item: ProbeRaw = arr[i];
      const nr: number = item.nr;
      const code: number = item.errno;
      const crit: CritItem | undefined = critMap.get(nr);
      const errName: string = ERRNO_NAMES[code] !== undefined
        ? ERRNO_NAMES[code]
        : (code !== 0 ? `errno=${code}` : '');
      out.push({
        nr: nr,
        ret: item.ret,
        err: errName,
        verdict: item.verdict,
        name: crit !== undefined ? crit.name : '',
        crit: crit !== undefined,
        why: crit !== undefined ? crit.why : '',
      });
    }
    return out;
  }

  private readContext(): ProbeContext | null {
    try {
      return JSON.parse(probe.getContext()) as ProbeContext;
    } catch (e) {
      hilog.error(DOMAIN, 'SysProbe', 'getContext failed: %{public}s', JSON.stringify(e));
      return null;
    }
  }

  private refreshCtx(): void {
    const ctx: ProbeContext | null = this.readContext();
    if (ctx !== null) {
      this.ctxText = `seccomp=${ctx.seccomp}  filters=${ctx.seccompFilters}  uid=${ctx.uid}\n` +
        `SELinux=${ctx.selinux}\n` +
        `CapEff=${ctx.capEff}  CapBnd=${ctx.capBnd}  NoNewPrivs=${ctx.noNewPrivs}`;
    }
  }

  // ---------------- 判读：严格区分「没测到」和「被挡」
  private judge(nr: number): string {
    const r: ProbeRow | undefined = this.resultMap.get(nr);
    return r === undefined ? VERDICT_NONE : r.verdict;
  }

  private isAllow(nr: number): boolean {
    return this.judge(nr).indexOf('ALLOWED') >= 0;
  }

  private analyze(): void {
    const socketV = this.judge(198);
    const ptraceV = this.judge(117);
    const clone3V = this.judge(435);
    const cloneV = this.judge(220);
    const robustV = this.judge(99);

    const fmt = (label: string, v: string, okText: string, badText: string): string => {
      if (v === VERDICT_NONE) {
        return `${label}: ⬜ 未测`;
      }
      return `${label}: ${v.indexOf('ALLOWED') >= 0 ? okText : badText}（${v}）`;
    };

    const lines: string[] = [];
    lines.push(fmt('socket', socketV, '✅ 可用', '❌ 被挡'));
    lines.push(fmt('ptrace', ptraceV, '✅ 可用', '❌ 被挡') + '  ← PRoot 前提');
    if (clone3V === VERDICT_NONE && cloneV === VERDICT_NONE) {
      lines.push('线程: ⬜ 未测');
    } else if (clone3V.indexOf('ALLOWED') >= 0) {
      lines.push(`线程: ✅ clone3 可用（${clone3V}）`);
    } else if (cloneV.indexOf('ALLOWED') >= 0) {
      lines.push(`线程: ⚠️ 仅 clone 可用（clone3=${clone3V}）`);
    } else {
      lines.push(`线程: ❌ 都不可用（clone3=${clone3V}, clone=${cloneV}）`);
    }
    lines.push(fmt('glibc 初始化', robustV, '✅ 可以', '❌ 被挡'));

    this.verdictText = lines.join('\n');

    const socketTested = socketV !== VERDICT_NONE;
    const threadTested = clone3V !== VERDICT_NONE || cloneV !== VERDICT_NONE;
    if (!socketTested || !threadTested) {
      this.summary = '结论待定：关键项还没测全，继续点测或批量跑。';
      return;
    }
    if (this.isAllow(198) && (this.isAllow(435) || this.isAllow(220))) {
      this.summary = '结论：本机引擎有戏。socket 与线程创建都通，剩下是运行时适配问题。';
    } else if (!this.isAllow(198)) {
      this.summary = '结论：本机引擎在这台设备上物理不可行——socket 被 seccomp 挡住。';
    } else {
      this.summary = '结论：socket 通但线程创建被挡，Node 运行时仍然起不来。';
    }
  }

  // ---------------- 单点测试
  private testOne(nr: number): void {
    if (this.running) {
      return;
    }
    this.running = true;
    const p = this.initLogPath();
    probe.appendLine(p, `# TESTONE ${nr}`);
    this.progress = `测试 ${nr} 号...`;

    setTimeout(() => {
      try {
        const raw: string = probe.runOnePersist(nr, p);
        const one: ProbeRow[] = this.buildRows(`[${raw}]`);
        if (one.length > 0) {
          this.resultMap.set(nr, one[0]);
          this.rows = this.criticalRows();
          this.analyze();
          this.progress = `${nr} 号完成：${one[0].verdict}`;
        }
      } catch (e) {
        this.progress = `${nr} 号失败：` + JSON.stringify(e);
      }
      this.running = false;
    }, 50);
  }

  // ---------------- 批量：跳过已知会杀进程的项
  private runBatch(all: boolean): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.refreshCtx();

    const p = this.initLogPath();
    const numbers: number[] = all
      ? Array.from({ length: 462 }, (_: Object, i: number) => i)
      : CRITICAL.map((c: CritItem) => c.nr);
    const todo: number[] = numbers.filter((n: number) => !this.skipSet.has(n));

    probe.resetFile(p);
    probe.appendLine(p, `# START ${new Date().toISOString()} all=${all} todo=${todo.length}`);
    probe.appendLine(p, `# CTX ${this.ctxText.replace(/\n/g, ' | ')}`);

    this.resultMap = new Map();
    this.rows = [];
    this.progress = `0/${todo.length}`;

    let idx = 0;
    const step = (): void => {
      const batchEnd = Math.min(idx + 6, todo.length);
      for (; idx < batchEnd; idx++) {
        const nr = todo[idx];
        probe.appendLine(p, `# KILLMARK ${nr}`);
        try {
          const raw: string = probe.runOnePersist(nr, p);
          const one: ProbeRow[] = this.buildRows(`[${raw}]`);
          if (one.length > 0) {
            this.resultMap.set(nr, one[0]);
          }
        } catch (e) {
          hilog.error(DOMAIN, 'SysProbe', 'batch %{public}d: %{public}s', nr, JSON.stringify(e));
        }
      }
      this.rows = this.criticalRows();
      this.progress = `${idx}/${todo.length}`;
      if (idx < todo.length) {
        setTimeout(step, 0);
        return;
      }
      probe.appendLine(p, `# END ${new Date().toISOString()}`);
      this.analyze();
      this.progress = `完成 ${this.resultMap.size} 项`;
      this.running = false;
    };
    setTimeout(step, 80);
  }

  // ---------------- exec 测试
  private runExecTest(which: string): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.execLog = '执行中...';

    setTimeout(() => {
      const dir = this.initExecDir();
      const name = which === 'hello' ? 'hello_static' : 'socket_probe';
      const payload = which === 'hello' ? HELLO_ELF_B64 : SOCKET_ELF_B64;
      try {
        const raw: string = execprobe.execPayload(dir, name, payload);
        const r: ExecResult = JSON.parse(raw) as ExecResult;
        const lines: string[] = [];
        lines.push(`写入 ${r.bytes}B chmod=${r.chmodOk}`);
        lines.push(`fork=${r.started} exit=${r.exitCode}`);
        if (r.output.length > 0) {
          lines.push(`out: ${r.output.trim()}`);
        }
        lines.push('---');
        if (r.exitCode === 0 && r.output.indexOf('SYSPROBE_EXEC_OK') >= 0) {
          lines.push('✅ 能 fork+exec 自建 ELF');
        } else if (r.exitCode === 7) {
          lines.push('✅ socket 已调用未杀进程');
        } else if (r.output.indexOf('EXEC_FAIL') >= 0) {
          lines.push('❌ execve 被拒');
        } else {
          lines.push(`⚠️ exit=${r.exitCode}`);
        }
        this.execLog = lines.join('\n');
      } catch (e) {
        this.execLog = '失败：' + JSON.stringify(e);
      }
      this.running = false;
    }, 50);
  }

  // ---------------- dlopen 诊断
  private runDlopenTest(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.execLog = 'dlopen 诊断中...';

    setTimeout(() => {
      const dir = this.initExecDir();
      let hapLib = '';
      try {
        const ctx = getContext(this) as common.UIAbilityContext;
        hapLib = ctx.bundleCodeDir + '/libs/arm64/libprobelib.so';
      } catch (e) {
        hapLib = '';
      }
      try {
        const raw: string = dlprobe.diagPayload(dir, 'libprobelib.so', PROBELIB_B64, hapLib);
        const r: DlopenResult = JSON.parse(raw) as DlopenResult;
        this.execLog = this.formatDlopenShort(r);
      } catch (e) {
        this.execLog = '失败：' + JSON.stringify(e);
      }
      this.running = false;
    }, 50);
  }

  /** 压成紧凑格式，确保一屏能显示完 */
  private formatDlopenShort(r: DlopenResult): string {
    const lines: string[] = [];
    for (let i = 0; i < r.steps.length; i++) {
      const s: DiagStep = r.steps[i];
      if (s.name.indexOf('RTLD_GLOBAL') >= 0) {
        continue;
      }
      let name: string = s.name;
      if (name.indexOf('dlopen(') === 0) {
        name = 'dlopen';
      }
      const mark = s.ok === 1 ? 'OK  ' : 'FAIL';
      let line = `${mark} ${name}`;
      if (s.ok !== 1 && s.err !== 0) {
        line += ` e=${s.err}`;
      }
      lines.push(line);
    }
    lines.push('---');
    if (r.answerOk === 1 && r.answer === 42) {
      lines.push('✅ 可用：进程内嵌可行');
    } else if (r.opened === 1) {
      lines.push('⚠️ 能开但符号解析失败');
    } else {
      lines.push('❌ 不可用');
    }
    return lines.join('\n');
  }

  private initExecDir(): string {
    try {
      const ctx = getContext(this) as common.UIAbilityContext;
      const d = ctx.filesDir + '/exec';
      try {
        fs.mkdirSync(d);
      } catch (e) {
        // 已存在
      }
      return d;
    } catch (e) {
      return '/data/storage/el2/base/files';
    }
  }

  private exportReport(): void {
    const lines: string[] = [];
    lines.push('# 鸿蒙 syscall 能力地图（应用沙箱内实测）');
    lines.push('');
    lines.push('## 进程上下文');
    lines.push('```');
    lines.push(this.ctxText);
    lines.push('```');
    lines.push('');
    lines.push('## 判读');
    lines.push('```');
    lines.push(this.verdictText);
    lines.push('未测 = 该编号还没执行到（可能被前一项的 SECCOMP_RET_KILL 中断）');
    lines.push('```');
    lines.push('');
    lines.push(this.summary);
    lines.push('');
    lines.push('## 关键项');
    lines.push('| nr | syscall | 结果 | 返回值 | errno |');
    lines.push('|---:|---|---|---:|---|');
    for (let i = 0; i < CRITICAL.length; i++) {
      const c: CritItem = CRITICAL[i];
      const r: ProbeRow | undefined = this.resultMap.get(c.nr);
      if (r !== undefined) {
        lines.push(`| ${c.nr} | ${c.name} | ${r.verdict} | ${r.ret} | ${r.err} |`);
      } else {
        lines.push(`| ${c.nr} | ${c.name} | 未测 | - | - |`);
      }
    }
    lines.push('');
    lines.push('方法：NAPI 内直接 svc #0，x0-x5 全 0，SIGSYS/SIGSEGV handler 捕获。');

    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, lines.join('\n'));
    pasteboard.getSystemPasteboard().setData(data).then(() => {
      this.progress = '报告已复制到剪贴板';
    }).catch((e: Error) => {
      this.progress = '复制失败：' + e.message;
    });
  }

  // ---------------- UI

  @Builder
  CritChip(c: CritItem) {
    Column() {
      Text(c.name)
        .fontSize(11)
        .fontWeight(FontWeight.Medium)
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
      Text(this.judge(c.nr) === VERDICT_NONE ? '未测' : this.judge(c.nr))
        .fontSize(9)
        .fontColor(this.judge(c.nr).indexOf('ALLOWED') >= 0 ? '#2E8B57'
          : (this.judge(c.nr) === VERDICT_NONE ? '#999' : '#C0392B'))
        .margin({ top: 2 })
    }
    .width(96)
    .height(46)
    .justifyContent(FlexAlign.Center)
    .padding(4)
    .margin(3)
    .backgroundColor(this.skipSet.has(c.nr) ? '#FFEDED' : '#F2F2F2')
    .borderRadius(6)
    .onClick(() => {
      this.testOne(c.nr);
    })
  }

  @Builder
  ResultRow(r: ProbeRow) {
    Row() {
      Text(r.nr.toString()).fontSize(13).fontColor('#888').width(44)
      Column() {
        Text(r.name.length > 0 ? r.name : `syscall ${r.nr}`)
          .fontSize(14)
          .fontWeight(r.crit ? FontWeight.Medium : FontWeight.Normal)
        if (r.why.length > 0) {
          Text(r.why).fontSize(11).fontColor('#999').maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      Text(r.verdict)
        .fontSize(12)
        .fontColor(r.verdict.indexOf('ALLOWED') >= 0 ? '#2E8B57' : '#C0392B')
        .fontWeight(FontWeight.Medium)
    }
    .width('100%')
    .padding({ top: 8, bottom: 8, left: 4, right: 4 })
    .border({ width: { bottom: 1 }, color: '#1A000000' })
  }

  build() {
    Column() {
      Column() {
        Text('鸿蒙 syscall 能力探针').fontSize(19).fontWeight(FontWeight.Bold).width('100%')
        Text('点方块单测一项；塞住就重启再点别的')
          .fontSize(11).fontColor('#888').width('100%').margin({ top: 3 })
      }
      .padding({ left: 16, right: 16, top: 10, bottom: 8 })
      .width('100%')

      Column() {
        Text(this.ctxText).fontSize(10).fontFamily('monospace').fontColor('#555').width('100%')
      }
      .padding(10)
      .margin({ left: 14, right: 14 })
      .backgroundColor('#F5F5F5')
      .borderRadius(8)
      .width('calc(100% - 28vp)')

      if (this.resumeHint.length > 0) {
        Text(this.resumeHint)
          .fontSize(11)
          .fontColor('#8A5A00')
          .width('calc(100% - 28vp)')
          .padding(8)
          .margin({ left: 14, right: 14, top: 6 })
          .backgroundColor('#FFF6E5')
          .borderRadius(6)
      }

      Text('关键项（点击单项测试）')
        .fontSize(12).fontWeight(FontWeight.Bold).width('100%')
        .padding({ left: 16, right: 16, top: 10, bottom: 2 })

      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.Start }) {
        ForEach(CRITICAL, (c: CritItem) => {
          this.CritChip(c)
        }, (c: CritItem) => c.nr.toString())
      }
      .padding({ left: 11, right: 11 })

      Row({ space: 8 }) {
        Button('跑剩余关键项')
          .fontSize(13).height(34).layoutWeight(1).enabled(!this.running)
          .onClick(() => {
            this.runBatch(false);
          })
        Button('跑全量 462')
          .fontSize(13).height(34).layoutWeight(1).enabled(!this.running)
          .backgroundColor('#EEE').fontColor('#333')
          .onClick(() => {
            this.runBatch(true);
          })
      }
      .padding({ left: 14, right: 14, top: 8 })

      Row({ space: 8 }) {
        Button('exec hello')
          .fontSize(11).height(30).layoutWeight(1).enabled(!this.running)
          .backgroundColor('#E8F0FE').fontColor('#1A4C9C')
          .onClick(() => {
            this.runExecTest('hello');
          })
        Button('exec socket')
          .fontSize(11).height(30).layoutWeight(1).enabled(!this.running)
          .backgroundColor('#E8F0FE').fontColor('#1A4C9C')
          .onClick(() => {
            this.runExecTest('socket');
          })
        Button('dlopen .so')
          .fontSize(11).height(30).layoutWeight(1).enabled(!this.running)
          .backgroundColor('#E6F4EA').fontColor('#136C34')
          .onClick(() => {
            this.runDlopenTest();
          })
      }
      .padding({ left: 14, right: 14, top: 6 })

      if (this.execLog.length > 0) {
        Text(this.execLog)
          .fontSize(10).fontFamily('monospace').fontColor('#333')
          .width('calc(100% - 28vp)')
          .padding(8)
          .margin({ left: 14, right: 14, top: 6 })
          .backgroundColor('#F0F4FF')
          .borderRadius(6)
      }

      if (this.progress.length > 0) {
        Text(this.progress).fontSize(11).fontColor('#666').width('100%')
          .padding({ left: 16, right: 16, top: 6 })
      }

      if (this.verdictText.length > 0) {
        Column() {
          Text('判读').fontSize(12).fontWeight(FontWeight.Bold).width('100%').margin({ bottom: 4 })
          Text(this.verdictText).fontSize(11).fontFamily('monospace').width('100%')
          Divider().margin({ top: 8, bottom: 8 })
          Text(this.summary).fontSize(12).width('100%')
        }
        .padding(10)
        .margin({ left: 14, right: 14, top: 8 })
        .backgroundColor('#F0F7F0')
        .borderRadius(8)
        .alignItems(HorizontalAlign.Start)
        .width('calc(100% - 28vp)')
      }

      if (this.rows.length > 0) {
        Row() {
          Text(`已测 ${this.resultMap.size} 项`).fontSize(12).fontWeight(FontWeight.Bold).layoutWeight(1)
          Text('复制报告').fontSize(12).fontColor('#4A78C2')
            .onClick(() => {
              this.exportReport();
            })
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 8, bottom: 2 })

        List() {
          ForEach(this.rows, (r: ProbeRow) => {
            ListItem() {
              this.ResultRow(r)
            }
          }, (r: ProbeRow) => r.nr.toString())
        }
        .layoutWeight(1)
        .padding({ left: 14, right: 14 })
      } else {
        Blank()
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor(Color.White)
  }
}
