# aidbg 开发文档（dev）

<p align="center">
  <a href="README.md">中文</a> | <a href="README.en.md">English</a>
  　·　<a href="Manual.md">Manual</a> | <a href="dev.md">dev</a>
</p>

---

面向开发者/维护者：构建系统、架构分层、关键设计决策与实测踩坑记录。
使用者请看 [Manual.md](Manual.md)，项目简介见 [README.md](README.md)。

---

## 1. 构建

```bat
build.bat Release
```

`build.bat` 依次完成：

1. 定位并调用 `vcvars64.bat`（优先 VS 18 的本机路径，找不到时自动搜索
   VS 18/2022/2019 的 Professional/Community/Enterprise/BuildTools）初始化 MSVC 环境
2. **编译内置 DLL 宿主**（`src/host/dllhost.c`）→ `build/host/dllhost64.exe`（本机 cl）
   与 `dllhost32.exe`（在独立的 `vcvars32` 环境里编，x64 环境链接不出 x86 目标）
3. CMake（NMake Makefiles）配置 + 构建主程序，资源脚本 `src/host/aidbg.rc` 把两个
   stub 以 RCDATA 嵌进 aidbg.exe

依赖与运行时：

- **Zydis 4.1.1**（`third_party/zydis`，已 vendored）：反汇编；x86 目标用 `LONG_COMPAT_32` 模式
- **DbgHelp**：PDB 符号、行号、类型（`SymGetTypeFromName` / `SymGetTypeInfo`）
- **MS Compression（cabinet.dll）**：快照 XPRESS_HUFF 压缩，系统自带
- **VC-LTL**（`D:\vc\VC-LTL-Binary`，ucrt 模式）+ `/MT`：产物只依赖
  `KERNEL32` / `dbghelp` / `cabinet` / `ucrtbase`，**无 VC 运行时依赖**；
  VC-LTL 缺失时 CMake 自动退回纯静态 `/MT`

输出位置固定为 `build\aidbg.exe`。

## 2. 目录结构

```
src/
  main.cpp             CLI 入口：-c / --script / 交互 / --mcp；--hide/--aslr 等参数
  cmd/commands.cpp     命令注册、解析与分发（70+ 命令）
  mcp/mcp_server.cpp   MCP 服务器（13 工具，信封与 CLI 一致）
  output/output.cpp    JSON/文本双格式输出层（事件、信封、quiet 模式）
  engine/
    engine.cpp         调试事件循环、进程/线程/模块、执行控制、固定基址
    breakpoints.cpp    软/硬/内存断点 + 条件 + 命中命令
    hide.cpp           反反调试：L1 补丁 + L2 API 虚拟化 + detect
    notes.cpp          用户标签/注释（模块+RVA 锚定）
    memory.cpp registers.cpp symbols.cpp expr.cpp types.cpp
    exceptions.cpp disasm.cpp cfg.cpp
    ntview.cpp         TEB/PEB/堆/句柄视图
    snapshot.cpp snapstore.cpp   快照内存环 + 单文件容器
    exports.cpp importfix.cpp pedump.cpp
  host/                内置 DLL 宿主 stub + 资源脚本
  util/                JSON 构造/解析、字符串、version.h（版本唯一来源）
tests/                 测试目标（x64/x86 DLL 与 EXE）、反检测探针、回归脚本（*.ajs）
third_party/zydis/     vendored Zydis
```

## 3. 架构分层

**JSON 优先**：`output` 层定义信封（`ok/cmd/data/error/session`），`cmd` 层只产出
`CmdResult`，`engine` 层完全不知道输出格式——同一引擎可同时服务 CLI 与 MCP。

```
main / mcp_server
      │  dispatch(Engine&, CliConfig&, line)
      ▼
   cmd 层（解析、参数校验、Json 组装）
      │
      ▼
   engine 层（事件循环、状态）── util/output（信封、数值编码）
```

- **多进程**：`DEBUG_PROCESS` 跟子进程；`ProcessInfo` 按 pid 组织，`current_pid_`
  随事件切换；`--no-children` 用 `DEBUG_ONLY_THIS_PROCESS`。`conhost.exe` 因继承调试端口
  也会被跟随，但标记 `is_system`：不进 `current`、不加载符号、不布断点、不参与 hide，
  其异常事件也不会被误判成目标断点。
- **会话生命周期**：最后一个非系统目标退出时 `reset_session()` 统一清理进程/线程句柄、
  每进程断点状态、hider、符号会话、快照和全局单步状态，并 `ContinueDebugEvent` 掉
  `EXIT_PROCESS`；`active()` 与 `launch()` 使用同一判据，避免“kill 报 no_target、
  restart 报 already active”的死锁。
- **WOW64**：调试器恒为 64 位；x86 目标经 `Wow64Get/SetThreadContext`，寄存器归一化为
  `CpuState`（`is32` 标志决定语义），反汇编/栈回溯按机器类型切换。
- **执行控制**：单步用 TF；软件断点命中后"还原字节→重定位 RIP→单步→重插桩"；
  执行型硬件断点是 fault 语义，继续/单步时先清 DR7 对应 enable 位再 TF 越过；
  `pause` 通过 `DebugBreakProcess` 注入断点（hide 清掉 `PEB.BeingDebugged` 时会临时置位），
  `continue <timeout>` 的超时按整段墙钟计算；`stepuntil/rununtil/autostep` 期间暂停自动快照。
- **表达式求值**：`expr.cpp` 递归下降 + `EvalContext` 回调（寄存器/读指针/名字解析），
  名字解析顺序：用户标签 → `$entry/$ra` → `module+off` → PDB 符号。

## 4. 关键设计决策（含实测依据）

### 4.1 固定基址：改名交换，而非打补丁副本或进程镂空

内核在 CreateProcess 建映像节时读 `DYNAMIC_BASE` 决定重定位，因此"关闭 ASLR"本质是
让**内核在映射时读到清掉标志的头部**。三条路的实测结论：

| 路线 | 结论 |
|---|---|
| 打补丁的副本（`.aidbg-fixbase`） | 可行但**过不了自校验**：目标哈希自己的文件会发现差异（被否） |
| 映射后重映像（TitanEngine 镂空同类） | **死锁内核**：CREATE_PROCESS 事件挂着时任何映像视图操作都不返回（进程不可杀）；`DEBUG_PROCESS\|CREATE_SUSPENDED` 甚至不投递事件 |
| **改名交换**（现方案） | 原件字节零修改，实测自校验 PASS |

改名交换流程（`TransientPePatch`，engine.cpp）：

1. 原件整体改名 `<目标>.aidbg-orig`（字节不动）
2. 副本就位并只改副本的 `DllCharacteristics`（清 `DYNAMIC_BASE|HIGH_ENTROPY_VA`）
3. CreateProcess：加载器自己按 ImageBase 映像
4. 补丁版改名 `<目标>.aidbg-patched-<pid>-<tick>`、原件改名回原位（**目标被调试事件门控，
   一行未跑**）

要点：Windows **拒绝写/替换/删除运行中映像的文件**，但**允许纯改名**——交换全程只用
MoveFileEx(0)。暂存名每次唯一，避免“上一次的补丁映像仍被映射 → 改名 / 替换失败
（win32 error 183）→ 用户文件残留为补丁版”。崩溃恢复：启动时发现 `.aidbg-orig` 即优先
还原；`.aidbg-patched-*` 是运行中映像（删不掉），下次启动 `cleanup_staged_files()` 自动
清理。系统文件（`%SystemRoot%`）从不参与交换；交换失败**回退 ASLR 并提示**而非报错。

### 4.2 反反调试：L1 补丁 + L2 虚拟化（不注入代码）

- **L1**（调试器侧写内存）：`PEB.BeingDebugged`、`NtGlobalFlag &= ~0x70`、堆
  `Flags/ForceFlags`（掩码与 ScyllaHide PebHider 一致）、StartupInfo 清洗 +
  `IMAGE_KEY_MISSING`、`KUSER_SHARED_DATA.KdDebuggerEnabled`。WOW64 目标补**两套 PEB**
  （32 位 + 64 位，`ProcessWow64Information` 取 PEB32）。
- **L2**（ntdll 导出布 INT3，调试器代答）：语义逐条对照 ScyllaHide HookedFunctions
  （如 ProcessDebugObjectHandle → `STATUS_PORT_NOT_SET`、DebugPort → 0、
  ThreadHideFromDebugger → 吞掉、NtClose 非法句柄 → `STATUS_INVALID_HANDLE` 不抛异常）。
  无法代答的调用 **unplant + TF 单步 + 重植**，在目标自己的上下文里回放原指令。
- **转发查询的自引用指针**（SystemProcessInformation 等 UNICODE_STRING.Buffer 指向
  调试器缓冲）必须重定位到目标缓冲，否则目标解引用野指针崩溃——NtQueryObject 类型表
  已做指针重写；其余含指针的类一律透传（宁可不隐藏，不破坏结构）。
- **WOW64 陷阱**：钩子调用约定随**所在模块**的位数走（ntdll32/ntdll64 各自布点）；
  跨位数转发 PBI 会把 64 位布局塞给 32 位调用方（目标必崩），x86 的 PBI 由调试器手工合成。
- 用户断点优先于隐藏钩子（同地址时）；hider 布点时跳过已被用户断点占用的地址；
  `hide off`/`detach` 时若字节仍被用户断点使用，则把真实原字节交接给 `BpPlant` 而不写回。
  命中透传按线程记账（`std::map<tid, PassThrough>`）；detach/退出必还原 INT3，写失败时
  保留真实 planted 状态而不是假装已拔除。
- **x64 CONTEXT 偏移**：`ContextFlags` 在 `+0x30`（`+0` 是 `P1Home`）。`NtGetContextThread`
  只回写调用方请求的字段组，debug 寄存器组清零；`NtSetContextThread` 在 `+0x30` 清
  `CONTEXT_DEBUG_REGISTERS` 位。`NtCurrentThread` 伪句柄是 `-2`，不是 `-1`。
- `NtQueryObject(ObjectNameInformation)` 的 `UNICODE_STRING.Buffer` 也要重定位到目标
  缓冲；未知布局的类回退真实调用，绝不把调试器地址交给目标。
- **pause 与 hide 的冲突**：`DebugBreakProcess` 的远程线程会检查 `PEB.BeingDebugged`，
  hide 把它清零后线程会直接退出而不触发 INT3。`Engine::pause()` 在注入期间临时置 1，
  收到停住事件后恢复 0。

### 4.3 快照：链式差分 + 追加式容器

- 只有首份全量，其余 4KB 页粒度脏页差分；MS Compression（cabinet.dll）压缩；
  全零页免费。8 份/256MB 上限，丢最旧时合并进下一份保链完整。
- `snapstore` 单文件 = 64 字节头 + 追加记录（自述长度 + prev 链 + 寄存器 + 压缩负载），
  崩溃可扫描恢复；删除标记会写回记录头（`mark_deleted`），`compact` 回收。
  文件偏移统一用 `_fseeki64/_ftelli64`（`long` 在 MSVC x64 只有 32 位，>2GB 会截断）。
- **负载 CRC 校验**：读取时比对记录里的 `payload_crc`，不匹配的记录直接跳过；
  解码前校验页数、地址、大小、数据长度和页保护，避免伪造 `.snap` 变成任意写/任意保护原语。
- **寄存器按字段序列化**（不 memcpy 结构体）：跨 ABI/跨版本安全，旧文件可加载
  （新增的 MXCSR/XMM 在旧记录里保持零）。恢复时刷指令缓存并重新武装软件/内存/硬件断点
  （原实现只重植软件/硬件断点，且用当前进程句柄去拔别的进程的断点）。

### 4.4 DLL 调试：内置宿主

`file <dll>` 检测 `IMAGE_FILE_DLL` → 从资源释放对应位数的 dllhost stub →
`stub.exe <dll> [export]`。自动断点：`bpload <dll>` + `dll+0x<入口RVA>` 待定断点。
DLL 的固定基址交换保持到 LOAD_DLL 映射完成才还原（`dll_patch_` 成员）。
约定：export 按 rundll32 签名调用；找不到 export 时 stub 退出码 3（不空转）。

## 5. 测试

- **测试目标**（`tests/`，均带 PDB）：`target.exe`（x64）、`target32.exe`、`spawner.exe`
  （子进程）、`types_test.exe`、`imports_test.exe`、`sample_dll(.32).dll`。
- **反检测探针**：`antidbg_probe(.32).exe` 跑 al-khaser 式 15 项检查；`selfcheck(.32).exe`
  运行时哈希自身文件（固定基址自校验）。
- **回归脚本**（`*.ajs`，`--script` 驱动）：`hide_std`（hide 矩阵）、`reg_basic`、
  `reg_children`、`reg_types`、`fixbase`、`dlltest` 等。判定标准：目标输出文件内容 +
  JSON 日志无意外 `"ok":false` + 进程正常退出。
- 修 bug 必须配可复现脚本；注意 `Start-Process` 不给含空格参数加引号（测试脚本里用
  内嵌引号或脚本文件传参）。
- **会话/MCP 回归关注点**（本轮修复对应）：
  1. `run → continue(exit) → restart` 必须成功，`session` 不能停留在 `active:true`；
  2. `continue <ms>` 超时后再次 `continue` 可继续等待，`pause` 能停在 `system_break`，
     且 hide 开/关都能工作；随后 `step`/`regs` 正常；
  3. MCP：先 `initialize`；含空格 `exe` 不被拆；数字地址/布尔参数可用；
     `breakpoint delete` 缺 `id` 报错；batch 返回 `-32600`；深嵌套 JSON 不崩溃；
  4. `ps` 中 `conhost.exe` 带 `system:true`，`hide hooks` 只含目标 pid；
  5. 伪造/篡改 CRC 的 `.snap` 被拒绝；正常 `snapshot save/restore/load` 仍通过；
  6. `q`/`exit` 退出；`eval nosuchsym` 的 `error.message` 非空；
  7. 硬件断点：多断点按 DR6 归属正确 id；从执行断点 `continue` 不重复命中同一条指令。

## 6. 发布流程

1. 版本号**只**改 `src/util/version.h`（`AIDBG_VERSION`），语义：修复递增第三位、
   新功能递增中间位；README 版本历史表加一行。
2. `build.bat Release` → 回归 → `git commit` → `git push`（远端有他人提交时 `pull --rebase`
   合并后再推，不覆盖）。
3. GitHub Release：tag `v<版本>`，标题 `aidbg <版本>`，正文写变更，附件 `build\aidbg.exe`。
   **每个版本独立发布，不复用旧 tag/资产**。

> [!WARNING]
> Release 文案用单引号 here-string 生成：PowerShell 双引号里反引号是转义符，会把
> Markdown 代码标记（`` `code` ``）吃掉，曾把 `bpcmd` 显示成 `pcmd`。

## 7. 实现笔记 / 踩坑清单

- `NtQueryInformationProcess(ThreadBasicInformation/ProcessBasicInformation)` 缓冲区
  **必须恰好 48 字节**（x64），更大会返回垃圾指针。
- x64 PEB：`NumberOfHeaps` 在 `0x0E8`（`0x0EC` 是 MaximumNumberOfHeaps）、
  `OSBuildNumber` 在 `0x120`；x86 对应 `0x088`/`0x0AC`。均经本机实测核对。
- 映射后 PE 头的 `ImageBase` 被 loader 改写为实际加载地址——`image_base` 必须读**文件**。
- toolhelp 堆快照（`TH32CS_SNAPHEAPLIST`）在被调试进程上会报 CRC 错误——走 PEB
  `ProcessHeaps`。
- 句柄枚举先按类型过滤再截断（顺序反了会漏匹配项）。
- `replace_all` 替换 `process_` 曾误伤 `process_event`/`process_count`——替换前先确认唯一性。
- WOW64 调试：取 32 位 PEB 用 `ProcessWow64Information`；`GetThreadContext`/`Wow64Get...`
  的位数必须与目标线程模式一致。
- 旧版"打补丁副本"方案因文件自校验问题废除；"映射后重映像"会死锁内核（见 4.1）。
- `WaitForDebugEvent` 的超时是**每次调用**的，不是整段等待；hide 钩子事件会不断返回并
  重置计时。超时必须自己做 deadline（`GetTickCount64`），否则 `continue <ms>` 在 hook
  繁忙的目标上永远不超时。
- `Json::u` 不能自动把 >2^53 转成 hex 字符串：JSON-RPC 的 `id` 和 `value_dec` 会因此
  变成 `"0x..."`，客户端无法关联。地址要精确就用 `set_hex`。
- MCP 工具参数不要拼成命令行再 `split_ws`：含空格的路径会被拆成“exe + args”。
  结构化参数直接写 `cfg.exe/cfg.args`。
- `read_memory` 的布尔返回值表示“至少读到一个字节”；需要完整读取的调用方必须查
  `got == n` 或用 `read_memory_exact()`，否则会用未初始化栈数据解析 PE 头。
- x64 `CONTEXT.ContextFlags` 在 `+0x30`；`GetThreadContext(GetCurrentThread())` 的
  伪句柄是 `-2`（`NtCurrentThread`），不是 `-1`。
- `DebugBreakProcess` 依赖 `PEB.BeingDebugged`（`DbgUiRemoteBreakin` 的判断）；
  hide 清零后注入线程会直接退出，pause 必须临时置位。
- 执行型硬件断点是 fault 语义（异常时 RIP 仍在指令上）；继续前要临时清 DR7 enable 位
  并 TF 单步，否则会无限重复命中。读/写型是 trap 语义，不需要。
- `conhost.exe` 会继承 `DEBUG_PROCESS` 的调试端口；不区分系统进程会导致 `current` 被抢、
  hide 往 conhost 的 ntdll 布 INT3、以及系统 DLL 同址导致的断点误归属。

---

**文档导航** [README](README.md) | [Manual](Manual.md) | [dev](dev.md) ·
[English](dev.en.md)
