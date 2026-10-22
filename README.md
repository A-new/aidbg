# aidbg — 面向 AI 的 Windows x86/x64 命令行调试器

`aidbg` 是一个为 **AI 辅助逆向分析** 设计的命令行调试器。它的核心目标不是人类交互体验，而是
**让程序（AI agent）能可靠地驱动调试会话并解析结果**：

- 每条命令可输出 **一行 JSON**（JSONL），字段稳定、可直接解析
- 支持 **批处理**（`-c` 连续命令）与 **脚本文件**（`--script`）
- **同一个 exe 自动识别并调试 x86 与 x64 目标**（WOW64），无需换工具
- 所有地址/64 位值以 **十六进制字符串** 返回，避免 JSON 数字精度丢失
- 输出可控（`max=N`、条目上限），不会撑爆上下文窗口
- 错误结构化返回，便于 agent 判断重试或换策略

技术栈：C++20 / MSVC、Zydis 4.1.1（反汇编，与 x64dbg 同款）、DbgHelp（PDB 符号）。
架构取自本目录多个开源调试器：x64dbg 的命令层与引擎解耦、raddebugger 的模块化引擎、
GDB 的请求-响应模型、Z0BDbgCli 的条件断点与异常策略、Nanomite 的状态视图完备性。

---

## 1. 快速开始

```bat
:: 构建（需要 VS 18 / MSVC，脚本会自动调用 vcvars64）
build.bat Release

:: 产物
build\aidbg.exe
```

构建配置：`/MT` 静态链接 C++ 标准库 + **VC-LTL**（`D:\vc\VC-LTL-Binary`，ucrt 模式）把 C 运行时
重定向到系统 `ucrtbase.dll`。若 VC-LTL 不存在，`CMakeLists.txt` 会自动退回纯静态 CRT（`/MT`），
两者都能达到"零 VC 运行时依赖"的效果，区别只是体积与 CRT 更新方式。

产物只依赖系统自带的 `KERNEL32.dll`、`dbghelp.dll`、`ucrtbase.dll`，
**不需要 Visual C++ Redistributable**（无 `MSVCP140.dll` / `VCRUNTIME140.dll` / `api-ms-win-crt-*`），
拷贝到 Windows 10+ 的机器上即可直接运行。

一次典型的 AI 调用（每条命令输出一行 JSON）：

```bat
aidbg --json ^
  -c "file tests\target.exe" ^
  -c "run" ^
  -c "break accumulate" ^
  -c "continue" ^
  -c "regs" ^
  -c "disasm 6" ^
  -c "stack 5"
```

脚本模式（命令一行一条，`#` 开头为注释）：

```bat
aidbg --script analysis.txt --json > result.jsonl
```

交互模式（人类使用）：直接运行 `aidbg.exe`，`help` 查看命令，`quit` 退出。

### 1.1 作为 MCP 服务器使用

```bat
aidbg --mcp
```

此时 `aidbg` 通过 **stdio 上的换行分隔 JSON-RPC 2.0**（MCP 标准 stdio transport）提供工具，
直到 stdin 关闭才退出。**调试会话在整个连接期间保持**：一次 `aidbg_session(action=run)` 启动的目标，
后续任何 tool call 都还在同一个会话里。

客户端配置示例：

```json
{
  "mcpServers": {
    "aidbg": {
      "command": "D:\\crack\\debug\\code\\aidbg\\build\\aidbg.exe",
      "args": ["--mcp"]
    }
  }
}
```

暴露 11 个工具，全部返回与命令行 **完全相同** 的 JSON 信封（见 §2）：

| 工具 | 对应命令 | 用途 |
|---|---|---|
| `aidbg_session` | `file` / `run` / `attach` / `detach` / `kill` / `restart` / `info` | 会话管理 |
| `aidbg_execute` | `continue` / `step` / `next` / `finish` / `until` / `stepuntil` / `rununtil` / `autostep` | 执行控制与追踪（`continue` 可带 `timeout_ms`） |
| `aidbg_breakpoint` | `break` / `hbreak` / `mbreak` / `cond` / `bl` / `be` / `bd` / `bc` | 三类断点与条件 |
| `aidbg_registers` | `regs` / `setreg` | 寄存器读写 |
| `aidbg_memory` | `read` / `mem` / `write` / `search` / `regions` / `alloc` / `free` / `protect` | 内存 |
| `aidbg_disasm` | `disasm` | 反汇编 |
| `aidbg_cfg` | `flow` | 函数控制流图（基本块 + 边） |
| `aidbg_stack` | `stack` | 调用栈 |
| `aidbg_modules` | `modules` / `threads` / `thread` / `symbols` | 模块、线程、符号 |
| `aidbg_eval` | `eval` | 表达式求值 |
| `aidbg_exceptions` | `exlist` / `exset` / `exdel` / `exall` | 异常策略 |
| `aidbg_snapshot` | `snapshot` / `stepback` | 快照保存/恢复，回退执行 |
| `aidbg_command` | 任意命令 | 原样透传，兜底所有未覆盖命令 |

协议行为：

- 成功/失败都通过 `result.content[0].text` 里的 JSON 信封表达，失败时 `isError: true`
- 命令级错误（如未知寄存器）→ 信封 `ok:false` + `error.code`
- 协议级错误 → JSON-RPC `error`：`-32601`（未知方法）、`-32602`（未知工具）、`-32700`（解析失败）
- 通知（无 `id`）不返回响应；stdout 只走协议，调试器自身输出不写 stdout

---

## 2. 输出契约（AI 必读）

### 2.1 JSON 信封

`--json` 下 **每条命令恰好输出一行** JSON：

```json
{"ok":true,"cmd":"regs","data":{...},"session":{...}}
{"ok":false,"cmd":"mem","error":{"code":"read_failed","message":"..."},"data":{},"session":{...}}
```

| 字段 | 说明 |
|---|---|
| `ok` | 命令是否成功 |
| `cmd` | 规范命令名（别名已归一化，如 `b` → `break`） |
| `data` | 成功时的结构化结果 |
| `error` | 失败时的 `{code, message}` |
| `session` | 会话快照，**每条响应都带**，便于跟踪状态 |

`session` 字段：

```json
{"active":true,"pid":123,"tid":456,"state":"paused",
 "stop_reason":"breakpoint","rip":"0x7ff6...","arch":"x64",
 "detail":"breakpoint 2 hit (accumulate)"}
```

- `state`: `idle`（无目标）/ `paused`（已停住，可读写状态）/ `running` / `exited`
- `arch`: 目标架构 `x86` 或 `x64`，**自动识别**，决定寄存器名与反汇编模式
- `stop_reason`: `entry` / `breakpoint` / `step` / `exception` / `memory_breakpoint` /
  `system_break` / `exit` / `timeout`

异步事件（调试字符串等）单独一行：`{"kind":"event","event":"debug_string","text":"..."}`

### 2.2 数值编码

| 类型 | 编码 | 示例 |
|---|---|---|
| 地址 / 64 位寄存器 | **十六进制字符串** | `"0x7ff674a47220"` |
| 小整数（大小、计数、行号） | JSON 数字 | `64`, `5` |
| 字节串 | 空格分隔大写十六进制 | `"48 8B 5C 24 08"` |

> 64 位值一律用字符串，因为 JSON number 只有 2^53 的安全整数范围。

### 2.3 退出码

`0` 全部成功；`1` 有命令失败；`2` 参数错误。批处理结束后会自动 `detach`，不会留下挂起的调试会话。

---

## 3. 地址与表达式

所有接受地址的地方都接受表达式：

| 形式 | 示例 | 含义 |
|---|---|---|
| 十六进制 | `0x7ff674a47220` | 字面量 |
| 十进制 | `1234` / `0n1234` | 字面量 |
| 寄存器 | `rax`, `rsp`, `rip`, `eax`, `al`, `ah` | 当前线程寄存器；x86 目标用 `eax`…`edi`/`eip`（`rax` 等 64 位名在 x86 下等价于低 32 位） |
| 符号 | `main`, `kernel32!CreateFileW` | PDB/导出符号 |
| 模块相对 | `target.exe+0x7220` | 模块基址 + 偏移 |
| 符号相对 | `main+0x10`, `accumulate+4` | 符号地址 + 偏移 |
| 内置 | `$entry`, `$ra` | 入口点 / 返回地址 |
| 解引用 | `[rsp]`, `[rax+0x10]` | 读 8 字节指针 |
| 运算 | `rax+8`, `[rbp-0x20]&0xff`, `x<<2` | `+ - * / & \| ^ ~ << >>` |
| 比较/逻辑 | `rcx == 14`, `rax && [rsp] > 0x1000` | `== != < <= > >= && \|\|` |

比较与逻辑运算返回 `1`/`0`，专供 **条件断点** 使用。

---

## 4. 命令参考

### 4.1 会话

| 命令 | 说明 |
|---|---|
| `file <path> [args...]` | 设置待调试程序与参数 |
| `run [args...]` | 启动并停在 **入口点**（自动跳过 ntdll 加载器断点） |
| `attach <pid>` | 附加到已运行进程，停在系统断点 |
| `detach` / `kill` | 干净分离 / 终止目标 |
| `restart` | 结束并用相同参数重新启动 |
| `aslr [on\|off]` | **固定加载基址**（默认关 = 固定），让动态地址与静态反汇编一致 |
| `processes\|ps` | 列出本次调试会话中的**所有进程**（含子进程） |
| `process\|proc <pid>` | 切换当前进程（后续命令作用于它） |
| `info` / `version` | 会话状态 / 版本 |
| `help` | 命令列表（`--json` 下返回机器可读目录） |

**子进程默认会被调试**（`DEBUG_PROCESS`）：目标启动的任何进程都会进入同一个会话，
可以像主进程一样设断点、读寄存器、看调用栈。用 `--no-children` 关闭（退回单进程模式）。
每个进程的架构独立识别，所以**一个会话里可以同时有 x64 和 x86 进程**。

### 固定基址（动静态地址对齐）

默认**关闭 ASLR**，目标按 PE 头的 `ImageBase` 加载，这样动态地址与 IDA / Ghidra
等静态反汇编工具里的地址完全一致：

| 目标 | 基址 | 入口点 |
|---|---|---|
| x64 | `0x140000000` | `0x140002306` |
| x86 | `0x400000` | `0x4025cc` |

`modules` 现在同时给出三个量，方便随时核对：

```
base             image_base       slide             name        path
0x7ff742810000   0x140000000      0x7ff602810000    target.exe  ...   ← ASLR on
0x140000000      0x140000000      0                 target.exe  ...   ← ASLR off
```

- `base`：实际加载地址
- `image_base`：PE 头里的 `ImageBase`，**也就是静态反汇编工具使用的基址**
- `slide`：两者之差（重定位偏移）。固定基址下为 `0`；开启 ASLR 时可用于手动换算
  静态地址 → 运行时地址

> 注意 `image_base` 必须从**文件**读取。Windows loader 会把已映射 PE 头中的 `ImageBase`
> 字段改写成实际加载地址，所以读内存里的 PE 头永远只能得到运行时基址——这点很容易踩坑。

实现细节（重要）：**原始文件绝不会被修改**。决定是否重定位的是 PE 头里的
`DYNAMIC_BASE` 标志，进程创建缓解策略无法覆盖它；而映像一旦被映射，Windows 就拒绝
再写该文件（`ERROR_SHARING_VIOLATION`），所以"打补丁后还原"这条路走不通。因此采用
**打补丁的副本**：复制到同级隐藏目录 `.aidbg-fixbase\`（保持相同文件名，模块名不变），
清掉副本的 `DYNAMIC_BASE` 标志后启动，会话结束时删除。目录不可写时退回 `%TEMP%`。

需要观察真实 ASLR 行为时用 `aslr on`（或 `--aslr`），此时 `slide` 会显示实际偏移。

<details>
<summary>为什么不用 x64dbg / TitanEngine 的做法</summary>

x64dbg 的 "Disable ASLR" 走 TitanEngine 的 `UE_ENGINE_DISABLE_ASLR`，底层是
`HollowProcessWithoutASLR`：**进程镂空**（create-suspended → 卸载随机映像 → 重映射到
首选基址 → 重新 attach）。这条路在实践中被公认为不可靠——第三方文档明确记录：

> *"ASLR disabling is unreliable (TitanEngine engine limitation) ... In this build that
> path is unreliable and often fails with `InitDebugW failed to create the target process`."*
> *"ASLR 开关无论 on/off 基址不变"，即该特性从未真正生效。*

进程镂空需要手工处理重定位、导入表、TLS、Load Config 等，任何一个环节出错都会导致
进程起不来。相比之下，清 `DYNAMIC_BASE` 让**加载器自己**按首选基址加载，不涉及任何
手工映射，实测 100% 可靠，且不触碰用户文件。
</details>

`session.processes` 字段给出当前会话的进程数（>1 时出现）。子进程自己的加载器断点
（ntdll / WOW64 层）会自动跳过，只有你设的断点才会停。

### 4.2 执行控制

| 命令 | 说明 |
|---|---|
| `continue\|c\|g [timeout_ms]` | 继续执行；可设超时（超时返回 `timeout` 而非挂死） |
| `step\|si [count]` | 单步（步入） |
| `next\|n\|so [count]` | 单步（步过 `call`/`rep`/`loop`） |
| `finish\|gu` | 执行到当前函数返回 |
| `until <addr\|expr>` | 执行到指定地址 |
| `stepuntil\|tu <条件> [max=N]` | **单步直到表达式为真**，每步求值一次 |
| `rununtil\|ru <条件> [max=N]` | **继续执行直到表达式为真**，每次停住时求值 |
| `autostep\|astep <count> [delay_ms]` | 连续单步并**记录执行轨迹**（每条指令的地址/字节/文本） |

追踪命令对 AI 探查特别有用：

```
break accumulate
continue
stepuntil eax == 3 max=200        # 一直单步，直到 eax 变成 3
  → condition 'eax == 3' true after 23 step(s)

rununtil ecx == 14 max=20         # 一直跑，直到 ecx 变成 14
  → condition 'ecx == 14' true after 4 stop(s)

autostep 14                       # 记录接下来 14 条实际执行的指令
  [   0] 0x...220  89 4C 24 08    mov [rsp+0x08], ecx
  [   1] 0x...224  48 83 EC 18    sub rsp, 0x18
  ...
```

条件是任意表达式（比较、逻辑、`[addr]` 解引用、寄存器、符号都行）。`stepuntil` 逐步求值，
`rununtil` 只在停住时求值（配合断点用）。`max=N` 是步数/停住次数上限，超了报
`condition_not_met` 而不是无限跑。

注意：`stepuntil`/`rununtil`/`autostep` 期间**自动快照是关闭的**（否则一万步会产生一万份
10MB 快照），结束后恢复正常。

### 4.3 断点

| 命令 | 说明 |
|---|---|
| `break\|b <addr\|symbol> [condition]` | 软件断点（INT3） |
| `hbreak <addr> [r\|w\|x] [size]` | 硬件断点（DR0-DR3，最多 4 个；size = 1/2/4/8） |
| `mbreak <addr> <size> [r\|w\|x]` | 内存断点（PAGE_GUARD，任意大小） |
| `cond <id> <expression>` | 设置条件；条件为 0 时自动继续 |
| `bpcmd <id> [command\|-]` | 命中动作：每次命中先执行命令（如 `eval rax` / `regs`），再按条件决定停/走 |
| `bpload [pattern\|del <pattern>\|clear]` | 模块加载断点：匹配的 DLL 加载时停下（`bpload dbghelp.dll`，支持 `*` 通配） |
| `bl` / `be <id>` / `bd <id>` / `bc <id\|*>` | 列表 / 启用 / 禁用 / 删除 |

**断点可以在目标启动前设置**，这是推荐工作流：

```
file sample.exe
break main              # 此时还没启动，断点为 pending
hbreak some_var w 4
run                     # 启动后自动解析符号并植入全部断点
continue                # 命中 main
```

`bl` 的 `resolved` 字段区分两者：`false` = 待定（符号还没解析出来），`true` = 已解析。
待定断点在模块加载后自动解析并植入，无需手动干预。

`bl` 的 `data.breakpoints[]` 每项含 `id, kind, address, symbol, size, access, enabled, hit_count, condition, command, resolved`。

### 4.4 状态读写

| 命令 | 说明 |
|---|---|
| `regs [name...]` | 寄存器（无参数返回全部 + 标志位 + SSE）；按目标架构输出 x64（`rax`…`r15`）或 x86（`eax`…`edi`）寄存器组，以及 `mxcsr` 与 `xmm0`-`xmm15`（x86 为 `xmm0`-`xmm7`） |
| `setreg <reg> <value>` | 写寄存器；`setreg xmm3 <1..32 hex>` 写完整 128 位（字节序与 `regs xmm3` 显示一致） |
| `mem <addr> [size]` | 十六进制 dump（默认 64 字节，上限 4096） |
| `read <addr> <size>` | 读字节（上限 65536） |
| `write <addr> <hexbytes>` | 写字节，如 `write 0x1000 90 90` 或 `write 0x1000 488B??90` |
| `search <start> <end> <pattern> [max=N]` | 字节搜索，`??` 为通配符 |
| `regions [start] [end]` | 内存区域（默认隐藏 free 区域） |
| `alloc <size>` / `free <addr>` / `protect <addr> <size> <r\|w\|x>` | 内存管理 |

> **搜索示例**：`search target.exe+0x0 target.exe+0xba100 61 69 64 62 67 max=16`
> 也可用紧凑写法 `488B??90`。`max=N` 必须显式写成 `max=数字`，以免与十六进制字节混淆。

### 4.5 分析

| 命令 | 说明 |
|---|---|
| `disasm\|u [addr] [count]` | 反汇编（默认从 RIP 起 8 条）；含字节、符号注释、跳转目标 |
| `flow\|cfg [addr] [max_blocks]` | **控制流图**：函数的基本块与块间边（fallthrough / branch / indirect） |
| `modules` | 已加载模块（基址、大小、名称、完整路径） |
| `threads` / `thread <tid>` | 线程列表 / 切换当前线程 |
| `stack\|bt [max]` | 调用栈（含符号、模块偏移、**源文件:行号**） |
| `teb [tid]` | **线程环境块**：栈范围、PEB 指针、LastError、ClientId |
| `peb` | **进程环境块**：BeingDebugged、ImageBaseAddress、NtGlobalFlag、堆指针 |
| `heap [max]` | **枚举堆**（读 PEB 的 ProcessHeaps 数组） |
| `handles [type] [max]` | **枚举句柄**：类型、访问掩码、对象名 |
| `symbols [mask] [max]` | 枚举符号，如 `symbols CreateFile* 20` |
| `eval <expression>` | 求值，并标注所属模块与符号 |
| `exports [module] [mask] [max]` | **解析模块导出表**（直接读目标内存里的 PE 导出目录） |
| `imports <addr> [count]` | **把一段指针解析成 `module!function`**，即 IAT 分析 |
| `iat scan [start end]` | **自动找导入表**：在内存中定位连续的导入指针段 |
| `iat map <addr> [count]` | 同 `imports`，但按模块分组输出（重建导入表用） |
| `iat refs <start> <end>` | **扫描代码里的导入引用**（`call/jmp/mov/lea [rip+x]`） |
| `iat fix <start> <end> [newva]` | **重建导入表并改写引用**——内存中自动修复 IAT |
| `iat trace <addr> [max_steps]` | **追踪一次导入调用**，看它最终落到哪个 API |
| `dump <file> [addr] [entry=<addr>] [compact] [keepbase]` | **把内存镜像导出为可加载的 PE 文件** |
| `ptype <type>` | **结构体/联合/枚举布局**：字段名、偏移、类型、大小 |
| `whatis <symbol\|expr>` | 查看符号或表达式的声明类型 |
| `print <expression>` | **带类型的求值**，支持 `.` / `->` / `[]` 成员访问，自动展开结构体字段 |

类型信息来自 PDB（DbgHelp），是 RadDbg `Types.cpp`/`Values.cpp` 那条路线的对应能力。

#### `teb` / `peb` / `heap` / `handles`：进程内部状态

Nanomite 那类"信息视图"。这几条直接读目标的内核结构，对反反调试和运行时分析很实用：

```
peb
  PEB 0x317000  (x64)
    BeingDebugged      1
    ImageBaseAddress   0x140000000
    NtGlobalFlag       0x70  [debugger flags set]     ← 附加调试器的痕迹
    ProcessHeap        0x510000
    [ok] ImageBaseAddress matches the main module base

teb
  TEB 0x318000  (x64)
    pid/tid     37356 / 29224
    stack base  0x160000
    stack limit 0x15c000
    last error  0

handles File 6
  0x58  File  0x100020  \Device\HarddiskVolume4\crack\debug\code
  0x60  File  0x12019F  \Device\ConDrv
```

`NtGlobalFlag` 里的 `0x70` 是附加调试器时的典型标志（尾部检查/释放检查/堆校验），
反反调试检测常查这个值；`BeingDebugged` 同理。`peb` 会**自校验** `ImageBaseAddress`
是否等于主模块基址，偏移写错会立刻暴露。

`heap` 走 PEB 的 `ProcessHeaps` 数组——toolhelp 的堆快照（`TH32CS_SNAPHEAPLIST`）在
被调试进程上会报 CRC 错误，PEB 方案既可靠又不受影响。`handles` 走系统句柄表
（`SystemExtendedHandleInformation`），按类型名过滤后再截断（先截断再过滤会漏掉匹配项）。

已知限制：x86 (WOW64) 目标的 `teb.peb` 与 `peb` 可能不一致——WOW64 线程同时有 32 位和
64 位两个 TEB，`NtQueryInformationThread` 返回的是哪一个取决于调用方位数。此时输出会
用 `[!]` 标出差异，核心字段（`ImageBaseAddress`/`BeingDebugged`/`NtGlobalFlag`）仍准确。典型用法：

```
ptype Node
  Node  (size 0x30 = 48 bytes)
  offset     type                     name
  +0x0        int                      value
  +0x4        Point                    pos
  +0x20       Node*                    next
  +0x28       double                   weight

print g_head.next->pos
  g_head.next->pos = Point   <Point> @ 0x7ff682c0d1f4
    +0x0      int      x       11 (0xb)
    +0x4      int      y       22 (0x16)
    +0x8      char[16] label   "second"
```

`print` 的表达式可以任意组合 `.`、`->`、`[下标]`，例如 `table[i].name`、`obj->next->next->value`。
数组会按可打印字符串或十六进制两种方式展示，整数同时给出十进制与十六进制。

`flow` 输出函数的控制流结构，用于快速看清分支逻辑：

```
accumulate [0x7ff674a47220 - 0x7ff674a4726f)  blocks=5 instructions=22
block 0  0x...220  [5 insn]  -> 0x...241 branch              # prologue + jmp
block 1  0x...239  [3 insn]  -> 0x...241 fallthrough          # i++
block 2  0x...241  [3 insn]  -> 0x...266 branch, 0x...24a fallthrough   # i < n
block 3  0x...24a  [8 insn]  -> 0x...239 branch               # 循环体，跳回 i++
block 4  0x...266  [3 insn]  -> (exit)  [exit]                # 返回
```

JSON 里每个块带完整指令列表和结构化边（`{"to":"0x...","type":"branch|fallthrough|indirect"}`），
`external: true` 表示跳到了函数外。函数边界取自符号表，无符号时会退化为"从当前位置扫到第一个 `ret`"。

`disasm` 传一个 **≤4096 的小整数** 时按条数处理（`disasm 6` = 6 条指令）；传地址表达式则按起始地址处理。

### 4.6 快照与回退执行

| 命令 | 说明 |
|---|---|
| `snapshot\|snap save [name]` | 保存完整进程状态（内存 + 寄存器） |
| `snapshot restore [name\|index]` | 恢复到某个保存点 |
| `snapshot list` | 列出快照（含自动捕获的） |
| `snapshot delete <name\|index>` / `snapshot clear` | 删除 / 全清 |
| `snapshot auto <on\|off>` | 开关"每次停住自动捕获"（默认开） |
| `snapshot file [path]` | 打开/创建**单文件快照库**（不带参数则查看当前） |
| `snapshot history` | 列出文件中的全部快照（含已不在内存里的） |
| `snapshot load <id>` | 从文件恢复某个快照（可跨内存环限制） |
| `snapshot compact` | 回收文件中已删除记录占用的空间 |
| `stepback\|sbk\|reverse [count]` | **回到较早的停住点**，可连续回退 |

这是 Z0BDbgCli `snapshot`/`stepback` 那条路线的对应能力。原理是把内存与寄存器整体
回写，属于可靠的"时间回溯"近似：

```
continue            → g_counter = 87
continue            → g_counter = 165
stepback 1          → g_counter = 87      ← 回到上一个停住点
stepback 1          → g_counter = 0       ← 继续往前
```

**每次停住会自动捕获一份快照**，所以 `stepback` 开箱即用，不需要手动 `save`。

### 存储：链式差分 + 压缩

快照采用**只有首个全量、其余只存差异**的结构（与 HDiffPatch 的思路一致，但用页粒度
脏页比较而非通用二进制 diff——捕获时目标是暂停的，必须快）：

| | raw | 压缩后 |
|---|---|---|
| auto-1 **full** | 9924 KB | 4178 KB |
| auto-2 **delta** | 12 KB | **1 KB** |
| auto-3 **delta** | 12 KB | **1 KB** |
| auto-4 **delta** | 12 KB | **1 KB** |
| auto-5 **delta** | 12 KB | **1 KB** |
| **合计（5 份）** | 9973 KB | **4184 KB** |

- **差分**：4KB 页粒度，只存与前一份不同的页。相邻停住点通常只有几页变化（局部变量、
  栈顶、少量堆），所以增量只有 1KB 左右。旧的全量方案同样 5 份要 49.6MB，**省 12 倍**；
  8 份的上限下约省 19 倍。
- **压缩**：Windows 自带的 MS Compression（`cabinet.dll`，XPRESS_HUFF 算法），无第三方
  依赖，全量快照约 2.4 倍压缩。
- **全零页继续免费**，两者叠加。

上限默认 8 份 / 256MB，超出自动丢最旧的，并把被丢弃的那份合并进下一份（保持链完整）。

### 单文件快照库

所有快照存在**一个容器文件**里，不会散落出一堆零散文件：

```
aidbg -c "snapshot file session.snap" -c "file a.exe" -c run ...
```

文件格式是自描述的追加式日志：一个 64 字节文件头 + 顺序追加的记录，每条记录带自己的
总长度、差分链引用（`prev`）、寄存器、名称和压缩后的页面负载。

| 场景 | 表现 |
|---|---|
| 单会话 5 次捕获 | 1 份 full(4178KB) + 4 份 delta(1KB) = **4.18 MB 一个文件** |
| 同样的 5 份散文件 | 5 个文件共 48.5 MB |

设计上几点值得注意：

- **追加式，不原地改写**。删除标记为 dead，`snapshot compact` 才真正回收空间。
- **崩溃可恢复**。每条记录自带长度，加载时直接扫描重建索引；文件头损坏或写入中断，
  已提交的快照都不会丢。
- **差分链不跨会话**。新进程内存布局不同，不能拿旧进程的页做差分，所以每个会话的第一份
  必然是全量（`history` 里 `kind=full`、`prev=-`）。`snapshot load` 也只会回溯到最近的
  full 记录，正好是会话边界。
- **id 跨会话连续**，不会与文件里已有的记录冲突。

注意两点：

- **只回滚内存和寄存器**。内核态对象（文件句柄、线程、套接字、已发出的系统调用）不会
  撤销，所以回退后继续运行可能与真实的历史不同——适合"看看刚才那个值是什么/再走一遍
  分支"，不适合精确的确定性重放。
- **恢复是破坏性的**：回到某个快照后，比它更新的快照会被丢弃（回到过去就意味着放弃
  未来），这样差分链才能保持正确。
- 只读共享页（如 `0x7FFE0000` 的 KUSER_SHARED_DATA）写不回去，会被自动跳过；
  这些页不承载调试目标的状态。

| 命令 | 说明 |
|---|---|
### 4.7 异常策略

| 命令 | 说明 |
|---|---|
| `exlist` | 显示策略（含各异常命中次数） |
| `exset <code> <break\|ignore\|pass>` | 设置单个异常码的行为 |
| `exdel <code>` | 删除规则 |
| `exall <on\|off>` | 全局忽略所有一次机会异常（单步噪音代码时用） |

异常码可写十六进制或别名：`av`(ACCESS_VIOLATION)、`bp`、`ss`、`guard`、`cpp`。

三种行为：

| 行为 | 一次机会异常 | 含义 |
|---|---|---|
| `break`（默认） | 停下并报告 | 让 AI 看到异常 |
| `ignore` | 不停，交给目标程序处理 | 程序自己会处理的异常 |
| `pass` | 不停，当作已处理吞掉 | 明确要屏蔽的信号（如 OutputDebugString） |

二次机会异常 **总是** 停下（通常是致命错误）。

### 4.8 反反调试（hide / detect）

| 命令 | 说明 |
|---|---|
| `detect` | 用常见反调试检测（al-khaser 清单）自查目标，报告哪些会命中 |
| `hide [status]` | 显示当前隐藏配置与已布钩子 |
| `hide on [profile]` / `hide off` | 开启/关闭隐藏（可同时指定 profile） |
| `hide profile <name>` | 切换配置档：`off` `basic` `standard` `aggressive` `vmp` `themida` `obsidium` |
| `hide set <key> <0\|1>` | 逐项开关（键名与 `scylla_hide.ini` 一致） |
| `hide apply` | 对所有存活进程重新应用补丁/钩子 |
| `hide hooks` | 列出钩子位点（地址/命中次数/是否在位） |
| `hide profiles` | 列出内置配置档及其开关组合 |
| `hide load <file>` / `hide save <file>` | 读写 ini（直接兼容 ScyllaHide 的 `scylla_hide.ini`） |

启动参数：`--hide <profile|off>`（默认 `standard`）。

**工作原理（两层，均不向目标注入代码）：**

1. **L1 内存补丁**（调试器侧写入，零副作用）：`PEB.BeingDebugged`、`NtGlobalFlag` 的
   0x70 调试位、堆 `Flags/ForceFlags` 的调试位、`RTL_USER_PROCESS_PARAMETERS`
   的启动信息泄漏、`KUSER_SHARED_DATA.KdDebuggerEnabled`。WOW64 目标会同时修补
   32 位与 64 位两套 PEB。
2. **L2 API 虚拟化**（在目标 ntdll 导出上布 INT3，由调试器代答）：
   `NtQueryInformationProcess`（DebugPort/DebugObjectHandle/DebugFlags/
   BreakOnTermination/HandleTracing）、`NtQuerySystemInformation`（内核调试器信息类）、
   `NtSetInformationThread`（吞掉 ThreadHideFromDebugger）、`NtSetInformationProcess`、
   `NtQueryObject`（隐藏 DebugObject 计数）、`NtClose`（非法句柄不再触发异常）、
   `NtYieldExecution`、`NtGet/SetContextThread`（隐藏调试寄存器）。无法代答的调用
   会在单步下回放原始指令（目标无感知）。

`detect` 的报告同时给出**真实内核状态**和**目标实际会读到的答案**（钩子生效时后者
已被伪装），并标注每个检测项由哪个开关修复。

**诚实的能力边界（重要）：**

- L2 的 INT3 留在目标 ntdll 里，**对 ntdll 代码完整性扫描可见**（`detect` 的
  `ntdll.integrity` 项会如实标注）。ScyllaHide 的跳板 hook 同样可被扫描到，这是
  用户态方案的共有限制。
- **直接 syscall**（绕过 ntdll 发 `syscall` 指令）不受 L2 影响；只清 PEB 的 L1 仍然有效。
- 计时类检测（RDTSC / GetTickCount 循环）、TrapFlag、int 2D、WriteWatch、PageGuard
  等需要在目标内执行代码的检测**未做规避**，`detect` 中标注为 skipped。
- 句柄表/进程列表过滤（SystemHandleInformation、SystemProcessInformation）**未实现**：
  结果缓冲含跨进程指针，转发过滤容易破坏结构，宁可透传。
- NtQueryObject 的 DebugObject 计数过滤在 WOW64 目标上**不生效**（结构布局随位数变化，
  32 位路径走透传）。
- 驱动级隐藏（HyperHide/TitanHide 路线）**不做**，aidbg 保持纯用户态单文件。
- `hide off`、`detach`、进程退出都会把 INT3 还原，不会在目标里留下断点字节。

### 4.9 用户笔记（label / comment）

| 命令 | 说明 |
|---|---|
| `label <addr> [name\|-]` | 设置/查看/删除标签；标签可在表达式中直接使用（`break my_loop`、`until decrypt`） |
| `comment <addr> [text\|-]` | 设置/查看/删除注释；`disasm` 输出会带上 |
| `notes [list\|save <file>\|load <file>\|clear]` | 列表 / 持久化到 JSON / 读回 / 清空 |

标签和注释**锚定在 模块+RVA**（借鉴 Syser 的符号/注释容器）：ASLR 滑动、目标重启后依然
有效。`notes save`/`load` 的 JSON 格式（`{"format":"aidbg-notes-1","notes":[{"module","rva",
"label","comment"}]}`）适合 AI 把一轮分析的结论带到下一轮会话：

```
label target.exe+0x2306 entry_point
comment target.exe+0x2306 program starts here
break entry_point
notes save session1.json
```

`disasm` 的每条指令会附带 `label`/`note` 字段（JSON）和 `; label: comment` 注释（文本）。

---

## 5. 典型 AI 工作流

### 5.1 摸清一个陌生二进制

```bat
aidbg --json ^
  -c "file sample.exe" ^
  -c "run" ^
  -c "modules" ^
  -c "disasm 16" ^
  -c "stack 8" ^
  -c "symbols main* 16"
```

### 5.2 先设断点再启动（推荐）

```bat
aidbg --json ^
  -c "file sample.exe" ^
  -c "break CreateFileW" ^
  -c "break main" ^
  -c "run" ^
  -c "continue" ^
  -c "regs" ^
  -c "stack 5"
```

### 5.3 追踪某个函数的调用

```bat
aidbg --json ^
  -c "file sample.exe" ^
  -c "run" ^
  -c "break CreateFileW" ^
  -c "continue" ^
  -c "regs rcx rdx r8 r9" ^
  -c "read rdx 64" ^
  -c "stack 6"
```

### 5.4 找到写某变量的位置

```bat
aidbg --json ^
  -c "file sample.exe" ^
  -c "run" ^
  -c "hbreak <var_addr> w 4" ^
  -c "continue" ^
  -c "disasm 4" ^
  -c "stack 4"
```

### 5.5 条件断点：只在特定参数时停下

```bat
aidbg --json ^
  -c "file sample.exe" ^
  -c "run" ^
  -c "break SomeFunc" ^
  -c "cond 1 rcx == 0x2a" ^
  -c "continue"
```

### 5.6 脱壳：定位并解析导入表

加密壳会在运行时解密代码并动态填充导入表，脱壳后需要修复 IAT 才能独立运行。
`aidbg` 可以在调试过程中**自动完成导入表的识别与解析**（相当于把 Scylla 的分析
那一步自动化）：

```
file packed.exe
run
until <OEP>              # 跑到壳解密完成后的原始入口点

iat scan                 # 自动在内存里找导入表
  0x1400b5000   0x2b8   87 slots   87 exports   3 modules   ← 目标自己的 IAT

imports 0x1400b5000 20   # 逐槽位解析
  0x1400b5000  0x7ffa4f153480  kernel32.dll!QueryPerformanceCounter
  0x1400b5008  0x7ffa4f152bb0  kernel32.dll!GetCurrentProcessId
  0x1400b5020  0x7ffa4ff3c980  ntdll.dll!RtlInitializeSListHead

iat map 0x1400b5000 87   # 按模块分组，直接可用于重建导入描述符
  kernel32.dll  (29 个)
    QueryPerformanceCounter, GetCurrentProcessId, ...
  ntdll.dll  (8 个)
    RtlInitializeSListHead, ...
```

实现要点：

- **导出表直接从目标内存解析**（PE 导出目录），不依赖符号文件，所以对第三方 DLL、
  加过壳的模块都有效
- **转发导出**能识别（`CreateFileMappingFromApp -> api-ms-win-core-memory-l1-1-1.*`）
- **导入跳转桩**会自动跟踪（`jmp [rip+x]` / `jmp rel32` 等），不会停在 stub 上
- **IAT 自动定位**按"连续指针段"扫描（与 Scylla 同思路），而不是整块内存区——
  真正的 IAT 往往只占 `.rdata` 的一小段，按整区统计会被稀释
- 解析不出来时退化为 `module+0xoff` 或最近导出 `name+0xdisp`，不会假装成功

#### `iat refs` / `iat fix`：内存中自动修复导入表

这对应 Wannabe Universal Import Fixer 的算法，解决 VMProtect/Themida 一类的场景：
壳解密后**导入引用散落在代码各处**，指向各自临时的槽位，而不是集中的导入表。

```
iat refs target.exe+0x7e00 target.exe+0x8000
  instruction        mnem   slot            api                module!function
  0x140007e92        call   0x1400b5018     0x7ffa4f160e70     kernel32.dll!GetSystemTimeAsFileTime
  0x140007ea2        call   0x1400b5010     0x7ffa4f148620     kernel32.dll!GetCurrentThreadId
  ...

iat fix target.exe+0x7e00 target.exe+0x8000
  import table written at 0x13fff0000
    unique imports: 4
    patched instructions: 8
```

`iat fix` 做三件事：

1. **去重**：把所有引用到的 API 汇总成一张连续表（8 条引用 → 4 个唯一 API）
2. **写表**：把真实 API 指针写进新表（`newva` 省略时自动在**代码 ±2GB 内**找空闲区，
   否则 RIP 相对位移放不下）
3. **改写位移**：把每条指令的 disp32 指向新槽位。重复引用复用同一槽位

验证方式：打补丁后程序仍正常退出（退出码 0），与未打补丁的对照一致——
说明改写后的指令通过新表正确调用了 API。

`iat refs` 只记录**指针落在已加载模块内**的引用（`lea`/`mov` 读普通数据会产生假阳性，
这与 wannabeuif 的过滤一致）。

#### `iat trace`：追踪动态解析的导入

VMProtect/Themida 一类的壳**不靠静态引用**调用 API——代码里是 `call [rsp+0x30]`
这类间接调用，目标地址运行时才算出来，反汇编里完全看不出指向哪个函数。这类只能**执行观察**：

```
iat trace 0x14000726b
  0x14000726b -> kernel32.dll!GetTickCount   (1 step(s))
```

`0x14000726b` 是一条 `call [rsp+0x30]`，静态分析无解；追踪器让它执行一步，
RIP 落到 `kernel32!GetTickCount` 的导出起点，就认出了真实 API。

原理：在调用点单步执行，每步检查 RIP 是否落在某个模块的**导出起点**上——
无论中间经过多少层哈希查表、多少次跳转，最终总要跳到真实 API。

两个细节：

- **追踪不污染现场**：追踪期间关闭自动快照（否则每步存 10MB），结束后用命名快照把
  内存与寄存器还原，追踪过程的副作用全部撤销。RIP 回到调用点，可以直接继续执行。
- **判定条件是"落在导出起点"**，所以普通的函数调用（如 `printf`）追踪下去会停在它
  调用的第一个 API 上，而不是调用点本身——对导入解析场景是对的，但要知道这个语义。

#### `dump`：导出内存镜像

脱壳的另一步——把运行时已解密的镜像写回成 PE 文件：

```
run
until <OEP>                 # 等壳解密完
dump unpacked.exe           # 导出内存镜像
dump unpacked.exe entry=<OEP>   # 同时把入口点改成 OEP
```

导出的文件是**可直接运行**的（实测导出后程序退出码与原始程序一致）。几个细节：

- **文件布局镜像内存布局**（`PointerToRawData = VirtualAddress`），所以壳新加的节、
  运行时变大的节都原样保留；`compact` 可改为紧凑布局
- **`ImageBase` 写成实际加载地址并清除 `DYNAMIC_BASE`**（`keepbase` 可关闭），这样
  导出文件在内存镜像原址加载，地址与调试时完全一致
- **节间自动补齐对齐**——`PointerToRawData` 是声明式偏移，顺序写入时若不补空隙，
  文件会比自己的节表声称的短，加载器直接拒绝
- 读不到的内存（守卫页等）以零填充，不会中断导出

典型脱壳流程串起来就是：

```
file packed.exe
run
until <OEP>
iat refs <code_start> <code_end>       # 看导入引用散落在哪
iat fix  <code_start> <code_end>       # 收拢成干净的导入表
dump unpacked.exe entry=<OEP>          # 导出
```

### 5.7 长时间运行的脚本

把命令写进 `analysis.txt`，用 `--script` 执行并落盘：

```bat
aidbg --script analysis.txt --json > result.jsonl
```

之后让 AI 读 `result.jsonl` 分析即可；每行是一条命令的完整结果。

---

## 6. 给 AI agent 的使用建议

1. **始终用 `--json`**，不要解析文本模式输出。
2. **每次响应都看 `session.state` 与 `stop_reason`**：只有 `state="paused"` 时才能读寄存器/内存。
3. **先看 `session.arch`**：`x86` 用 `eax`/`eip`/`esp`，`x64` 用 `rax`/`rip`/`rsp`。64 位寄存器名在 x86 目标下也能用（取低 32 位），但输出寄存器组以 `arch` 为准。
4. **不要假设地址固定**：开了 ASLR 后每次运行的模块基址都变，用 `modules` 拿基址，或直接用 `module+0xoff` / 符号。x86 目标地址通常在 32 位范围（如 `0x447190`）。
5. **控制输出量**：`mem` 默认 64 字节、`disasm` 默认 8 条、`search` 默认 64 个命中。需要更多时显式加大，但注意上下文预算。
6. **失败要读 `error.code`**：`not_paused` 表示需要先 `continue`/`step`；`read_failed` 常表示地址不可读（先用 `regions` 确认）。
7. **脚本跑完会自动 detach**，不会把目标进程挂住；但用交互/管道模式时记得 `detach` 或 `kill`。
8. **`continue` 建议带超时**（如 `continue 5000`），避免目标进入死循环时 agent 永久阻塞。

---

## 7. 已知限制（当前版本）

- 仅支持 **Windows 用户态** 调试：x64 与 WOW64 (x86) 目标均可，内核态、远程调试未实现
- `step`/`next` 不支持反向执行；`rep` 前缀指令按单步处理
- 符号依赖 DbgHelp，非 ASCII 路径的 PDB 可能解析失败
- 硬件断点最多 4 个；内存断点基于 PAGE_GUARD，会捕获整个区域的访问（按地址范围过滤）
- 条件断点每次命中都会求值，高频路径下会有开销
- 反反调试为用户态方案：L2 的 INT3 可被 ntdll 完整性扫描发现，直接 syscall 不受影响，
  计时类/驱动级检测未覆盖，详见 4.8 的"诚实的能力边界"
- Python 绑定尚未提供（命令行 + JSON 与 MCP 已覆盖同等能力）

### 关于 x86 / x64 自动识别

调试器本身始终是 64 位进程。对 WOW64 (x86) 目标，寄存器通过
`Wow64Get/SetThreadContext` 读写 32 位上下文，反汇编切到 Zydis 的
`LONG_COMPAT_32` 模式，调用栈用 `IMAGE_FILE_MACHINE_I386` 回溯，指针宽度为 4 字节。
`session.arch` 与 `regs`/`disasm` 的 `arch` 字段会告诉你是哪种目标，AI 可据此选择寄存器名。

---

## 8. 项目结构

```
aidbg/
  build.bat              构建脚本（自动调用 MSVC 环境）
  CMakeLists.txt
  src/
    main.cpp             CLI 入口：-c / --script / 交互 / --mcp 四种模式
    cmd/commands.cpp     命令注册、解析与分发（70 个命令（含子命令））
    mcp/mcp_server.cpp   MCP (Model Context Protocol) 服务器，11 个工具
    output/output.cpp    JSON/文本双格式输出层
    engine/
      engine.cpp         调试事件循环、进程/线程/模块管理、执行控制
      breakpoints.cpp    软件/硬件/内存断点 + 条件 + 命中命令
      memory.cpp         读写、搜索、区域、保护
      registers.cpp      寄存器表（GPR 8/16/32 位视图 + mxcsr/xmm）
      symbols.cpp        DbgHelp PDB 符号
      expr.cpp           表达式求值器
      exceptions.cpp     异常策略
      hide.cpp           反反调试（PEB 补丁 + ntdll API 虚拟化 + detect）
      notes.cpp          用户标签/注释（模块+RVA 锚定，JSON 持久化）
      disasm.cpp         Zydis 封装
    util/                JSON 构造/解析、字符串与模式解析
  third_party/zydis/     Zydis 4.1.1 + Zycore
  tests/                 测试目标程序（x64 的 target.exe 与 x86 的 target32.exe）与冒烟脚本
```
