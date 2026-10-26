# aidbg AI 使用手册（Manual）

<p align="center">
  <a href="README.md">中文</a> | <a href="README.en.md">English</a>
  　·　<a href="Manual.md">Manual</a> | <a href="dev.md">dev</a>
</p>

---

面向 AI agent / 脚本作者的完整使用手册。`aidbg` 的每条命令都可输出一行 JSON；
本文档定义输出契约、表达式语法、全部命令与推荐工作流。开发者请看 [dev.md](dev.md)。

---

## 1. 输出契约（必读）

### 1.1 JSON 信封

`--json` 下**每条命令恰好输出一行** JSON：

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
| `text` | 仅 MCP：命令没有结构化数据时（如 `help`）附带的文本结果 |

`session` 字段：

```json
{"active":true,"pid":123,"tid":456,"state":"paused",
 "stop_reason":"breakpoint","rip":"0x7ff6...","arch":"x64",
 "detail":"breakpoint 2 hit (accumulate)"}
```

- `state`: `idle`（无目标，含目标已退出）/ `paused`（已停住，可读写）/ `running`
- `arch`: 目标架构 `x86` 或 `x64`（**自动识别**，决定寄存器名与反汇编模式）
- `stop_reason`: `entry` / `breakpoint` / `step` / `exception` / `memory_breakpoint` /
  `system_break` / `module_load` / `exit` / `timeout`

异步事件（调试字符串、告警等）单独成行：`{"kind":"event","event":"debug_string","text":"..."}`。

### 1.2 数值编码

| 类型 | 编码 | 示例 |
|---|---|---|
| 地址 / 64 位寄存器 | **十六进制字符串** | `"0x7ff674a47220"` |
| 小整数（大小、计数、行号） | JSON 数字 | `64`, `5` |
| 字节串 | 空格分隔大写十六进制 | `"48 8B 5C 24 08"` |

> [!NOTE]
> 64 位值一律字符串：JSON number 的安全整数范围只有 2^53。

### 1.3 退出码与会话

`0` 全部成功；`1` 有命令失败；`2` 参数错误。批处理结束后自动 `detach`，不留挂起会话。
交互模式下 `quit` / `exit` / `q` 均可退出。

- **目标退出即会话结束**：最后一个被调试目标退出后，引擎清理进程/断点/符号/hide 状态，
  `session.state` 回到 `idle`；随后可直接 `run`/`restart` 开始新会话（不需要重启 aidbg）。
- 每条响应都带 `session` 信封；`active:false,state:idle` 表示当前没有可操作目标。

---

## 2. 地址与表达式

所有接受地址的地方都接受表达式：

| 形式 | 示例 | 含义 |
|---|---|---|
| 十六进制 | `0x7ff674a47220` | 字面量 |
| 十进制 | `1234` / `0n1234` | 字面量 |
| 寄存器 | `rax`, `rsp`, `rip`, `eax`, `al`, `xmm0` | 当前线程寄存器；x86 目标用 `eax`…`edi`/`eip`（`rax` 等 64 位名等价低 32 位） |
| 符号 | `main`, `kernel32!CreateFileW` | PDB/导出符号 |
| 标签 | `entry_point` | `label` 命令定义的用户标签 |
| 模块相对 | `target.exe+0x7220` | 模块基址 + 偏移 |
| 符号相对 | `main+0x10`, `accumulate+4` | 符号地址 + 偏移 |
| 内置 | `$entry`, `$ra` | 入口点 / 返回地址 |
| 解引用 | `[rsp]`, `[rax+0x10]` | 读指针宽度的值 |
| 运算 | `rax+8`, `[rbp-0x20]&0xff`, `x<<2` | `+ - * / & \| ^ ~ << >>` |
| 比较/逻辑 | `rcx == 14`, `rax && [rsp] > 0x1000` | `== != < <= > >= && \|\|` |

比较与逻辑返回 `1`/`0`，专供**条件断点**使用。`eval 2+2` 这类算术同样支持。

---

## 3. 命令参考

### 3.1 会话

| 命令 | 说明 |
|---|---|
| `file <exe> [args...]` \| `file <dll> [export]` | 设置目标：EXE+参数，或 DLL（内置宿主加载，`export` 为可选调用入口） |
| `run [args...]` | 启动并停在**入口点**（自动跳过 ntdll 加载器断点） |
| `attach <pid>` | 附加到已运行进程，停在系统断点 |
| `detach` / `kill` | 干净分离 / 终止目标 |
| `restart` | 结束并以相同参数重启 |
| `aslr [on\|off]` | 固定加载基址开关（默认关 = 固定基址） |
| `processes\|ps` / `process\|proc <pid>` | 列出/切换会话内所有进程（含子进程） |
| `info` / `version` / `help` | 会话状态 / 版本 / 命令目录（`--json` 下机器可读） |

- **子进程默认被调试**（`--no-children` 关闭）；每个进程独立识别架构，可混合 x86/x64。
- `conhost.exe` 会因继承调试端口出现在会话中，但被标记为系统进程：`ps` 里带
  `"system":true`，不会成为 `current`，不参与 hide、符号加载和断点植入。
- 命令行启动参数：`--exe` `--args` `--cwd` `--console` `--aslr` `--no-children`
  `--hide <profile|off>` `--json` `--pretty` `-c <cmd>` `--script <file>` `--mcp`
  `--port <n>` `--bind <addr>` `--token <secret>`（后三个配合 `--mcp` 提供 HTTP/SSE
  远程传输，见 6.1）。

### 3.2 固定基址（默认开启）

目标按 PE 头的 `ImageBase` 加载，动态地址与静态反汇编**完全一致**（x64: `0x140000000`、
x86: `0x400000`）。`modules` 给出 `base`（实际基址）/ `image_base`（PE 头基址）/
`slide`（重定位偏移，固定基址下为 0）。

- **原始文件字节永不修改**：内核在 CreateProcess 建映像节时读 `DYNAMIC_BASE` 标志，
  aidbg 用"改名交换"在创建前清掉它、创建后立即还原——目标对自身文件的自校验读到原始字节。
- 暂存副本使用每次唯一的 `<目标>.aidbg-patched-<pid>-<tick>` 名称；目标退出后下一次
  固定基址启动会清理残留（文件仍被运行中映像占用时保留到之后）。
- 系统文件（`%SystemRoot%`）不参与交换；交换失败自动**回退 ASLR 并提示**（slide 非 0）。
- `aslr on`（或 `--aslr`）保留真实 ASLR 行为。

### 3.3 调试 DLL

DLL 不能创建为进程，`file <dll>` 时 aidbg 从自身资源释放**内置宿主 stub**（x86/x64）加载：

```
file sample_dll.dll SampleEntry    # 第二参数 = 加载后调用的导出（可省略）
run
```

自动断点链（可 `bc` 删除）：宿主入口 → **DLL 加载**（自动 `bpload`）→ **DllMain**
（自动 `dll+0x<入口RVA>` 待定断点）。固定基址对 DLL 同样生效。

- 不给 `export`：只 `LoadLibrary` 并保持映射（研究 DllMain / 手动控制）。
- 给 `export`：按 rundll32 约定调用 `void WINAPI fn(HWND, HINSTANCE, LPSTR, int)`；
  x86 导出名请用 .def 保持无修饰。找不到导出时宿主以退出码 3 结束。
- 已运行进程里的 DLL：`attach <pid>` + `bpload <dll>`。

### 3.4 执行控制

| 命令 | 说明 |
|---|---|
| `continue\|c\|g [timeout_ms]` | 继续（超时返回 `timeout` 而非挂死） |
| `pause [timeout_ms]` | **暂停仍在运行的目标**（向目标注入一次断点，停在 `system_break`） |
| `step\|si [count]` / `next\|n\|so [count]` | 单步（步入 / 步过 call/rep/loop） |
| `finish\|gu` | 执行到当前函数返回 |
| `until <addr\|expr>` | 执行到指定地址 |
| `stepuntil\|tu <条件> [max=N]` | **单步直到表达式为真**（每步求值） |
| `rununtil\|ru <条件> [max=N]` | **继续直到表达式为真**（每次停住求值） |
| `autostep\|astep <count> [delay_ms]` | 连续单步并**记录执行轨迹** |

```
stepuntil eax == 3 max=200        # 直到 eax 变 3
rununtil ecx == 14 max=20         # 直到 ecx 变 14
autostep 14                       # 记录接下来 14 条实际执行的指令
```

`max=N` 是步数/停住次数上限，超限报 `condition_not_met`。追踪期间自动快照暂停
（避免万步万份快照），结束后恢复。

超时语义：`continue <ms>` 的超时是**整段墙钟预算**（hide 钩子产生的内部调试事件不会
重置计时）。超时后目标仍在运行：再次 `continue` 会继续等待；要查看状态或单步，先用
`pause`。`pause` 在 hide 开启时也能工作（内部临时恢复 `PEB.BeingDebugged`，完成后还原）。

### 3.5 断点

| 命令 | 说明 |
|---|---|
| `break\|b <addr\|symbol> [condition]` | 软件断点（INT3） |
| `hbreak <addr> [r\|w\|x] [size]` | 硬件断点（DR0-3，最多 4 个，size 1/2/4/8） |
| `mbreak <addr> <size> [r\|w\|x]` | 内存断点（PAGE_GUARD，任意大小） |
| `cond <id> <expression>` | 条件；为 0 时自动继续 |
| `bpcmd <id> [command\|-]` | **命中动作**：每次命中先执行命令（如 `eval rax`），再按条件停/走 |
| `bpload [pattern\|add <pattern>\|del <pattern>\|clear]` | **模块加载断点**（`*` 通配） |
| `bl` / `be <id>` / `bd <id>` / `bc <id\|*>` | 列表 / 启用 / 禁用 / 删除 |

- **启动前设断点**是推荐工作流：pending 断点在模块加载后自动解析植入（`bl` 的
  `resolved` 字段区分）。
- 同一地址/符号重复设软件或内存断点会被拒绝（`already_set`）；`module+0xoff` 形式的
  断点按**每个进程**的模块基址分别解析并植入。
- 硬件断点按 DR6 槽位匹配命中 id；`rw` 映射为读写；从执行型硬件断点继续/单步时会
  自动临时关闭该槽位并单步越过，不会反复命中同一条指令。
- `bl` 的 `data.breakpoints[]` 含 `id, kind, address, symbol, size, access, enabled,
  hit_count, condition, command, resolved`。
- 命中命令中**禁止执行控制**（`continue`/`kill`/`detach` 会被拒绝）：它们会重入调试事件泵。
- hide 与用户断点共用同一字节时会交接所有权：`hide off` 后用户断点仍然有效。

### 3.6 状态读写

| 命令 | 说明 |
|---|---|
| `regs [name...]` | 寄存器：GPR（按架构）+ 标志位 + `mxcsr` + `xmm0-15`（x86 为 0-7） |
| `setreg <reg> <value>` | 写寄存器；`setreg xmm3 <1..32 hex>` 写完整 128 位 |
| `mem <addr> [size]` | 十六进制 dump（默认 64 字节，上限 4096） |
| `read <addr> <size>` / `write <addr> <hexbytes>` | 读字节（≤65536）/ 写字节 |
| `patch [list \| undo <id\|*> \| clear \| file <out> [orig=<path>] \| <addr> <hexbytes>]` | 补丁管理（见下） |
| `search <start> <end> <pattern> [max=N]` | 字节搜索（`??` 通配） |
| `regions [start] [end]` | 内存区域 |
| `alloc <size>` / `free <addr>` / `protect <addr> <size> <r\|w\|x>` | 内存管理 |

`max=N` 必须显式写成 `max=数字`，以免与十六进制字节混淆。

#### patch：补丁记录与落盘

写入**模块映像内**的字节（`write` 或 `patch <addr> <hexbytes>`，二者等价）会被自动记录：
先捕获改前字节，按 模块+RVA 锚定（与 notes 相同，跨 ASLR 滑移 / 重启稳定），重叠写入合并为
一条记录并保留**最初**的原始字节。

- `patch` / `patch list`：列出记录（id、模块、RVA、原始 → 修改后字节）
- `patch undo <id|*>`：把原始字节写回内存并删除记录（模块须已加载；重启后内存已还原，
  此时用 `patch clear` 丢弃记录即可）
- `patch clear`：只丢弃记录，不动内存
- `patch file <out> [orig=<path>]`：把记录烘焙进磁盘文件副本——按 PE 节表把每个 RVA 映射到
  文件偏移后写回、重算 CheckSum，输出**可独立运行**的补丁文件（不修改原文件）。默认源为该
  模块的磁盘路径；模块已卸载时用 `orig=` 指定。记录跨多个模块时须分模块烘焙；RVA 无文件
  原始映射（纯虚拟数据节）时报错。注意：调试会话若开了 ASLR（slide≠0），新字节中的绝对
  地址以运行基址为准，落盘前需自行换算（默认固定基址无此问题）。

内存中的补丁也天然包含在 `dump` 导出里（dump 导出的是整个内存镜像），`patch file` 则用于
"原文件 + 少量字节补丁"的经典破解场景。

### 3.7 分析

| 命令 | 说明 |
|---|---|
| `disasm\|u [addr] [count]` | 反汇编（≤4096 的小整数按条数，表达式按起始地址）；含字节、符号/标签注释、跳转目标 |
| `flow\|cfg [addr] [max_blocks]` | 函数控制流图（基本块 + fallthrough/branch/indirect 边） |
| `modules` / `threads` / `thread <tid>` / `symbols [mask] [max]` | 模块 / 线程 / 符号 |
| `stack\|bt [max]` | 调用栈（符号、模块偏移、源文件:行号） |
| `teb [tid]` / `peb` | 线程/进程环境块（BeingDebugged、NtGlobalFlag、栈范围、LastError…） |
| `heap [max]` / `handles [type] [max]` | 堆枚举（PEB ProcessHeaps）/ 句柄枚举（类型、访问掩码、名字） |
| `eval <expression>` | 求值（标注所属模块与符号） |
| `exports [module] [mask] [max]` | 解析模块导出表（直接读目标内存的 PE） |
| `imports <addr> [count]` | 指针段 → `module!function`（IAT 分析） |
| `iat scan [start end]` | 自动定位导入指针段 |
| `iat map <addr> [count]` | 按模块分组的导入映射（重建用） |
| `iat refs <start> <end>` | 扫描代码中的导入引用（`call/jmp/mov/lea [rip+x]`） |
| `iat fix <start> <end> [newva]` | 重建导入表并改写引用（内存中修复 IAT） |
| `iat trace <addr> [max_steps]` | 追踪一次导入调用最终落到哪个 API |
| `dump <file> [addr] [entry=<addr>] [compact] [keepbase] [noiat]` | 内存镜像导出为可加载 PE（自动修复导入表与重定位，见下） |
| `ptype <type>` / `whatis <symbol>` / `print <expression>` | PDB 类型布局 / 声明类型 / 带类型求值（`.` `->` `[]` 成员访问） |

#### dump 的导入表与重定位修复

- **导入表**：先校验内存中的原导入目录；完好（普通 DLL/EXE、未加壳）则原样保留——
  加载器自己就能按名字解析。原目录损坏/丢失（加壳、IAT 被 VMProtect 派发器重建）时，
  自动扫描数据节的导入指针序列，按模块分组重建 `IMAGE_IMPORT_DESCRIPTOR` + 名称表，
  追加 `aidbgIAT` 节并让 `FirstThunk` 指回原槽位——加载器会把名字解析回代码实际读取的
  位置。`noiat` 关闭该修复。
- **重定位**（`keepbase`）：把 `ImageBase` 恢复为 preferred 基址，并按 `.reloc` 把加载器
  施加的位移从每个已重定位指针中减去，导出重新可重定位的镜像（保留 ASLR 位）。
  `.reloc` 被壳抹掉时退回"钉在运行基址 + 关 ASLR"并给出提示。
- **INT3 拓印**：dump 前自动摘除镜像内所有已植入的 INT3（用户断点与 hide 钩子），
  dump 后原样种回——否则导出文件带着 0xCC 一运行就崩。
- 默认（不带 `keepbase`）仍是"钉在运行基址 + 关 ASLR"（加载器直接映射原地址）。

`peb` 会自校验 `ImageBaseAddress` 与主模块基址一致；`NtGlobalFlag` 的 `0x70` 是附加
调试器的典型痕迹。x86(WOW64) 的 `teb.peb` 与 `peb` 可能不一致（双 TEB），输出用 `[!]`
标出，核心字段仍准确。

### 3.8 快照与回退

| 命令 | 说明 |
|---|---|
| `snapshot\|snap save [name]` / `restore [name\|index]` | 保存 / 恢复完整状态（内存+寄存器） |
| `snapshot list` / `delete <name\|index>` / `clear` / `auto on\|off` | 管理（auto = 每次停住自动捕获，默认开） |
| `snapshot file [path]` / `history` / `load <id>` / `compact` | 单文件快照库 |
| `stepback\|sbk\|reverse [count]` | **回到较早的停住点** |

存储为链式差分（首份全量 + 页粒度脏页差分）+ MS Compression 压缩 + 全零页免费；
单文件容器是追加式日志，崩溃可扫描恢复，负载带 CRC（损坏记录会被跳过）。`delete`
只能删除最新的一份（保持差分链完整）；恢复会重刷指令缓存并重新武装软件/内存/硬件断点。
注意：**只回滚内存/寄存器**（内核对象不撤销）、**恢复是破坏性的**（比目标快照更新的
会被丢弃）、差分链不跨会话。

### 3.9 异常策略

| 命令 | 说明 |
|---|---|
| `exlist` / `exset <code> <break\|ignore\|pass>` / `exdel <code>` | 查看 / 设置 / 删除 |
| `exall <on\|off>` | 全局忽略所有一次机会异常 |

别名：`av` `bp` `ss` `guard` `cpp`。`break`（默认）停下报告；`ignore` 交给目标；
`pass` 吞掉。二次机会异常总是停下。

### 3.10 反反调试（hide / detect）

| 命令 | 说明 |
|---|---|
| `detect` | al-khaser 清单自查，报告哪些检测会命中、由哪个开关修复 |
| `hide [status]` / `hide on [profile]` / `hide off` | 状态 / 开启 / 关闭 |
| `hide profile <name>` | `off` `basic` `standard` `aggressive` `vmp` `themida` `obsidium` |
| `hide set <key> <0\|1>` | 逐项开关（键名 = `scylla_hide.ini`） |
| `hide apply` / `hide hooks` / `hide profiles` | 重新应用 / 钩子位点 / 配置档目录 |
| `hide load <file>` / `hide save <file>` | ini 读写（直接兼容 `scylla_hide.ini`） |

默认 `--hide standard`，`--mcp` 模式下同样生效。系统进程（`conhost.exe`）不会被 hook。
两层实现，均不注入代码：**L1 内存补丁**（PEB.BeingDebugged、
NtGlobalFlag 0x70、堆 Flags、StartupInfo、KUSER_SHARED_DATA；WOW64 双 PEB）+
**L2 API 虚拟化**（ntdll 导出上布 INT3、调试器代答：NtQueryInformationProcess、
NtQuerySystemInformation、NtSetInformationThread、NtQueryObject、NtClose、
NtYieldExecution、NtGet/SetContextThread 等；无法代答的单步回放原指令）。

`detect` 在**调试器侧**发起查询，不经过目标进程里的 L2 钩子；`process.debug_flags`
这类项反映的是内核真实状态。要判断 L2 是否生效，请以目标自身运行 `antidbg_probe`
的结果为准。

**能力边界（诚实声明）**：L2 的 INT3 可被 ntdll 完整性扫描发现（`detect` 如实标注）；
直接 syscall 不受 L2 影响；计时类/TrapFlag/int 2D 等运行时检测未覆盖（detect 标 skipped）；
句柄表/进程列表过滤未实现；NtQueryObject 计数过滤在 WOW64 不生效；不做驱动级隐藏；
NtClose 钩子高频目标有性能代价（`hide set NtCloseHook 0` 可单独关）。

### 3.11 用户笔记（label / comment / notes）

| 命令 | 说明 |
|---|---|
| `label <addr> [name\|-]` | 标签可直接进表达式（`break my_loop`） |
| `comment <addr> [text\|-]` | 注释（`disasm` 输出会带上） |
| `notes [list\|save <file>\|load <file>\|clear]` | 管理 / JSON 持久化 |

锚定**模块+RVA**（ASLR/重启后仍有效）。`notes save` 的 JSON（`aidbg-notes-1`）适合把一轮
分析结论带进下一会话。

---

## 4. 典型工作流

```
# 摸底
file sample.exe / run / modules / disasm 16 / stack 8

# 先设断点再启动（推荐）
file sample.exe / break CreateFileW / break main / run / continue / regs

# 追踪函数调用
break CreateFileW / continue / regs rcx rdx r8 r9 / read rdx 64 / stack 6

# 找写变量的位置
hbreak <var_addr> w 4 / continue / disasm 4 / stack 4

# 条件断点
break SomeFunc / cond 1 rcx == 0x2a / continue

# 脱壳：定位并修复 IAT
iat scan / iat refs .text范围 / iat fix <start> <end> / dump unpacked.exe

# 自校验型壳/加固：先查再藏
detect → hide profile vmp → run → detect

# DLL
file crypto.dll DecryptEntry / run / break crypto.dll!key_schedule
```

## 5. 给 AI 的使用建议

1. **先 `info`/`session` 后动作**：每条响应都带会话状态，`state=paused` 才能读写。
2. **用表达式而不是硬编码地址**：`break main`、`read rdx 64` 都比裸地址稳。
3. **批量取样防上下文爆炸**：`mem` 默认 64 字节、`search` 用 `max=N`、列表命令都有上限。
4. **条件断点代替循环查询**：`cond` / `rununtil` / `stepuntil` 在引擎内求值，少一轮往返。
5. **出错看 `error.code` 决定重试**：`not_paused`→先 continue/step（若刚 `continue` 超时则先
   `pause`）；`unknown_type`→换 `whatis`；`condition_not_met`→加大 `max` 或换 `rununtil`。
6. **脱壳类任务**用 `iat` 系列 + `dump`；**类型推断**用 `ptype`/`print`；**入口侦察**用 `flow`。
7. **把结论写进 `notes`** 并 `notes save`，跨会话接力。

## 6. MCP 服务器

`aidbg --mcp`：stdio 上换行分隔 JSON-RPC 2.0；会话在整个连接期间保持；13 个工具
（`aidbg_session` / `execute` / `breakpoint` / `registers` / `memory` / `disasm` / `cfg` /
`stack` / `modules` / `eval` / `exceptions` / `snapshot` / `command`）返回与命令行**完全相同**
的 JSON 信封（成功且无结构化数据的命令额外带 `text`，例如 `help`）。

协议约定：

- 必须先 `initialize`；之后才能调用 `tools/*`（否则 `-32002`）。`ping` 随时可用。
- 参数是**结构化 JSON**：地址既可以是 `"0x..."` 字符串，也可以是 JSON 数字；布尔开关
  既可以是 `true/false`，也可以是 `"on"/"off"`。
- `aidbg_session(action=file)` 的 `exe/args` 原样传递，**含空格路径不会被拆开**。
- `aidbg_execute` 支持 `action=pause`（超时后暂停运行中的目标）。
- `aidbg_breakpoint(action=delete)` 必须给 `id`；删除全部请用
  `aidbg_command{command:"bc *"}`。
- 目标进程退出后会话自动复位，可在同一连接里继续 `action=file/run`。
- 单条消息上限 8 MiB；不支持 JSON-RPC batch（返回 `-32600`），避免被静默丢弃。

错误分两级：命令级 = 信封 `ok:false`；协议级 = JSON-RPC `error`
（`-32700` 解析失败 / `-32600` 非法请求或 batch / `-32601` 未知方法 /
`-32602` 未知工具 / `-32002` 未初始化 / `-32603` 内部错误）。通知不返回响应（带 `id`
的通知例外）。

### 6.1 远程（双机）调试：HTTP/SSE 传输

`--mcp --port <n>` 在 stdio 之外同时提供 HTTP 传输，另一台机器上的 MCP 客户端可以直接
连接调试器（所有命令仍由单线程串行执行，多客户端共享同一个调试会话）：

```bat
:: 目标机（调试器所在机器）
aidbg --mcp --port 8799 --bind 0.0.0.0
:: 非回环绑定且未给 --token 时会自动生成并打印一个 Bearer 令牌，复制给客户端
:: 显式指定：--token <secret>
```

同一端口服务两种传输，覆盖新旧 MCP 客户端：

| 端点 | 传输 | 说明 |
|---|---|---|
| `GET /sse` | 旧版 SSE | 建立事件流；首事件 `endpoint` 给出消息入口 URL（`/messages?sessionId=...`），响应经事件流回传 |
| `POST /messages?sessionId=<id>` | 旧版 SSE | 提交 JSON-RPC 消息，返回 `202`，响应在事件流上 |
| `POST /mcp` | Streamable HTTP | 直接以 JSON-RPC 消息为请求体，**HTTP 响应即 JSON-RPC 响应** |
| `GET /` | — | 健康检查（返回版本） |

- 鉴权：配置令牌后所有请求需带 `Authorization: Bearer <token>`（SSE 的 GET 也可用
  `?token=` 查询参数）。默认绑定 `127.0.0.1`；`--bind 0.0.0.0` 暴露到网络时**必须**有
  令牌（未指定则自动生成）。调试器可以启动任意进程、读写任意内存，不要裸奔到公网。
- 注意：不带 `timeout_ms` 的 `continue` 会阻塞到目标停下为止——HTTP 请求会一直挂着，
  与 stdio 行为一致；远程客户端建议始终带超时并用 `pause`。
- 事件流每 15 秒发一次 `: ping` 注释保持连接。
- 停止服务器直接结束进程即可；退出前记得先 `detach`，否则被调试目标会一并终止。

---

**文档导航** [README](README.md) | [Manual](Manual.md) | [dev](dev.md) ·
[English](Manual.en.md)
