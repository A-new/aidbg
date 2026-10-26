<h1 align="center">aidbg</h1>
<p align="center">面向 AI 的 Windows x86/x64 命令行调试器</p>

<p align="center">
  <a href="https://github.com/A-new/aidbg/releases"><img alt="release" src="https://img.shields.io/github/v/release/A-new/aidbg?style=flat-square" /></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-Windows%20x86%20%7C%20x64-blue?style=flat-square" />
  <img alt="runtime" src="https://img.shields.io/badge/runtime-zero%20VC%20redist-brightgreen?style=flat-square" />
</p>

<p align="center">
  <a href="README.md">中文</a> |
  <a href="README.en.md">English</a>
</p>

---

`aidbg` 的核心目标不是人类交互体验，而是 **让程序（AI agent）能可靠地驱动调试会话并解析结果**：

- 每条命令输出 **一行 JSON**（JSONL），字段稳定、可直接解析
- **同一 exe 自动识别 x86 / x64 目标**（WOW64 感知），一个会话可混合两种架构
- 批处理（`-c`）/ 脚本（`--script`）/ **MCP 服务器**（`--mcp`）三种驱动方式
- **默认固定基址**：动态地址与 IDA / Ghidra 静态地址逐字节一致
- 反反调试（ScyllaHide 式）+ 快照回退 + IAT 重建 + **直接调试 DLL**

### 快速开始

```bat
:: 构建（MSVC；脚本自动定位 VS 2019/2022/18 并编译内置 DLL 宿主）
build.bat Release

:: 一次典型的 AI 调用
aidbg --json ^
  -c "file tests\target.exe" ^
  -c "run" ^
  -c "break accumulate" ^
  -c "continue" ^
  -c "regs" ^
  -c "stack 5"
```

> [!TIP]
> 产物零 VC 运行时依赖（仅 `KERNEL32` / `dbghelp` / `ucrtbase`），拷贝到 Windows 10+ 即可运行。

### 能力一览

| | |
|---|---|
| **调试** | 软/硬/内存断点、条件断点、命中命令、模块加载断点、继续/暂停/单步/步过/步出/运行到地址 |
| **分析** | 反汇编（符号注释）、控制流图、调用栈（源码行号）、TEB/PEB/堆/句柄、PDB 类型 |
| **脱壳** | 导入表扫描/引用定位/重建修复、导入调用追踪、`dump` 导出可运行 PE（原表完好自动保留；损坏时按 Scylla 方式重建导入表；`keepbase` 还原 preferred 基址与重定位；断点 INT3 不拓印） |
| **反反调试** | `hide` 配置档（兼容 `scylla_hide.ini`）+ `detect` 自查（al-khaser 清单） |
| **可逆** | 快照（差分+压缩+单文件库）与 `stepback` 回退执行 |
| **DLL** | `file foo.dll [export]` 内置宿主加载，自动断点链（加载 → DllMain） |
| **多进程** | 子进程跟随（混合 x86/x64）、world-stop（停靠时冻结全部被调试进程）、每进程独立符号会话 |
| **MCP** | `--mcp` stdio；`--port` 提供 HTTP 远程传输（SSE + Streamable HTTP，双机调试，Bearer 鉴权） |

### 下载

每个版本在 [Releases](https://github.com/A-new/aidbg/releases) 单独发布 `aidbg.exe`
（版本号以 `src/util/version.h` 为唯一来源，每次更新递增）。

### 文档

| 文档 | 受众 |
|---|---|
| [Manual.md](Manual.md) · [Manual.en.md](Manual.en.md) | **AI / 脚本作者**：输出契约、表达式、全部命令、工作流 |
| [dev.md](dev.md) · [dev.en.md](dev.en.md) | **开发者**：构建、架构、设计决策、测试与发布 |
| [skills/aidbg](skills/aidbg) | **AI agent 技能包**：把 `skills/aidbg` 目录拷到 `.claude/skills/aidbg`（或其他 agent 的 skills 目录），即可让 Claude 等 agent 按本手册驱动调试器 |

### 致谢

工具链：[Zydis](https://github.com/zyantific/zydis)（MIT）。设计参考了 x64dbg、raddebugger、
GDB、Z0BDbgCli、Nanomite、Syser、ScyllaHide、al-khaser 等开源项目，在此一并致谢。

---

**反馈与问题** [Issues](https://github.com/A-new/aidbg/issues) | [Releases](https://github.com/A-new/aidbg/releases)
