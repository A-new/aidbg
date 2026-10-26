<h1 align="center">aidbg</h1>
<p align="center">An AI-first command line debugger for Windows x86/x64</p>

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

`aidbg` is not about human ergonomics - it is built so that **a program (an AI agent) can drive
a debug session reliably and parse the results**:

- Every command emits **one line of JSON** (JSONL) with a stable schema
- **One exe debugs both x86 and x64** (WOW64 aware); a session can mix both
- Three driving modes: batch (`-c`), scripts (`--script`), **MCP server** (`--mcp`)
- **Fixed load base by default**: runtime addresses match IDA / Ghidra byte for byte
- Anti-anti-debug (ScyllaHide-style) + snapshot rollback + IAT rebuild + **DLL debugging**

### Quick start

```bat
:: build (MSVC; the script locates VS 2019/2022/18 and builds the embedded DLL host)
build.bat Release

:: a typical AI invocation
aidbg --json ^
  -c "file tests\target.exe" ^
  -c "run" ^
  -c "break accumulate" ^
  -c "continue" ^
  -c "regs" ^
  -c "stack 5"
```

> [!TIP]
> Zero VC runtime dependencies (only `KERNEL32` / `dbghelp` / `ucrtbase`) - copy the exe to
> any Windows 10+ machine and run.

### Features

| | |
|---|---|
| **Debugging** | software/hardware/memory breakpoints, conditions, on-hit commands, module-load breaks, continue/pause/step/over/out/until |
| **Patching** | writes to module memory are recorded (original bytes kept), `undo` rolls back, `patch file` bakes them into a standalone runnable copy |
| **Analysis** | disassembly with symbol annotations, control flow graphs, call stacks with source lines, TEB/PEB/heap/handle views, PDB types |
| **Unpacking** | IAT scan / xref / rebuild-fix, import call tracing, dump the in-memory image as a runnable PE |
| **Anti-anti-debug** | `hide` profiles (compatible with `scylla_hide.ini`) + `detect` self-check (al-khaser catalogue) |
| **Reversible** | snapshots (differential + compressed + single-file store) and `stepback` |
| **DLL targets** | `file foo.dll [export]` runs in a built-in host with an automatic breakpoint chain |

### Download

Every version is published separately on
[Releases](https://github.com/A-new/aidbg/releases) as `aidbg.exe`
(`src/util/version.h` is the single source of the version; it is bumped on every update).

### Documentation

| Document | Audience |
|---|---|
| [Manual.md](Manual.md) · [Manual.en.md](Manual.en.md) | **AI / script authors**: output contract, expressions, full command reference, workflows |
| [dev.md](dev.md) · [dev.en.md](dev.en.md) | **Developers**: build, architecture, design decisions, test and release process |
| [skills/aidbg](skills/aidbg) | **AI agent skill**: copy the `skills/aidbg` folder to `.claude/skills/aidbg` (or your agent's skills directory) so agents like Claude can drive the debugger per this manual |

### Credits

Toolchain: [Zydis](https://github.com/zyantific/zydis) (MIT). The design draws on x64dbg,
raddebugger, GDB, Z0BDbgCli, Nanomite, Syser, ScyllaHide and al-khaser - thanks to all of them.

---

**Feedback** [Issues](https://github.com/A-new/aidbg/issues) | [Releases](https://github.com/A-new/aidbg/releases)
