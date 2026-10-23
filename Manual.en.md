# aidbg AI Manual

<p align="center">
  <a href="README.md">中文</a> | <a href="README.en.md">English</a>
  　·　<a href="Manual.en.md">Manual</a> | <a href="dev.en.md">dev</a>
</p>

---

The complete manual for AI agents and script authors. Every command can emit one line of
JSON; this document defines the output contract, expression syntax, all commands and the
recommended workflows. Developers: see [dev.en.md](dev.en.md).

---

## 1. Output contract (read first)

### 1.1 JSON envelope

With `--json`, **each command produces exactly one line** of JSON:

```json
{"ok":true,"cmd":"regs","data":{...},"session":{...}}
{"ok":false,"cmd":"mem","error":{"code":"read_failed","message":"..."},"data":{},"session":{...}}
```

| Field | Meaning |
|---|---|
| `ok` | whether the command succeeded |
| `cmd` | canonical command name (aliases normalized, e.g. `b` -> `break`) |
| `data` | structured result on success |
| `error` | `{code, message}` on failure |
| `session` | session snapshot, present on **every** response for easy state tracking |
| `text` | MCP only: textual result when a command has no structured data (e.g. `help`) |

`session` fields:

```json
{"active":true,"pid":123,"tid":456,"state":"paused",
 "stop_reason":"breakpoint","rip":"0x7ff6...","arch":"x64",
 "detail":"breakpoint 2 hit (accumulate)"}
```

- `state`: `idle` (no target, including after the target exited) / `paused` (stopped,
  readable) / `running`
- `arch`: `x86` or `x64` (**auto-detected**; picks register names and disassembly mode)
- `stop_reason`: `entry` / `breakpoint` / `step` / `exception` / `memory_breakpoint` /
  `system_break` / `module_load` / `exit` / `timeout`

Async events (debug strings, warnings) get their own line:
`{"kind":"event","event":"debug_string","text":"..."}`.

### 1.2 Value encoding

| Type | Encoding | Example |
|---|---|---|
| addresses / 64-bit registers | **hex strings** | `"0x7ff674a47220"` |
| small integers (sizes, counts) | JSON numbers | `64`, `5` |
| byte strings | space-separated uppercase hex | `"48 8B 5C 24 08"` |

> [!NOTE]
> 64-bit values are always strings: JSON numbers only have 2^53 of safe integer range.

### 1.3 Exit codes and sessions

`0` all succeeded; `1` some command failed; `2` bad arguments. Batch runs `detach`
automatically afterwards - no dangling sessions. In interactive mode `quit`, `exit` and
`q` all leave the program.

- **The session ends when the target does**: after the last debugged target exits the
  engine clears processes, breakpoints, symbols and hide state, and `session.state`
  returns to `idle`. `run`/`restart` can then start a new session without restarting aidbg.
- Every response carries the `session` envelope; `active:false,state:idle` means there is
  no operable target.

---

## 2. Addresses and expressions

Everything that takes an address accepts an expression:

| Form | Example | Meaning |
|---|---|---|
| hex | `0x7ff674a47220` | literal |
| decimal | `1234` / `0n1234` | literal |
| register | `rax`, `rsp`, `rip`, `eax`, `al`, `xmm0` | current thread registers; x86 targets use `eax`..`edi`/`eip` (64-bit names alias the low halves) |
| symbol | `main`, `kernel32!CreateFileW` | PDB/export symbols |
| label | `entry_point` | user labels made with `label` |
| module relative | `target.exe+0x7220` | module base + offset |
| symbol relative | `main+0x10` | symbol + offset |
| built-ins | `$entry`, `$ra` | entry point / return address |
| dereference | `[rsp]`, `[rax+0x10]` | read a pointer-sized value |
| arithmetic | `rax+8`, `[rbp-0x20]&0xff`, `x<<2` | `+ - * / & \| ^ ~ << >>` |
| compare/logic | `rcx == 14`, `rax && [rsp] > 0x1000` | `== != < <= > >= && \|\|` |

Comparisons return `1`/`0` for **conditional breakpoints**. Plain arithmetic like `eval 2+2`
works too.

---

## 3. Command reference

### 3.1 Session

| Command | Meaning |
|---|---|
| `file <exe> [args...]` \| `file <dll> [export]` | set target: exe+args, or a DLL (loaded in the built-in host; `export` is an optional entry to call) |
| `run [args...]` | launch, stop at the **entry point** (ntdll loader breakpoints are skipped) |
| `attach <pid>` | attach to a running process |
| `detach` / `kill` | clean detach / terminate |
| `restart` | relaunch with the same arguments |
| `aslr [on\|off]` | fixed load base toggle (default off = fixed base) |
| `processes\|ps` / `process\|proc <pid>` | list/switch processes (children included) |
| `info` / `version` / `help` | session state / version / machine-readable catalog |

- **Child processes are debugged by default** (`--no-children` disables); each process gets
  its own arch detection - x86 and x64 can mix in one session.
- `conhost.exe` shows up because it inherits the debug port, but it is marked as a system
  process: `ps` reports `"system":true`, it never becomes `current`, and it takes no part
  in hiding, symbol loading or breakpoint planting.
- CLI flags: `--exe` `--args` `--cwd` `--console` `--aslr` `--no-children`
  `--hide <profile|off>` `--json` `--pretty` `-c <cmd>` `--script <file>` `--mcp`.

### 3.2 Fixed base (default)

Targets load at the PE `ImageBase` so runtime addresses match static disassembly exactly
(x64: `0x140000000`, x86: `0x400000`). `modules` reports `base` (actual), `image_base`
(PE header) and `slide` (relocation delta; 0 when pinned).

- **The original file's bytes are never modified.** The kernel reads `DYNAMIC_BASE` while
  creating the image section during CreateProcess, so aidbg clears it *before* creation via a
  rename swap and restores the file immediately afterwards - a target hashing its own file
  sees exactly the original bytes.
- The staging copy uses a unique `<target>.aidbg-patched-<pid>-<tick>` name per launch; the
  next fixed-base launch removes leftovers (a file still mapped by a running image is kept
  until it can be deleted).
- System files (`%SystemRoot%`) never take part in the swap; any swap failure **falls back
  to an ASLR launch with a warning** (slide will be non-zero).
- `aslr on` (or `--aslr`) keeps real ASLR behaviour.

### 3.3 Debugging DLLs

A DLL cannot be a process, so `file <dll>` makes aidbg extract a **built-in host stub**
(x86 and x64) from its own resources to load it:

```
file sample_dll.dll SampleEntry    # second parameter = export to call after load (optional)
run
```

Automatic breakpoint chain (removable with `bc`): host entry -> **DLL load** (auto `bpload`)
-> **DllMain** (auto pending breakpoint at `dll+0x<entry RVA>`). Fixed base applies to DLLs too.

- No `export`: just `LoadLibrary` and keep it mapped (DllMain studies / manual control).
- With `export`: called as `void WINAPI fn(HWND, HINSTANCE, LPSTR, int)` (rundll32
  convention); use a .def for undecorated x86 export names. A missing export ends the host
  with exit code 3 instead of idling.
- DLLs in running processes: `attach <pid>` + `bpload <dll>`.

### 3.4 Execution control

| Command | Meaning |
|---|---|
| `continue\|c\|g [timeout_ms]` | resume (timeout returns `timeout` instead of hanging) |
| `pause [timeout_ms]` | **pause a running target** (injects a break; stops as `system_break`) |
| `step\|si [count]` / `next\|n\|so [count]` | step into / step over calls |
| `finish\|gu` | run until the current function returns |
| `until <addr\|expr>` | run to an address |
| `stepuntil\|tu <cond> [max=N]` | **single step until the expression is true** |
| `rununtil\|ru <cond> [max=N]` | **run until true** (evaluated at every stop) |
| `autostep\|astep <count> [delay_ms]` | step repeatedly and **record the executed trace** |

```
stepuntil eax == 3 max=200        # until eax becomes 3
rununtil ecx == 14 max=20         # until ecx becomes 14
autostep 14                       # record the next 14 instructions
```

`max=N` caps steps/stops (`condition_not_met` when exceeded). Auto-snapshots pause during
tracing and resume afterwards.

Timeout semantics: `continue <ms>` is a **wall-clock budget for the whole stop** (internal
debug events from hide hooks no longer reset the timer). After a timeout the target is still
running: another `continue` keeps waiting; use `pause` before inspecting state or stepping.
`pause` also works with hide enabled (it temporarily restores `PEB.BeingDebugged` and puts
it back afterwards).

### 3.5 Breakpoints

| Command | Meaning |
|---|---|
| `break\|b <addr\|symbol> [condition]` | software breakpoint (INT3) |
| `hbreak <addr> [r\|w\|x] [size]` | hardware breakpoint (DR0-3, max 4, size 1/2/4/8) |
| `mbreak <addr> <size> [r\|w\|x]` | memory breakpoint (PAGE_GUARD, any size) |
| `cond <id> <expression>` | condition; false auto-continues |
| `bpcmd <id> [command\|-]` | **on-hit command** (runs before the stop/continue decision) |
| `bpload [pattern\|add <p>\|del <p>\|clear]` | **module-load breakpoint** (`*` wildcards) |
| `bl` / `be <id>` / `bd <id>` / `bc <id\|*>` | list / enable / disable / delete |

- **Set breakpoints before launching** (recommended): pending ones resolve and plant when
  their module loads (`bl` shows `resolved`).
- Duplicate software or memory breakpoints at the same address/symbol are rejected
  (`already_set`); `module+0xoff` breakpoints resolve against **each process's** module base.
- Hardware breakpoints are matched by their DR6 slot; `rw` maps to read/write; continuing or
  stepping from an execution breakpoint temporarily disables its slot and steps over the
  instruction, so it does not fire repeatedly on the same instruction.
- Execution control is refused inside on-hit commands (`continue`/`kill`/`detach`): it would
  re-enter the debug event pump.
- When hide and a user breakpoint share a byte, ownership is handed over: the user
  breakpoint keeps working after `hide off`.

### 3.6 Registers and memory

| Command | Meaning |
|---|---|
| `regs [name...]` | GPRs (per arch) + flags + `mxcsr` + `xmm0-15` (x86: 0-7) |
| `setreg <reg> <value>` | write a register; `setreg xmm3 <1..32 hex>` writes the full 128 bits |
| `mem <addr> [size]` | hex dump (default 64 bytes, max 4096) |
| `read <addr> <size>` / `write <addr> <hexbytes>` | read (<=65536) / write bytes |
| `search <start> <end> <pattern> [max=N]` | byte search (`??` wildcard) |
| `regions [start] [end]` | memory regions |
| `alloc` / `free` / `protect` | memory management |

Write `max=N` explicitly so it cannot be confused with hex bytes.

### 3.7 Analysis

| Command | Meaning |
|---|---|
| `disasm\|u [addr] [count]` | disassembly (small ints = count, expressions = start); symbol/label annotations |
| `flow\|cfg [addr] [max_blocks]` | control flow graph (blocks + fallthrough/branch/indirect edges) |
| `modules` / `threads` / `thread <tid>` / `symbols` | modules / threads / symbols |
| `stack\|bt [max]` | call stack with symbols and source lines |
| `teb` / `peb` | TEB/PEB views (BeingDebugged, NtGlobalFlag, stack bounds, LastError...) |
| `heap [max]` / `handles [type] [max]` | heap enumeration (PEB ProcessHeaps) / handle table |
| `eval <expression>` | evaluate with module/symbol annotation |
| `exports [module] [mask]` | parse the export directory from target memory |
| `imports <addr> [count]` | pointer run -> `module!function` (IAT analysis) |
| `iat scan/map/refs/fix/trace` | locate import slots, group by module, find code references, **rebuild the IAT**, trace where an import call lands |
| `dump <file> [addr] [entry=] [compact] [keepbase]` | dump the in-memory image as a loadable PE |
| `ptype` / `whatis` / `print` | PDB type layouts / declared types / typed evaluation (`.` `->` `[]`) |

`peb` self-checks `ImageBaseAddress` against the main module base. On WOW64 targets
`teb.peb` and `peb` may differ (dual TEBs) - the output flags it with `[!]`; core fields stay
accurate.

### 3.8 Snapshots and reverse execution

| Command | Meaning |
|---|---|
| `snapshot save/restore [name\|index]` | save/restore full state (memory + registers) |
| `snapshot list/delete <name\|index>/clear/auto` | management (`auto` = capture at every stop, default on) |
| `snapshot file [path]` / `history` / `load <id>` / `compact` | single-file snapshot store |
| `stepback\|sbk\|reverse [count]` | **return to an earlier stop** |

Storage is a differential chain (one full + page-granular dirty diffs) with MS Compression;
the container is an append-only log that survives crashes and carries a CRC per payload
(corrupt records are skipped). `delete` only removes the newest snapshot (keeps the chain
intact); restore flushes the instruction cache and re-arms software/memory/hardware
breakpoints. Note: only memory/registers roll back (kernel objects do not), restore is
destructive (newer snapshots are dropped), and chains never cross sessions.

### 3.9 Exception policy

`exlist` / `exset <code> <break|ignore|pass>` / `exdel <code>` / `exall <on|off>`.
Aliases: `av` `bp` `ss` `guard` `cpp`. `break` (default) stops and reports, `ignore` lets the
target handle it, `pass` swallows it. Second-chance exceptions always stop.

### 3.10 Anti-anti-debug (hide / detect)

| Command | Meaning |
|---|---|
| `detect` | self-check against the al-khaser catalogue: which checks fire, which switch fixes them |
| `hide [status]` / `hide on [profile]` / `hide off` | status / enable / disable |
| `hide profile <name>` | `off` `basic` `standard` `aggressive` `vmp` `themida` `obsidium` |
| `hide set <key> <0\|1>` | per-switch toggles (key names = `scylla_hide.ini`) |
| `hide apply` / `hooks` / `profiles` / `load` / `save` | re-apply / sites / catalog / ini I/O |

Default `--hide standard`; it also applies in `--mcp` mode. System processes such as
`conhost.exe` are never hooked. Two layers, no code injection: **L1 memory patches** (PEB
BeingDebugged, NtGlobalFlag 0x70, heap flags, StartupInfo, KUSER_SHARED_DATA; both PEBs on
WOW64) and **L2 API virtualization** (INT3 on ntdll exports answered by the debugger:
NtQueryInformationProcess, NtQuerySystemInformation, NtSetInformationThread, NtQueryObject,
NtClose, NtYieldExecution, NtGet/SetContextThread; unanswerable calls replay the original
instruction under a single step).

`detect` issues its queries **from the debugger**, bypassing the target-side L2 hooks;
items such as `process.debug_flags` therefore show the real kernel state. To judge whether
L2 is effective, run `antidbg_probe` inside the target and use its output.

**Honest limits**: L2's INT3s are visible to ntdll integrity scans (`detect` reports it);
direct syscalls bypass L2; timing/TrapFlag/int 2D style checks are not covered; handle-table
and process-list filtering is not implemented; DebugObject filtering is inert on WOW64; no
driver-level hiding; the NtClose hook costs performance on handle-heavy targets
(`hide set NtCloseHook 0` disables just that).

### 3.11 User notes (label / comment / notes)

`label <addr> [name|-]` (labels usable in expressions), `comment <addr> [text|-]`
(shown by `disasm`), `notes [list|save|load|clear]`. Anchored to **module+RVA** so they
survive ASLR and restarts. The `aidbg-notes-1` JSON carries analysis conclusions between
sessions.

---

## 4. Typical workflows

```
# survey                file / run / modules / disasm 16 / stack 8
# breakpoints first     file / break CreateFileW / break main / run / continue / regs
# trace a call          break CreateFileW / continue / regs rcx rdx r8 r9 / read rdx 64
# find a writer         hbreak <var> w 4 / continue / disasm 4 / stack 4
# conditional break     break SomeFunc / cond 1 rcx == 0x2a / continue
# unpack: fix the IAT   iat scan / iat refs <range> / iat fix <start> <end> / dump out.exe
# hardened target       detect -> hide profile vmp -> run -> detect
# DLL                   file crypto.dll DecryptEntry / break crypto.dll!key_schedule
```

## 5. Advice for AI agents

1. **Check `session` first**: `state=paused` is required for reads/writes.
2. **Prefer expressions over raw addresses** (`break main`, `read rdx 64`).
3. **Bound your sampling**: 64-byte dumps, `max=N` on searches/lists.
4. **Let the engine loop**: `cond` / `rununtil` / `stepuntil` beat polling from outside.
5. **Branch on `error.code`**: `not_paused` -> continue/step first (if a `continue` just
   timed out, `pause` first); `unknown_type` -> try `whatis`; `condition_not_met` -> raise
   `max` or switch to `rununtil`.
6. **Unpacking** -> `iat` + `dump`; **type recovery** -> `ptype`/`print`; **survey** -> `flow`.
7. **Persist conclusions** with `label`/`comment` + `notes save` for the next session.

## 6. MCP server

`aidbg --mcp`: newline-delimited JSON-RPC 2.0 over stdio; the session persists for the whole
connection; 13 tools (`aidbg_session`, `execute`, `breakpoint`, `registers`, `memory`,
`disasm`, `cfg`, `stack`, `modules`, `eval`, `exceptions`, `snapshot`, `command`) return the
very same JSON envelopes (commands with no structured data, such as `help`, also carry a
`text` field).

Protocol notes:

- `initialize` is required before `tools/*` (otherwise `-32002`); `ping` works at any time.
- Arguments are **structured JSON**: addresses may be `"0x..."` strings or JSON numbers;
  boolean switches accept `true/false` as well as `"on"/"off"`.
- `aidbg_session(action=file)` passes `exe/args` through unchanged - **paths containing
  spaces are not split**.
- `aidbg_execute` accepts `action=pause`.
- `aidbg_breakpoint(action=delete)` requires `id`; use
  `aidbg_command{command:"bc *"}` to delete all.
- After the target exits the session resets, so the same connection can
  `action=file/run` again.
- Messages are capped at 8 MiB; JSON-RPC batches are rejected with `-32600` instead of
  being silently dropped.

Errors are two-level: command-level `ok:false` in the envelope, protocol-level JSON-RPC
`error` (`-32700` parse error, `-32600` invalid request/batch, `-32601` unknown method,
`-32602` unknown tool, `-32002` not initialized, `-32603` internal error). Notifications get
no response (except notifications that carry an `id`).

---

**Docs** [README](README.en.md) | [Manual](Manual.en.md) | [dev](dev.en.md) ·
[中文](Manual.md)
