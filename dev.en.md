# aidbg Developer Guide (dev)

<p align="center">
  <a href="README.md">中文</a> | <a href="README.en.md">English</a>
  　·　<a href="Manual.en.md">Manual</a> | <a href="dev.en.md">dev</a>
</p>

---

For developers/maintainers: the build system, architecture layers, key design decisions and
the measured pitfalls behind them. Users: see [Manual.en.md](Manual.en.md); project overview:
[README.en.md](README.en.md).

---

## 1. Build

```bat
build.bat Release
```

`build.bat` does, in order:

1. Locate and call `vcvars64.bat` (the known VS 18 path first; otherwise search
   VS 18/2022/2019 Professional/Community/Enterprise/BuildTools) to set up MSVC
2. **Build the embedded DLL hosts** (`src/host/dllhost.c`) -> `build/host/dllhost64.exe`
   (native cl) and `dllhost32.exe` (built in a separate `vcvars32` environment - the x64
   environment cannot link x86 targets)
3. CMake (NMake Makefiles) builds the main program; `src/host/aidbg.rc` embeds both stubs
   as RCDATA resources

Dependencies and runtime:

- **Zydis 4.1.1** (`third_party/zydis`, vendored): disassembly; x86 targets use the
  `LONG_COMPAT_32` mode
- **DbgHelp**: PDB symbols, line info, types (`SymGetTypeFromName` / `SymGetTypeInfo`)
- **MS Compression (cabinet.dll)**: XPRESS_HUFF for snapshots - ships with Windows
- **VC-LTL** (`D:\vc\VC-LTL-Binary`, ucrt mode) + `/MT`: the binary depends only on
  `KERNEL32` / `dbghelp` / `cabinet` / `ucrtbase` with **no VC runtime**; without VC-LTL the
  CMake setup falls back to plain static `/MT`

Output is always `build\aidbg.exe`.

## 2. Layout

```
src/
  main.cpp             CLI entry: -c / --script / interactive / --mcp; --hide/--aslr flags
  cmd/commands.cpp     command registration, parsing, dispatch (70+ commands)
  mcp/mcp_server.cpp   MCP server (13 tools, same envelopes as the CLI)
  output/output.cpp    JSON/text output layer (events, envelopes, quiet mode)
  engine/
    engine.cpp         debug event loop, process/thread/module mgmt, execution, fixed base
    breakpoints.cpp    software/hardware/memory breakpoints + conditions + on-hit commands
    hide.cpp           anti-anti-debug: L1 patches + L2 API virtualization + detect
    notes.cpp          user labels/comments (module+RVA anchored)
    memory/registers/symbols/expr/types/exceptions/disasm/cfg
    ntview.cpp         TEB/PEB/heap/handle views
    snapshot.cpp snapstore.cpp   in-memory snapshot ring + single-file store
    exports.cpp importfix.cpp pedump.cpp
  host/                built-in DLL host stubs + resource script
  util/                JSON build/parse, strings, version.h (single source of the version)
tests/                 test targets (x64/x86 EXE and DLL), detection probes, *.ajs scripts
third_party/zydis/     vendored Zydis
```

## 3. Architecture

**JSON first**: the `output` layer defines the envelope (`ok/cmd/data/error/session`); the
`cmd` layer only produces `CmdResult`; the engine knows nothing about output formats - one
engine serves both the CLI and MCP.

```
main / mcp_server
      |  dispatch(Engine&, CliConfig&, line)
      v
   cmd layer (parsing, validation, Json assembly)
      |
      v
   engine layer (event loop, state) -- util/output (envelope, value encoding)
```

- **Multi-process**: `DEBUG_PROCESS` follows children; `ProcessInfo` is keyed by pid and
  `current_pid_` follows the event; `--no-children` switches to `DEBUG_ONLY_THIS_PROCESS`.
  `conhost.exe` is followed too (it inherits the debug port) but is marked `is_system`:
  it never becomes `current`, gets no symbols/breakpoints/hiding, and its exception events
  are not mistaken for target breakpoints.
- **Session lifetime**: when the last non-system target exits, `reset_session()` clears
  process/thread handles, per-process breakpoint state, the hider, the symbol session,
  snapshots and the global single-step state, and continues the `EXIT_PROCESS` event.
  `active()` and `launch()` share the same predicate, so "kill says no_target while restart
  says already active" cannot happen.
- **WOW64**: the debugger is always 64-bit; x86 targets go through
  `Wow64Get/SetThreadContext` and normalize into `CpuState` (its `is32` flag drives
  semantics); disassembly/stack walking follow the machine type.
- **Execution control**: single step via TF; a software breakpoint hit does
  "restore byte -> rewind RIP -> single step -> replant". Execution hardware breakpoints
  are fault-like, so continuing/stepping clears the DR7 enable bit and steps over the
  instruction first. `pause` injects a break with `DebugBreakProcess` (temporarily setting
  `PEB.BeingDebugged` when hide cleared it); `continue <timeout>` uses a wall-clock budget;
  auto-snapshots pause during `stepuntil/rununtil/autostep`.
- **Expressions**: recursive descent in `expr.cpp` with an `EvalContext` callback
  (register / read-pointer / name resolution). Name order: user labels -> `$entry`/`$ra` ->
  `module+off` -> PDB symbols.

## 4. Key design decisions (with measurements)

### 4.1 Fixed base: rename swap - not a patched copy, not hollowing

The kernel reads `DYNAMIC_BASE` while creating the image section during CreateProcess, so
"disabling ASLR" means making the kernel see a header without that flag at mapping time.
Measured verdicts on the three approaches:

| Approach | Verdict |
|---|---|
| patched copy (`.aidbg-fixbase`) | works but **fails self-checks**: the target hashing its own file sees the difference (rejected) |
| remapping after mapping (TitanEngine-style hollowing) | **deadlocks the kernel**: image-view operations never return while the CREATE_PROCESS event is unacknowledged (unkillable processes); `DEBUG_PROCESS|CREATE_SUSPENDED` does not even deliver that event |
| **rename swap** (current) | original bytes untouched; self-check verified PASS |

The swap (`TransientPePatch`, engine.cpp):

1. rename the original to `<target>.aidbg-orig` (bytes untouched)
2. a copy takes the path and only the copy gets `DllCharacteristics` patched
   (`DYNAMIC_BASE|HIGH_ENTROPY_VA` cleared)
3. CreateProcess: the loader maps at ImageBase by itself
4. the patched copy is renamed to `<target>.aidbg-patched-<pid>-<tick>` and the original
   takes the path back (**the target is gated by debug events and has executed nothing**)

Key fact: Windows **refuses to write, replace or delete a running image's file** but
**allows plain renames** - the swap only uses MoveFileEx(0). The staging name is unique per
launch: reusing a fixed name failed with win32 error 183 when the previous session's mapped
image was still alive, leaving the user's file as the patched copy. Crash recovery: a
leftover `.aidbg-orig` is restored at the next launch; `.aidbg-patched-*` files (mapped
images, undeletable) are removed by `cleanup_staged_files()` on the next run. System files
(`%SystemRoot%`) never participate; a failed swap **falls back to an ASLR launch with a
warning** instead of aborting.

### 4.2 Anti-anti-debug: L1 patches + L2 virtualization (no injection)

- **L1** (writes from the debugger): `PEB.BeingDebugged`, `NtGlobalFlag &= ~0x70`, heap
  `Flags/ForceFlags` (same masks as ScyllaHide's PebHider), StartupInfo cleanup +
  `IMAGE_KEY_MISSING`, `KUSER_SHARED_DATA.KdDebuggerEnabled`. WOW64 targets get **both PEBs**
  patched (PEB32 via `ProcessWow64Information`).
- **L2** (INT3 on ntdll exports answered by the debugger): semantics follow ScyllaHide's
  HookedFunctions one by one (ProcessDebugObjectHandle -> `STATUS_PORT_NOT_SET`, DebugPort ->
  0, ThreadHideFromDebugger swallowed, NtClose on an invalid handle -> `STATUS_INVALID_HANDLE`
  with no exception). Calls that cannot be answered are **replayed in the target**:
  unplant + TF step + replant.
- **Self-referential pointers in forwarded buffers** (UNICODE_STRING.Buffer in
  SystemProcessInformation etc.) must be relocated into the target's buffer or the target
  dereferences a debugger address and crashes - the NtQueryObject type table rewrites them;
  other pointer-carrying classes are passed through (no hiding beats corrupted structures).
- **WOW64 traps**: the calling convention of a hook follows the **module's** bitness
  (ntdll32/ntdll64 hooked separately); forwarding a PBI across bitness hands 64-bit layout to
  a 32-bit caller (guaranteed crash) - the x86 PBI is synthesized by hand.
- User breakpoints win over hide hooks at the same address; the hider skips addresses that a
  user breakpoint already owns, and on `hide off`/detach it hands the real original byte to
  `BpPlant` instead of writing it back. Pass-through bookkeeping is per-thread
  (`std::map<tid, PassThrough>`); INT3s are always restored on detach/exit, and a failed
  write keeps `planted=true` instead of pretending the hook is gone.
- **x64 CONTEXT offsets**: `ContextFlags` lives at `+0x30` (`+0` is `P1Home`).
  `NtGetContextThread` writes back only the requested field groups and zeros the debug
  registers; `NtSetContextThread` clears the DEBUG_REGISTERS bit at `+0x30`.
  `NtCurrentThread` is the pseudo handle `-2`, not `-1`.
- `NtQueryObject(ObjectNameInformation)`'s `UNICODE_STRING.Buffer` must also be relocated
  into the target's buffer; unknown layouts fall back to the real call so a debugger address
  is never handed to the target.
- **pause vs. hide**: the `DebugBreakProcess` remote thread checks `PEB.BeingDebugged`;
  after hide clears it, the thread exits without raising INT3. `Engine::pause()` temporarily
  sets it to 1 and restores 0 once the stop is received.

### 4.3 Snapshots: differential chain + append-only store

- One full capture, then 4KB page-granular dirty diffs; MS Compression; zero pages are free.
  Cap: 8 / 256MB; when dropping the oldest it is merged into the next to keep the chain whole.
- The `snapstore` container is a 64-byte header + appended records (self-described length +
  prev link + registers + compressed payload); a crash can be recovered by scanning; delete
  marks are written back into the record header (`mark_deleted`), `compact` reclaims.
  File offsets use `_fseeki64/_ftelli64` (`long` is 32-bit on MSVC x64 and truncated >2GB).
- **Payload CRC** is verified on load (mismatching records are skipped), and page count,
  address, size, data length and protection are validated before decoding, so a crafted
  `.snap` cannot become an arbitrary-write / arbitrary-protection primitive.
- **Registers are serialized field by field** (never memcpy of the struct): ABI/version safe,
  old files still load (new MXCSR/XMM fields stay zero in old records). Restore flushes the
  instruction cache and re-arms software/memory/hardware breakpoints (the old code only
  replanted software/hardware, and used the current process handle for other pids).

### 4.4 DLL targets: built-in host

`file <dll>` detects `IMAGE_FILE_DLL` -> extracts the matching dllhost stub from resources ->
`stub.exe <dll> [export]`. Automatic breakpoints: `bpload <dll>` plus a pending
`dll+0x<entry RVA>`. The DLL's fixed-base swap stays active until its LOAD_DLL mapping is
done (`dll_patch_` member). The export is called with the rundll32 signature; a missing
export ends the stub with exit code 3 (no silent idling).

## 5. Testing

- **Targets** (`tests/`, all with PDBs): `target.exe` (x64), `target32.exe`, `spawner.exe`
  (children), `types_test.exe`, `imports_test.exe`, `sample_dll(.32).dll`.
- **Probes**: `antidbg_probe(.32).exe` runs 15 al-khaser-style checks;
  `selfcheck(.32).exe` hashes its own file at runtime (fixed-base verification).
- **Regression scripts** (`*.ajs`, driven by `--script`): `hide_std`, `reg_basic`,
  `reg_children`, `reg_types`, `fixbase`, `dlltest`, ... Pass criteria: the target's output
  file contents + no unexpected `"ok":false` in the JSON log + clean process exit.
- Every bug fix ships with a reproducing script. Beware: `Start-Process` does not quote
  arguments containing spaces (use embedded quotes or a script file in tests).
- **Session/MCP regression checks** (for this round of fixes):
  1. `run -> continue(exit) -> restart` must succeed; the session must not stay
     `active:true`;
  2. after `continue <ms>` times out, another `continue` keeps waiting and `pause` stops at
     `system_break` - with hide on **and** off; `step`/`regs` then work;
  3. MCP: `initialize` first; an `exe` containing spaces is not split; numeric addresses and
     boolean arguments work; `breakpoint delete` without `id` errors; batch returns
     `-32600`; deeply nested JSON does not crash;
  4. `ps` marks `conhost.exe` with `system:true` and `hide hooks` lists only the target pid;
  5. a crafted/CRC-corrupted `.snap` is rejected; normal `snapshot save/restore/load` works;
  6. `q`/`exit` quit; `eval nosuchsym` returns a non-empty `error.message`;
  7. hardware breakpoints attribute hits to the right DR6 slot; continuing from an execution
     breakpoint does not hit the same instruction repeatedly.

## 6. Release process

1. Bump `AIDBG_VERSION` in `src/util/version.h` **only** (fixes -> third digit, features ->
   middle digit); add a row to the version history in README.
2. `build.bat Release` -> regression -> `git commit` -> `git push` (if the remote has other
   people's commits, `pull --rebase` and push - never overwrite them).
3. GitHub release: tag `v<version>`, title `aidbg <version>`, body = changes,
   asset = `build\aidbg.exe`. **Each release gets its own tag/asset; nothing is reused.**

> [!WARNING]
> Build release notes with single-quoted here-strings: in PowerShell double quotes the
> backtick is an escape character and eats Markdown code markers (once rendered `bpcmd`
> as `pcmd`).

## 7. Implementation notes / measured pitfalls

- `NtQueryInformationProcess` with `ProcessBasicInformation` needs **exactly 48 bytes**
  (x64); a larger buffer returns garbage pointers.
- x64 PEB: `NumberOfHeaps` is at `0x0E8` (`0x0EC` is MaximumNumberOfHeaps), `OSBuildNumber`
  at `0x120`; x86 equivalents are `0x088` / `0x0AC`. All verified on a live system.
- The loader rewrites `ImageBase` inside the mapped PE header to the actual load address -
  `image_base` must be read from the **file**.
- Toolhelp heap snapshots (`TH32CS_SNAPHEAPLIST`) report CRC errors on debugged processes -
  walk the PEB `ProcessHeaps` array instead.
- Handle enumeration: filter by type first, then truncate (the reverse order drops matches).
- A `replace_all` on `process_` once clobbered `process_event`/`process_count` - check
  uniqueness before broad replaces.
- WOW64 debugging: PEB32 comes from `ProcessWow64Information`; the bitness of
  `GetThreadContext` vs `Wow64GetThreadContext` must match the thread's mode.
- The old "patched copy" approach died on file self-checks; "remap after mapping" deadlocks
  the kernel (see 4.1).
- `WaitForDebugEvent`'s timeout applies to **one call**, not the whole wait; hide hook events
  keep arriving and reset it. Track a deadline yourself (`GetTickCount64`), otherwise
  `continue <ms>` never times out on a hooked, busy target.
- `Json::u` must not auto-convert values >2^53 to hex strings: it broke JSON-RPC `id` and
  `value_dec` (clients saw `"0x..."`). Use `set_hex` for exact addresses.
- Never build an MCP command line from strings and `split_ws` it: paths with spaces become
  "exe + args". Set `cfg.exe/cfg.args` directly for structured arguments.
- `read_memory`'s bool means "at least one byte"; callers needing the full range must check
  `got == n` or use `read_memory_exact()`, or they parse PE headers from uninitialized stack.
- x64 `CONTEXT.ContextFlags` is at `+0x30`; `GetThreadContext(GetCurrentThread())` uses the
  `-2` pseudo handle (`NtCurrentThread`), not `-1`.
- `DebugBreakProcess` depends on `PEB.BeingDebugged` (inside `DbgUiRemoteBreakin`); after
  hide clears it the injected thread exits immediately, so pause must set it temporarily.
- Execution hardware breakpoints are fault-like (RIP still points at the instruction):
  clear the DR7 enable bit and TF-step before continuing, or they fire forever. Read/write
  breakpoints are trap-like and need no special handling.
- `conhost.exe` inherits the `DEBUG_PROCESS` debug port. Not separating system processes lets
  it steal `current`, makes hide plant INT3s into it, and lets shared system-DLL addresses
  mis-attribute breakpoints.

---

**Docs** [README](README.en.md) | [Manual](Manual.en.md) | [dev](dev.en.md) ·
[中文](dev.md)
