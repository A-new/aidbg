---
name: aidbg
description: |
  Drive the aidbg Windows debugger (JSONL CLI / MCP) to debug and reverse-engineer
  Windows x86/x64 executables and DLLs. Use when the user asks to debug, trace,
  break, unpack (IAT fix/dump), inspect memory/registers/PEB-TEB, bypass
  anti-debugging (hide/detect), or analyze a Windows binary with a debugger -
  including "why does this exe behave this way" style questions that need a live
  run. Not for explaining debugging theory, using other debuggers (x64dbg, IDA,
  gdb), kernel debugging, or non-Windows targets.
---

# aidbg

aidbg is an AI-first command line debugger: every command can emit one line of JSON
(`--json`), so drive it in batches and parse the envelopes. Drive it with `-c` lines,
`--script` files, or MCP (`--mcp` stdio; `--port`/`--bind`/`--token` serve MCP over HTTP
to remote-control a debugger on another machine). Full command reference:
`references/commands.md`. Deep manual: `Manual.md` in the aidbg repo.

## Inputs to collect

- target binary path (exe or dll) and any arguments / working directory
- what to find out (specific function, why a value changes, unpack, anti-debug check)
- whether the target uses packers/anti-debug (choose a `hide` profile) - when unsure,
  run `detect` first and switch profiles if checks fire

## Procedure

1. **Launch in batch mode with the JSON contract**. Defaults already suit analysis:
   fixed base (runtime addresses match IDA/Ghidra) and `--hide standard`. Prefer one
   invocation with many `-c` lines (or `--script` for long runs):

   ```
   aidbg --json -c "file sample.exe" -c "run" -c "modules" -c "disasm 16" -c "stack 8"
   ```

   DLL targets work the same way: `file crypto.dll DecryptEntry` runs it in a built-in
   host and auto-breaks at load and DllMain.

2. **Survey before acting**. `info` (session state), `modules` (base/image_base/slide),
   `disasm`, `flow` (CFG), `stack`, `symbols <mask>`. Every response carries `session`;
   only `state:paused` accepts reads/writes.

   > `resolved:false` on a breakpoint set BEFORE `run` is **normal** (it is pending and
   > plants when the module loads) - it does not mean symbols are missing. Verify PDB
   > resolution directly with `disasm <symbol>` or `eval <symbol>`; `symbols <mask>` only
   > enumerates and can legitimately come back empty.

3. **Prefer expressions over raw addresses**: `break main`, `read rdx 64`,
   `[rbp-0x20]`, `sample.dll+0x2300`. User labels (`label addr name`) work in
   expressions too.

4. **Let the engine do the looping**: `cond` (per-hit condition), `stepuntil` /
   `rununtil <expr> max=N`, `bpcmd <id> <cmd>` (on-hit action) instead of polling from
   outside. Execution control is refused inside `bpcmd` by design.

   **Counting function calls / capturing arguments**: set one breakpoint at the function
   entry (read `rcx`/`rdx`/`r8`/`r9` for args) and one at its `ret` (read `rax`), then use
   plain `continue` between hits and finish with `bl` (`hit_count` is the authority).
   Parked breakpoints are re-planted after `finish`/`next`/`until`, so interleaving those
   with hits is safe too.

5. **Bound output**: `mem` defaults to 64 bytes; lists take `max=N`; `search` requires
   `max=N` written explicitly.

6. **Persist conclusions** with `label`/`comment` + `notes save file.json` so a later
   session can reload them (`notes load`).

7. **Hardened targets**: run `detect`; if checks fire, `hide profile vmp|themida|obsidium`
   (or `hide set <key> 1`) and re-run `detect`. Report honestly what is not covered
   (direct syscalls, timing checks, ntdll integrity scans see the INT3 hooks).

## Output contract (essentials)

- one JSON line per command: `{ok, cmd, data, error?, session}`; errors carry
  `error.code`/`error.message`; async events come as `{"kind":"event",...}` lines.
- addresses and 64-bit values are **hex strings** (`"0x7ff6..."`); counts are numbers;
  byte strings are space-separated uppercase hex.
- `session` always reports `state`, `stop_reason`, `rip`, `arch` (x86/x64 - it decides
  register names), `detail`.
- exit codes: 0 ok, 1 some command failed, 2 bad usage.

## Failure handling

| `error.code` | Action |
|---|---|
| `not_paused` | continue/step first; the target is running |
| `no_target` | `file` + `run`, or `attach <pid>` |
| `eval_failed` / `bad_address` | simplify the expression; check `arch` register names |
| `unknown_type` / `no_type` | try `whatis`, or plain `eval`; PDB may be missing |
| `condition_not_met` | raise `max=` or use `rununtil` instead of `stepuntil` |
| `read_failed` | address may be unmapped: check `regions` |

A `warning` event "fixed base skipped/unavailable" (system files, locked images) is not
a failure: the launch continues with ASLR and a non-zero slide; pass `--aslr` to silence
it up front.

When a run hangs, suspect the target hid its threads (`ThreadHideFromDebugger` on a
session without the hide hooks) or a DLL host idling (`kill` ends it). Re-run with
`continue <timeout_ms>` to avoid waiting forever.

## Examples

Trace who writes a variable:

```
aidbg --json -c "file sample.exe" -c "run" -c "hbreak 0x140003010 w 4" -c "continue" -c "disasm 4" -c "stack 4"
```

Check and hide anti-debugging, then inspect an API call:

```
aidbg --json -c "file sample.exe" -c run -c detect -c "hide profile vmp" -c "break CreateFileW" -c "continue" -c "regs rcx rdx r8 r9" -c "read rdx 64"
```

## Windows (win32) platform notes

- Invoke as `aidbg.exe` (on PATH, the repo's `build\aidbg.exe`, or the single-file
  release download).
- In PowerShell, `Start-Process -ArgumentList` does **not** quote arguments containing
  spaces - use embedded quotes (`'"two words"'`) or a `--script` file; `-c` lines with
  spaces are best passed via a script file.
- Output is UTF-8 JSONL; redirect to a file and parse line by line.
