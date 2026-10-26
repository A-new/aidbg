# aidbg command reference (condensed)

Addresses accept expressions everywhere (see SKILL.md). Aliases in parentheses.

## Session
| Command | Notes |
|---|---|
| `file <exe> [args...]` / `file <dll> [export]` | set target; dll runs in built-in host, `export` optional (rundll32 signature) |
| `run [args...]` | launch, stop at entry (loader breakpoints skipped) |
| `attach <pid>` / `detach` / `kill` / `restart` | attach / clean detach / terminate / relaunch |
| `aslr [on\|off]` | fixed base toggle (default off = pinned to PE ImageBase) |
| `processes\|ps`, `process\|proc <pid>` | all processes in the session (children included) |
| `info`, `version`, `help` | session state / version / machine-readable catalog |

CLI flags: `--json --pretty --exe --args --cwd --console --aslr --no-children --hide <profile|off> -c <line> --script <file> --mcp [--port <n> --bind <addr> --token <bearer>]`
(`--port` switches MCP to HTTP - SSE + streamable HTTP - for remote/dual-machine
debugging; beyond loopback a bearer token is required and auto-generated).

Stopping on any process world-stops every debuggee in the session (children included,
mixed x86/x64), so reads while paused are consistent process-wide.

## Execution
| Command | Notes |
|---|---|
| `continue\|c\|g [timeout_ms]` | resume; timeout returns `timeout` |
| `pause\|break-in [timeout_ms]` | interrupt a running target (inject a break) |
| `step\|si [n]` / `next\|n\|so [n]` | into / over calls |
| `finish\|gu` / `until <expr>` | to function return / to address |
| `stepuntil\|tu <cond> [max=N]` | step until true (evaluated per step) |
| `rununtil\|ru <cond> [max=N]` | run until true (evaluated per stop) |
| `autostep\|astep <n> [delay_ms]` | record the executed instruction trace |
| `sleep\|wait <ms>` | pause the debugger (not the target) - script timing |

## Breakpoints
| Command | Notes |
|---|---|
| `break\|b <addr\|sym> [cond]` | software (INT3); set before `run` -> auto-planted when resolvable |
| `hbreak <addr> [r\|w\|x] [size]` | hardware, max 4, size 1/2/4/8 |
| `mbreak <addr> <size> [r\|w\|x]` | memory (PAGE_GUARD), any size |
| `cond <id> <expr>` | false auto-continues |
| `bpcmd <id> [cmd\|-]` | on-hit command; execution control is refused inside it |
| `bpload [pattern\|add\|del\|clear]` | stop when a module matching `*` pattern loads |
| `bl` / `be` / `bd` / `bc <id\|*>` | list / enable / disable / delete |

## Registers & memory
| Command | Notes |
|---|---|
| `regs [name...]` | GPRs + flags + mxcsr + xmm0-15 (x86: 0-7) |
| `setreg <reg> <val>` | `setreg xmm3 <1..32 hex>` for full 128-bit |
| `mem <addr> [size]` / `read` / `write <addr> <hexbytes>` | dump (<=4096) / read (<=65536) / write |
| `search <s> <e> <pat> [max=N]` | `??` wildcard; `max=N` explicit |
| `regions [s] [e]`, `alloc`, `free`, `protect` | memory management |

## Analysis
| Command | Notes |
|---|---|
| `disasm\|u [addr] [count]` | small int = count, expression = start |
| `flow\|cfg [addr] [max]` | CFG: blocks + fallthrough/branch/indirect edges |
| `modules`, `threads`, `thread <tid>`, `symbols [mask] [max]` | listings |
| `stack\|bt [max]` | call stack with source lines |
| `teb`, `peb`, `heap [max]`, `handles [type] [max]` | internal state views |
| `eval <expr>` | expression evaluation |
| `exports [module] [mask]` | export directory from target memory |
| `imports <addr> [n]` | pointer run -> module!function |
| `iat scan/map/refs/fix/trace` | find IAT slots, group, find code refs, rebuild IAT, trace an import call |
| `dump <file> [addr] [entry=] [compact] [keepbase] [noiat]` | dump in-memory image as a runnable PE; `noiat` skips the import-table rebuild |
| `ptype <type>`, `whatis <sym>`, `print <expr>` | PDB types; `print` supports `.` `->` `[]` |

## Snapshots
`snapshot save/restore/list/delete/clear/auto on|off/file/history/load/compact`,
`stepback|sbk|reverse [n]`. Auto-capture at every stop is on by default; restore is
destructive (newer snapshots dropped); state = memory + registers only.

## Exceptions
`exlist`, `exset <code> <break|ignore|pass>`, `exdel <code>`, `exall <on|off>`.
Aliases: `av` `bp` `ss` `guard` `cpp`. Second-chance always stops.

## Anti-anti-debug
`detect` (al-khaser catalogue self-check), `hide status|on [profile]|off|profile <name>|
set <key> <0|1>|apply|hooks|profiles|load <file>|save <file>`.
Profiles: `off basic standard aggressive vmp themida obsidium`; keys match
`scylla_hide.ini`. L1 = PEB/heap/StartupInfo/KUSER patches; L2 = ntdll API virtualization.
Limits: INT3s visible to ntdll integrity scans, direct syscalls bypass L2, timing checks
uncovered.

## Notes
`label <addr> [name|-]` (usable in expressions), `comment <addr> [text|-]`,
`notes [list|save <file>|load <file>|clear]`. Anchored to module+RVA; JSON format
`aidbg-notes-1`.
