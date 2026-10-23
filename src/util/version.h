#pragma once

// Single source of truth for the program version.
//
// Bump it on every published update; each released build gets its own GitHub
// release (tag v<major.minor.patch>) instead of reusing an old one.
//   0.3.2  MCP over HTTP for remote (dual-machine) debugging: legacy SSE
//          transport (GET /sse) + streamable HTTP (POST /mcp) on --port,
//          --bind / --token with auto-generated bearer token beyond loopback
//   0.3.1  second review round: next/finish/until no longer disarm the
//          breakpoint they started from; memory breakpoints no longer kill
//          the target on neighbouring page traffic (access-type filter,
//          silent step + re-arm, page-granular guard); snapshots capture real
//          instruction bytes (INT3 lifted); snapshot delete wired to the
//          store; snapshot load restores through the engine; misc hardening
//   0.3.0  built-in DLL host (debug DLLs directly), fixed-base fallback for
//          un-renamable targets (system files / access denied)
//   0.2.1  review fixes: snapshot SSE persistence, hit-command re-entry guard,
//          fixed-base crash recovery, user-bp priority over hide hooks, misc
//   0.2.0  fixed-base rename-swap launch, notes/labels, bpcmd, bpload, XMM
//   0.1.0  initial release
#define AIDBG_VERSION "0.3.2"
