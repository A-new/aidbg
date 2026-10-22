#pragma once

// Single source of truth for the program version.
//
// Bump it on every published update; each released build gets its own GitHub
// release (tag v<major.minor.patch>) instead of reusing an old one.
//   0.2.0  fixed-base rename-swap launch, notes/labels, bpcmd, bpload, XMM
//   0.1.0  initial release
#define AIDBG_VERSION "0.2.0"
