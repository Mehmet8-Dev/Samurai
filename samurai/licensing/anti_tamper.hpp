#pragma once

#include <string>

namespace samurai::licensing {

struct IntegrityResult {
  bool ok = true;
  std::string reason;
  std::string text_sha256;
};

// Check if a tracer/debugger is attached to this process.
bool IsDebuggerAttached();

// Perform self-integrity check on the ELF .text / executable code segment:
// 1. Checks for active tracers / debuggers.
// 2. Compares the running memory code pages against the on-disk ELF binary (/proc/self/exe)
//    to detect any in-memory NOP patches, detour hooks, or breakpoint injections (0xCC).
// 3. Computes the SHA-256 fingerprint of the executable segment.
IntegrityResult VerifySelfIntegrity();

}  // namespace samurai::licensing
