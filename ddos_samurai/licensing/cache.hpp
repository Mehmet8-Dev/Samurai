#pragma once

// Offline license cache — native C++ port of ddos_samurai/licensing/cache.py.
// The validated result is stored encrypted so the tool can keep running for the
// grace period when the license server is unreachable. Encryption is
// AES-256-GCM (OpenSSL) with a key derived from the HWID, so the cache only
// opens on the same machine.
//
// Format note: the native cache uses AES-256-GCM (nonce||ciphertext||tag), not
// Python's Fernet; it is self-consistent (write + read here) and not required to
// interoperate with old Python caches, which are being removed.

#include <string>

#include "license_types.hpp"

namespace samurai::licensing {

// Encrypt + write the result to the cache file. Returns false on any error.
bool SaveCache(const LicenseResult& result, const std::string& hwid);

// Read + decrypt the cache. Returns true and fills `out` (offline=true,
// reason="offline_cache") when a valid, in-grace-period cache exists; false
// otherwise (missing / expired / tampered), removing an unusable cache.
bool LoadCache(const std::string& hwid, LicenseResult& out);

void ClearCache();

}  // namespace samurai::licensing
