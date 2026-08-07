#pragma once

// Hardware fingerprint for license binding — native C++ port of
// ddos_samurai/licensing/hwid.py. SHA-256 over CPU model + primary MAC +
// hostname + OS; stable per physical machine.

#include <string>

namespace samurai::licensing {

// 64-char lowercase hex SHA-256 fingerprint.
std::string GetHardwareId();

}  // namespace samurai::licensing
