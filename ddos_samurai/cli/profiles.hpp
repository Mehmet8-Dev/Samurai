#pragma once

// Native workload/browser profiles.
//
//   - ApplyProfile(): applies a named corporate test profile's overrides onto
//     the parsed job options.
//   - ListProfiles(): prints the available profiles.
//   - The browser TLS/H2 profile names are exposed as constants for the L7
//     paths.

#include <optional>
#include <string>

#include "options.hpp"

namespace samurai::cli {

// Browser TLS/H2 fingerprint profiles.
inline constexpr const char* kProfileNone = "none";
inline constexpr const char* kDefaultBrowserProfile = "chrome_120";
inline constexpr const char* kBrowserProfileNames[] = {
    "chrome_120",
    "firefox_120",
    "safari_17",
};

// Applies the named corporate test profile's overrides onto opt.job. Returns an
// error message if the profile name is unknown, or std::nullopt on success.
std::optional<std::string> ApplyProfile(const std::string& name, CliOptions& opt);

// Prints the table of available workload profiles to stdout.
void ListProfiles();

}  // namespace samurai::cli
