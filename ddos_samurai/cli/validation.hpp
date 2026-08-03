#pragma once

// Validates parsed CLI options before a job is dispatched. Native replacement
// for ddos_samurai/cli/validation.py (subset; grows toward parity).

#include <optional>
#include <string>

#include "options.hpp"

namespace samurai::cli {

// Returns an error message if the options are invalid, or std::nullopt if the
// options are safe to run.
std::optional<std::string> Validate(const CliOptions& opt);

}  // namespace samurai::cli
