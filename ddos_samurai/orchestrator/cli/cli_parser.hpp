#pragma once

// argv -> CliOptions. Native replacement for the argparse layer in
// ddos_samurai/cli/args.py.

#include "cli_options.hpp"

namespace samurai::cli {

enum class ParseStatus {
  kOk,     // options populated, proceed
  kHelp,   // help requested; caller should print usage and exit 0
  kError,  // malformed arguments; caller should exit non-zero
};

// Parses argv into `out`. On kError, a diagnostic has already been written to
// stderr. Unknown flags are treated as errors (strict, like the Python CLI).
ParseStatus ParseArgs(int argc, char** argv, CliOptions& out);

// Prints the CLI usage/help text.
void PrintUsage(const char* argv0);

}  // namespace samurai::cli
