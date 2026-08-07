#pragma once

// Feature-gate enforcement — native C++ port of ddos_samurai/licensing/gates.py.
// Given the requested run parameters and a validated LicenseResult, allow or
// reject the run and clamp duration/PPS to the tier limits. Pure logic, except
// the "critical capabilities" server-side execution grant, which is abstracted
// behind ExecGrantClient (its HTTP transport is deferred, like the license
// client itself).

#include <string>
#include <vector>

#include "license_types.hpp"

namespace samurai::licensing {

struct GateInput {
  std::string attack_vector = "basic";
  std::string compute_backend = "cpu";
  bool xdp_enable = false;
  std::string xdp_interface;
  std::string custom_tcp_mode = "off";
  bool ninja_mode = false;
  bool spoof = false;
  bool realistic_spoof = false;
  std::string spoof_subnet;
  std::string spoof_list_file;
  std::string spoof_ip;
  std::string kpi_gate_profile = "off";
  bool kpi_hard_fail = false;
  bool fault_inject = false;  // any fault-injection scenarios requested
  std::string prom_textfile;
  long duration = 0;
  double rps = 0.0;
  bool has_role = false;      // whether a distributed "role" was provided
  std::string role = "standalone";
  std::string license_key;
  std::string license_file;
};

struct GateResult {
  bool ok = true;
  std::string error;
  std::string upgrade_hint;
  std::vector<std::string> warnings;
  // Possibly-clamped outputs the caller should apply back.
  long duration = 0;
  double rps = 0.0;
  bool prom_textfile_cleared = false;
};

struct ExecGrantResult {
  bool ok = false;
  std::string reason;
  std::string grant_token;
  std::string expires_at;
};

class ExecGrantClient {
 public:
  virtual ~ExecGrantClient() = default;
  virtual ExecGrantResult RequestGrant(const std::string& license_key,
                                       const std::string& hardware_id,
                                       const std::string& session_id,
                                       const std::string& attack_vector,
                                       const std::string& compute_backend, const std::string& role,
                                       const std::vector<std::string>& required_features) = 0;
};

// Enforce all gates. On a hard violation, returns ok=false with error +
// upgrade_hint. May append warnings and clamp duration/rps. Mutates `lr`'s
// exec_grant_* when a critical grant is obtained. `grant` may be null.
GateResult EnforceFeatureGates(const GateInput& in, LicenseResult& lr,
                               ExecGrantClient* grant = nullptr);

}  // namespace samurai::licensing
