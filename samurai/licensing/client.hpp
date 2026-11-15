#pragma once

// Native license client — the C++ replacement for the network side of
// samurai/licensing/client.py. Talks to the license server over HTTP(S)
// (http_client): validate a key into a LicenseResult, and satisfy the gates'
// ExecGrantClient by requesting a server-side execution grant.
//
// This unblocks the previously-deferred license network path. The server-side
// heartbeat/deactivate/updater calls remain to be added as needed.

#include <string>
#include <vector>

#include "constants.hpp"
#include "gates.hpp"          // ExecGrantClient / ExecGrantResult
#include "license_types.hpp"

namespace samurai::licensing {

class HttpLicenseClient : public ExecGrantClient {
 public:
  explicit HttpLicenseClient(const std::string& server_url = LicenseServerUrl(),
                             int timeout_s = RequestTimeoutS())
      : server_url_(server_url), timeout_s_(timeout_s) {}

  // POST /validate with {license_key, hardware_id}; parse into a LicenseResult.
  // Transport/HTTP errors yield an invalid result with a reason.
  LicenseResult Validate(const std::string& license_key, const std::string& hardware_id);

  // ExecGrantClient: POST /exec-grant for critical capabilities.
  ExecGrantResult RequestGrant(const std::string& license_key, const std::string& hardware_id,
                               const std::string& session_id, const std::string& attack_vector,
                               const std::string& compute_backend, const std::string& role,
                               const std::vector<std::string>& required_features) override;

 private:
  std::string server_url_;
  int timeout_s_;
};

}  // namespace samurai::licensing
