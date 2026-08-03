#pragma once

// Server-side control-plane authorization — native C++ port of
// server.py's _SecretServerInterceptor authorization core: cluster-secret
// validation, optional JWT fallback, RBAC role resolution, and per-RPC
// allowed-role enforcement. Reuses control/auth.* (RBAC) and control/jwt.*.

#include <set>
#include <string>

#include "auth.hpp"  // RoleSecrets
#include "json.hpp"

namespace samurai::control {

struct AuthConfig {
  std::string expected_secret;      // cluster secret; blank disables the check
  bool rbac_enabled = false;
  RoleSecrets role_secrets;         // role -> secret (from NormalizeRoleSecrets)
  std::string default_role = "viewer";
  std::string jwt_secret;           // enables JWT-as-secret fallback when set
  std::string jwt_role_claim = "role";
};

struct AuthResult {
  bool ok = false;
  std::string error;
  std::string status;  // wire status code on failure (UNAUTHENTICATED/PERMISSION_DENIED)
  std::string role;    // resolved role on success
};

class Interceptor {
 public:
  explicit Interceptor(const AuthConfig& cfg);

  // Whether auth is enforced at all (Python: expected set OR rbac enabled).
  bool active() const { return active_; }

  // Authorize a request given its meta object (x-cluster-secret) and rpc name.
  AuthResult Authorize(const samurai::core::json::Value& meta,
                       const std::string& rpc_name) const;

  // Roles permitted to invoke `rpc_name` (port of _allowed_roles_for_rpc).
  static std::set<std::string> AllowedRolesForRpc(const std::string& rpc_name);

 private:
  AuthConfig cfg_;
  bool active_;
};

}  // namespace samurai::control
