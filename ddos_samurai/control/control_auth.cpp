#include "control_auth.hpp"

#include <set>
#include <string>

#include "control_wire.hpp"
#include "jwt.hpp"

namespace samurai::control {

namespace {

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

std::string MetaSecret(const samurai::core::json::Value& meta) {
  const auto* v = meta.find("x-cluster-secret");
  return v ? v->as_string("") : "";
}

}  // namespace

Interceptor::Interceptor(const AuthConfig& cfg) : cfg_(cfg) {
  cfg_.expected_secret = Strip(cfg_.expected_secret);
  cfg_.jwt_secret = Strip(cfg_.jwt_secret);
  cfg_.default_role = Lower(Strip(cfg_.default_role));
  if (cfg_.default_role.empty()) cfg_.default_role = "viewer";
  if (cfg_.jwt_role_claim.empty()) cfg_.jwt_role_claim = "role";
  active_ = !cfg_.expected_secret.empty() || cfg_.rbac_enabled;
}

std::set<std::string> Interceptor::AllowedRolesForRpc(const std::string& rpc_name) {
  const std::string name = Strip(rpc_name);
  if (name == "AbortJob") return {"admin"};
  if (name == "GetWorkerStatus" || name == "ForceSync") return {"admin", "operator", "viewer"};
  if (name == "RegisterWorker" || name == "Heartbeat" || name == "ReportStats" ||
      name == "ReportStatsStream") {
    return {"admin", "operator", "worker"};
  }
  if (name == "StartShard" || name == "StopShard" || name == "ReconfigureShard") {
    return {"admin", "operator"};
  }
  return {"admin"};
}

AuthResult Interceptor::Authorize(const samurai::core::json::Value& meta,
                                  const std::string& rpc_name) const {
  AuthResult r;
  const std::string provided = MetaSecret(meta);

  bool have_jwt = false;
  samurai::core::json::Value jwt_claims = samurai::core::json::Value::Object();

  if (!ValidateClusterSecret(cfg_.expected_secret, provided)) {
    if (!cfg_.jwt_secret.empty()) {
      const auto dec = DecodeJwtHs256(provided, cfg_.jwt_secret);
      if (!dec.ok) {
        r.ok = false;
        r.error = "invalid cluster secret";
        r.status = wire::kStatusUnauthenticated;
        return r;
      }
      have_jwt = true;
      jwt_claims = dec.payload;
    } else {
      r.ok = false;
      r.error = "invalid cluster secret";
      r.status = wire::kStatusUnauthenticated;
      return r;
    }
  }

  if (!cfg_.rbac_enabled) {
    r.ok = true;
    r.role = "legacy";
    return r;
  }

  std::string role = ResolveRoleFromSecret(provided, cfg_.role_secrets);
  if (role.empty() && have_jwt) {
    const auto* claim = jwt_claims.find(cfg_.jwt_role_claim);
    if (claim) role = Lower(Strip(claim->as_string("")));
  }
  if (role.empty()) {
    if (cfg_.role_secrets.entries.empty()) {
      role = cfg_.default_role;
    } else if (!cfg_.expected_secret.empty() &&
               ValidateClusterSecret(cfg_.expected_secret, provided)) {
      role = cfg_.default_role;
    } else {
      r.ok = false;
      r.error = "unknown role secret";
      r.status = wire::kStatusPermissionDenied;
      return r;
    }
  }

  const auto allowed = AllowedRolesForRpc(rpc_name);
  if (allowed.find(role) == allowed.end()) {
    r.ok = false;
    r.error = "forbidden for role=" + role + " rpc=" + rpc_name;
    r.status = wire::kStatusPermissionDenied;
    r.role = role;
    return r;
  }

  r.ok = true;
  r.role = role;
  return r;
}

}  // namespace samurai::control
