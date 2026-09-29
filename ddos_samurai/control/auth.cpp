#include "auth.hpp"

#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>

namespace samurai::control {

namespace {

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

}  // namespace

std::vector<std::string> SplitEndpoints(const std::string& raw) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= raw.size()) {
    const auto comma = raw.find(',', start);
    const std::string tok =
        Strip(raw.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
    if (!tok.empty()) out.push_back(tok);
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return out;
}

std::vector<std::pair<std::string, std::string>> BuildClusterMetadata(
    const std::string& cluster_secret, const std::string& tenant_namespace) {
  std::vector<std::pair<std::string, std::string>> out;
  const std::string secret = Strip(cluster_secret);
  const std::string tenant = Strip(tenant_namespace);
  if (!secret.empty()) out.emplace_back("x-cluster-secret", secret);
  if (!tenant.empty()) out.emplace_back("x-tenant-namespace", tenant);
  return out;
}

bool ValidateClusterSecret(const std::string& expected, const std::string& provided) {
  const std::string exp = Strip(expected);
  const std::string got = Strip(provided);
  if (exp.empty()) return true;
  return exp == got;
}

const std::string* RoleSecrets::Find(const std::string& role) const {
  for (const auto& kv : entries) {
    if (kv.first == role) return &kv.second;
  }
  return nullptr;
}

RoleSecrets NormalizeRoleSecrets(const std::string& admin_secret,
                                 const std::string& operator_secret,
                                 const std::string& viewer_secret,
                                 const std::string& worker_secret) {
  RoleSecrets out;
  const std::pair<const char*, const std::string&> roles[] = {
      {"admin", admin_secret},
      {"operator", operator_secret},
      {"viewer", viewer_secret},
      {"worker", worker_secret},
  };
  for (const auto& r : roles) {
    const std::string v = Strip(r.second);
    if (!v.empty()) out.entries.emplace_back(r.first, v);
  }
  return out;
}

std::string ResolveRoleFromSecret(const std::string& provided_secret,
                                  const RoleSecrets& role_secrets) {
  const std::string got = Strip(provided_secret);
  if (got.empty()) return "";
  // Strongest-first so an overlapping secret grants the highest role.
  for (const char* role : {"admin", "operator", "viewer", "worker"}) {
    const std::string* exp = role_secrets.Find(role);
    if (exp && !exp->empty() && *exp == got) return role;
  }
  return "";
}

bool EnsureTlsFilesExist(const std::vector<std::string>& paths, std::string* missing) {
  for (const auto& path : paths) {
    if (path.empty()) continue;
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
      if (missing) *missing = path;
      return false;
    }
  }
  return true;
}

}  // namespace samurai::control
