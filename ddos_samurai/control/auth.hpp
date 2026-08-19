#pragma once

// Control-plane auth helpers — the transport-agnostic parts: endpoint parsing,
// cluster-secret metadata, and role/secret (RBAC) resolution. Pure logic, no
// I/O.
//
// TLS credential construction is transport wiring and belongs to the native
// transport layer; only EnsureTlsFilesExist (a filesystem precondition check)
// lives here.

#include <string>
#include <utility>
#include <vector>

namespace samurai::control {

// "a,b , c" -> {"a","b","c"} (blank entries dropped, trimmed).
std::vector<std::string> SplitEndpoints(const std::string& raw);

// Cluster-secret / tenant metadata headers, in the same order as the Python
// implementation (secret first, then tenant); blank values are omitted.
std::vector<std::pair<std::string, std::string>> BuildClusterMetadata(
    const std::string& cluster_secret, const std::string& tenant_namespace = "");

// A blank expected secret disables the check (returns true); otherwise the
// provided secret must match exactly (both trimmed).
bool ValidateClusterSecret(const std::string& expected, const std::string& provided);

// Role -> secret map for the four roles, keeping only the non-blank ones.
struct RoleSecrets {
  std::vector<std::pair<std::string, std::string>> entries;  // preserves role order
  const std::string* Find(const std::string& role) const;
};

RoleSecrets NormalizeRoleSecrets(const std::string& admin_secret,
                                 const std::string& operator_secret,
                                 const std::string& viewer_secret,
                                 const std::string& worker_secret);

// Resolve the role a presented secret grants. Prefers the strongest role when
// secrets overlap: admin > operator > viewer > worker. "" when no match.
std::string ResolveRoleFromSecret(const std::string& provided_secret,
                                  const RoleSecrets& role_secrets);

// Returns true if every non-blank path exists as a regular file; on failure
// sets *missing (when non-null) to the first offending path.
bool EnsureTlsFilesExist(const std::vector<std::string>& paths, std::string* missing = nullptr);

}  // namespace samurai::control
