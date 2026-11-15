#pragma once

// RBAC audit chain — append_rbac_audit / load_last_audit_hash /
// verify_rbac_audit_chain. Each appended entry is a
// tamper-evident JSON line: schema + fields + prev_hash, with an entry_hash =
// SHA256 over the sorted-key JSON of the entry (excluding entry_hash). Entries
// chain via prev_hash so any edit/reorder/deletion breaks verification.
//
// Serialization is core JSON with sort_keys (deterministic). The native chain is
// self-consistent (write + verify use the same serializer); it is not required
// to be byte-compatible with old Python-written logs, which are being removed.

#include <mutex>
#include <string>

#include "json.hpp"

namespace samurai::control {

struct AuditVerifyResult {
  bool ok = false;
  std::string error;
};

class RbacAuditLog {
 public:
  // A blank path disables logging (Append is a no-op returning true).
  explicit RbacAuditLog(const std::string& path);

  // Append an audit item (JSON object of the event fields). Adds schema +
  // prev_hash + entry_hash and writes one line. Returns false on I/O error.
  bool Append(const samurai::core::json::Value& item);

  // Verify the full chain of `path`. ok=false with a reason on the first break.
  static AuditVerifyResult Verify(const std::string& path);

  const std::string& prev_hash() const { return prev_hash_; }
  bool enabled() const { return !path_.empty(); }

 private:
  std::string path_;
  std::string prev_hash_;
  std::mutex mu_;
};

}  // namespace samurai::control
